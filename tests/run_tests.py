"""End-to-End-Tests gegen eine echte, isolierte App-Instanz.

Aufruf (im Projektordner, mit dem venv):

    python tests/run_tests.py

Das Skript startet die App selbst (Port 5100) mit temporärer SQLite-Datenbank,
Testzugangsdaten und deaktiviertem Mailversand. Die echte .env-Konfiguration und
die echte Datenbank werden nicht verwendet: alle relevanten Variablen werden
explizit gesetzt und die DB liegt in einem temporären Ordner.
"""
import csv
import io
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.getenv("TEST_PORT", "5100"))
BASE = f"http://127.0.0.1:{PORT}"
USER, PW, GATE = "testadmin", "test-pass-123", "gate-test"

SEED = """
from app import app, db, RSVP
print(app.config["SQLALCHEMY_DATABASE_URI"])
rows = [
    ("Anna Muster", "anna@example.com", "yes", 2, "both", "vegetarian", "Nudelsalat", "Glutenfrei"),
    ("Ben Beispiel", "ben@example.com", "yes", 1, "sat", "meat", "", ""),
    ("Clara Test", "clara@example.com", "no", 1, "", "", "", "Urlaub"),
    ("Dora Probe", "dora@example.com", "yes", 3, "fri", "meat", "Kuchen", ""),
    ("Emil Demo", "emil@example.com", "yes", 1, "sat", "vegetarian", "", ""),
]
with app.app_context():
    db.create_all()
    for n, e, a, g, d, m, c, no in rows:
        db.session.add(RSVP(name=n, email=e, attendance=a, guests=g, attendance_days=d,
                            meal_choice=m, contribution=c, notes=no, consent=True))
    db.session.commit()
"""

results = []


def check(name, cond, extra=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"   [{extra}]" if extra and not cond else ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def new_client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirect())


def req(op, path, data=None, headers=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    r = urllib.request.Request(BASE + path, data=body, headers=headers or {})
    try:
        resp = op.open(r, timeout=15)
    except urllib.error.HTTPError as e:
        resp = e
    return resp.status, resp.headers, resp.read().decode("utf-8", "replace")


def csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None


def pass_gate(client):
    _, _, b = req(client, "/gate")
    s, _, _ = req(client, "/gate", {"csrf_token": csrf(b), "code": GATE})
    return s == 302


def admin_login(client, password=PW, nxt="/admin", remember="1"):
    _, _, b = req(client, "/admin/login")
    return req(client, "/admin/login", {"csrf_token": csrf(b), "username": USER, "password": password,
                                        "next": nxt, "remember": remember})


def csv_rows(client):
    s, h, b = req(client, "/admin/export.csv")
    return s, h, b, list(csv.reader(io.StringIO(b), delimiter=";"))


class Env:
    def __init__(self, deadline):
        self.tmp = tempfile.TemporaryDirectory(prefix="wh_test_")
        self.db = Path(self.tmp.name) / "test.db"
        self.proc = None
        self.env = dict(os.environ)
        self.env.update({
            "SECRET_KEY": "test-secret-not-real", "ENV": "development", "FLASK_DEBUG": "1",
            "FORCE_HTTPS": "0", "GATE_ENABLED": "1", "ACCESS_CODE": GATE,
            "ADMIN_USER": USER, "ADMIN_PASS": PW, "RSVP_DEADLINE": deadline,
            "DATABASE_URL": f"sqlite:///{self.db.as_posix()}", "PORT": str(PORT),
            "SMTP_HOST": "", "MAIL_TO": "", "PHOTOS_URL": "",
        })

    def seed(self):
        out = subprocess.run([sys.executable, "-c", SEED], cwd=ROOT, env=self.env,
                             capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            print(out.stdout, out.stderr)
            raise SystemExit("Seeding fehlgeschlagen")
        uri = next((l for l in out.stdout.splitlines() if l.startswith("sqlite:")), "")
        if self.tmp.name.replace("\\", "/") not in uri:
            raise SystemExit(f"Sicherheitsabbruch: Test-DB liegt nicht im Temp-Ordner ({uri})")

    def start(self):
        # Debug-Modus ist nötig, damit Talisman das Session-Cookie nicht als "Secure" markiert
        # (Tests laufen über http). Ohne Reloader, damit ein einzelner Prozess läuft.
        code = ("import os; from app import app; "
                "app.run(host='127.0.0.1', port=int(os.environ['PORT']), debug=True, use_reloader=False)")
        self.proc = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT, env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                if urllib.request.urlopen(BASE + "/healthz", timeout=1).status == 200:
                    return
            except Exception:
                time.sleep(0.5)
        raise SystemExit("Server startet nicht")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.tmp.cleanup()

    def cli(self, *args):
        out = subprocess.run([sys.executable, "-m", "flask", "--app", "app.py", *args], cwd=ROOT,
                             env=self.env, capture_output=True, text=True, timeout=60)
        return out.stdout + out.stderr


def phase_open():
    print("\n=== Phase A: RSVP offen ===")
    e = Env("2099-12-31")
    e.seed()
    e.start()
    try:
        c = new_client()

        s, h, _ = req(c, "/admin")
        check("ohne Gate: /admin -> Gate", s == 302 and "/gate" in h["Location"], f"{s}")
        check("Gate-Code akzeptiert", pass_gate(c))

        s, _, b = req(c, "/")
        check("Startseite erreichbar", s == 200)
        check("RSVP offen: Formular sichtbar", 'action="/rsvp"' in b)
        check("RSVP offen: 'Jetzt zusagen' im Hero", "Jetzt zusagen" in b)
        check("RSVP offen: RSVP-Button in der Kopfzeile", 'class="btn btn--small">RSVP' in b)
        check("RSVP offen: Vorschautext 'jetzt zusagen'", 'content="Alle Infos - jetzt zusagen' in b)
        check("Footer zeigt aktuelles Jahr", f"© {datetime.now().year} " in b)
        check("Info-Hinweis zu Schüsseln/Behältern", "Schüsseln und Behälter" in b)
        check("Parkplatz-Karte vorhanden", "Parkplatz Kurgarten" in b)
        check("Zeitleiste: Empfang um 12:30",
              re.search(r'T12:30">12:30</time>\s*<div class="timeline__card">\s*<h3 class="timeline__title">Empfang', b) is not None)
        check("Zeitleiste: kein Empfang mehr um 13:00", not re.search(r'13:00</time>\s*<div class="timeline__card">\s*<h3 class="timeline__title">Empfang', b))
        check("Infokarte Kuchenabgabe: ab 11 Uhr im Kurgarten",
              "Kuchenabgabe" in b and "ab 11 Uhr im Kurgarten abgegeben" in b)
        check("Krähenlochhütte: Toilettenhäuschen (Plumpsklo) vorhanden",
              "Toilettenhäuschen (Plumpsklo) vorhanden" in b)
        check("Krähenlochhütte: Hinweis mit dem Wald entfernt", "nur der Wald" not in b and "keine Toilette" not in b)
        s, _, b = req(c, "/fotos")
        check("/fotos erreichbar", s == 200 and "Hochzeitsfotos" in b)
        check("Kopfzeile verlinkt auf Startseite (/#ablauf)", 'href="/#ablauf"' in b)

        # --- Zugriffsschutz ---
        for path in ("/admin", "/admin/export.csv", "/admin/rsvps"):
            s, h, _ = req(c, path)
            check(f"{path} ohne Login geschützt", s == 302 and "/admin/login" in h["Location"], f"{s}")

        # --- Login ---
        s, h, b = req(c, "/admin/login?next=/admin")
        check("Login-Seite rendert", s == 200 and "Admin-Login" in b)
        check("Login-Seite enthält next-Feld", 'name="next" value="/admin"' in b)
        ltok = csrf(b)
        s, _, _ = req(c, "/admin/login", {"username": USER, "password": PW})
        check("Login ohne CSRF-Token -> 403", s == 403, str(s))
        s, _, b = req(c, "/admin/login", {"csrf_token": ltok, "username": USER, "password": "falsch",
                                          "next": "/admin?meal=meat"})
        check("falsches Passwort -> 401 + Fehlermeldung", s == 401 and "nicht korrekt" in b, str(s))
        check("next bleibt nach Fehlversuch erhalten", 'value="/admin?meal=meat"' in b.replace("&amp;", "&"))
        ltok = csrf(b)
        s, _, _ = req(c, "/admin/login", {"csrf_token": ltok, "username": "falsch", "password": PW})
        check("falscher Benutzername -> 401", s == 401, str(s))

        for evil in ("//evil.example", "https://evil.example/x", "/\\evil.example"):
            c2 = new_client()
            pass_gate(c2)
            s, h, _ = admin_login(c2, nxt=evil)
            check(f"Open-Redirect blockiert ({evil})", s == 302 and "evil" not in h.get("Location", ""),
                  h.get("Location", ""))

        s, h, _ = admin_login(c, nxt="/admin?meal=meat")
        check("Login ok -> Redirect auf next", s == 302 and h["Location"].endswith("/admin?meal=meat"),
              h.get("Location", ""))

        # --- Dashboard ---
        s, _, b = req(c, "/admin")
        check("Dashboard erreichbar", s == 200 and "Admin-Dashboard" in b)
        check("Dashboard: Gesamt = 5", re.search(r'stat-card__value">\s*5\s*<', b) is not None)
        check("Dashboard: Gäste = 7", re.search(r'Gäste \(Zusagen\)</div>\s*<div class="stat-card__value">\s*7\s*<', b) is not None)
        check("Dashboard: Essen 2 Veg / 2 Fleisch", "2 Vegetarisch" in b and "2 Fleisch" in b)
        check("Dashboard: Logout-Button", "/admin/logout" in b)
        check("Kopfzeile im Dashboard verlinkt auf Startseite", 'href="/#ablauf"' in b)
        s, _, b = req(c, "/admin?meal=meat")
        check("Filter Essen=Fleisch", "Ben Beispiel" in b and "Dora Probe" in b and "Anna Muster" not in b)
        s, _, b = req(c, "/admin?q=Clara")
        check("Suche", "Clara Test" in b and "Anna Muster" not in b)
        s, _, b = req(c, "/admin?order=name_desc")
        check("Sortierung Name Z-A", b.index("Emil Demo") < b.index("Anna Muster"))
        tok = csrf(b)

        # --- CSV deutsch ---
        s, h, b, rows = csv_rows(c)
        check("CSV: Kopfzeile deutsch", rows[0] == ["Datum", "Name", "E-Mail", "Status", "Tage", "Personen", "Spende", "Essen", "Notizen"])
        anna = next(r for r in rows if r[1] == "Anna Muster")
        ben = next(r for r in rows if r[1] == "Ben Beispiel")
        dora = next(r for r in rows if r[1] == "Dora Probe")
        check("CSV: Tage deutsch (Freitag & Samstag / Samstag / Freitag)",
              (anna[4], ben[4], dora[4]) == ("Freitag & Samstag", "Samstag", "Freitag"), str((anna[4], ben[4], dora[4])))
        check("CSV: Essen deutsch (Vegetarisch / Mit Fleisch)", (anna[7], ben[7]) == ("Vegetarisch", "Mit Fleisch"), str((anna[7], ben[7])))
        check("CSV: keine internen Codes", not re.search(r";(fri|sat|both|vegetarian|meat);", b))

        # --- Sonderzeichen & Sicherheit bei RSVP-Eingaben ---
        cg = new_client()
        pass_gate(cg)
        _, _, idx = req(cg, "/")
        rtok = csrf(idx)

        def submit(name, email, notes="", contribution=""):
            return req(cg, "/rsvp", {"csrf_token": rtok, "name": name, "email": email, "attendance": "yes",
                                     "attendance_days": "sat", "meal_choice": "vegetarian", "guests": "2",
                                     "notes": notes, "contribution": contribution, "consent": "on"})

        s, h, _ = submit("O'Brien & Söhne <b>x</b>", "special@example.com",
                         "Tom & Jerry's \"Torte\"", "Käse & Wein")
        check("RSVP mit Sonderzeichen wird angenommen", s == 302 and "/thank-you" in h["Location"], f"{s}")
        s, _, tb = req(cg, h["Location"])
        check("Danke-Seite zeigt Namen korrekt (einfach escaped)",
              "O&#39;Brien &amp; Söhne &lt;b&gt;x&lt;/b&gt;" in tb and "&amp;amp;" not in tb)
        s, h, _ = submit("x'); alert(1); ('", "xss@example.com")
        check("RSVP mit Script-Versuch im Namen wird angenommen", s == 302, f"{s}")
        s, h, _ = submit("Zeile1\r\nBcc: evil@example.com", "newline@example.com")
        check("RSVP mit Zeilenumbruch im Namen wird angenommen", s == 302, f"{s}")

        s, _, b = req(c, "/admin?per_page=50")
        check("Dashboard: Sonderzeichen korrekt, nicht doppelt escaped",
              "O&#39;Brien &amp; Söhne &lt;b&gt;x&lt;/b&gt;" in b and "&amp;amp;" not in b and "&amp;#39;" not in b)
        check("Dashboard: kein ungefiltertes HTML aus Eingaben", "<b>x</b>" not in b)
        confirms = re.findall(r"onclick='return confirm\((.*?)\)'", b)
        evil_confirm = next((x for x in confirms if "alert" in x), "")
        check("Löschen-Button: Name als JSON-String (\\u0027), kein Script-Ausbruch",
              "\\u0027" in evil_confirm and "x'); alert(1)" not in b, evil_confirm[:80])
        s, h, b, rows = csv_rows(c)
        sp = next(r for r in rows if r[2] == "special@example.com")
        check("CSV: Sonderzeichen unverändert", sp[1] == "O'Brien & Söhne <b>x</b>" and sp[8] == "Tom & Jerry's \"Torte\"" and sp[6] == "Käse & Wein", str(sp))
        nl = next(r for r in rows if r[2] == "newline@example.com")
        check("Zeilenumbruch im Namen -> einzeilig", nl[1] == "Zeile1 Bcc: evil@example.com", repr(nl[1]))

        # --- Bearbeiten / Leeren / Löschen ---
        s, h, b = req(c, "/admin")
        tok = csrf(b)
        s, h, _ = req(c, "/admin/rsvps/update",
                      {"csrf_token": tok, "id": "1", "attendance": "yes", "attendance_days": "both",
                       "meal_choice": "vegetarian", "guests": "2", "contribution": "", "notes": ""},
                      {"Referer": f"{BASE}/admin?meal=vegetarian"})
        check("Update -> Redirect zurück aufs Dashboard (mit Filter)", s == 302 and h["Location"].endswith("/admin?meal=vegetarian"), h.get("Location", ""))
        _, _, _, rows = csv_rows(c)
        anna = next(r for r in rows if r[1] == "Anna Muster")
        check("Notiz und Spende lassen sich leeren", anna[8] == "" and anna[6] == "", str(anna))
        s, h, _ = req(c, "/admin/rsvps/delete", {"csrf_token": tok, "id": "3"}, {"Referer": f"{BASE}/admin"})
        check("Löschen -> Redirect aufs Dashboard", s == 302 and h["Location"].endswith("/admin"), h.get("Location", ""))
        _, _, b = req(c, "/admin?per_page=50")
        check("Eintrag gelöscht", "Clara Test" not in b)

        # --- Dashboard-Burst (60/min erlaubt) ---
        codes = [req(c, "/admin?order=name_asc")[0] for _ in range(25)]
        check("Dashboard: 25 Aufrufe in kurzer Zeit ohne 429", codes.count(200) == 25, str(sorted(set(codes))))

        # --- Bereinigung alter, doppelt kodierter Einträge ---
        con = sqlite3.connect(e.db)
        con.execute("INSERT INTO rsvp (name,email,attendance,guests,notes,consent,attendance_days) "
                    "VALUES ('Müller &amp; Söhne','legacy@example.com','yes',1,'It&#39;s fine',1,'sat')")
        con.commit()
        con.close()
        _, _, b = req(c, "/admin?q=legacy")
        check("Altbestand wird (noch) doppelt kodiert angezeigt", "&amp;amp;" in b)
        out = e.cli("unescape-db", "--dry-run")
        check("unescape-db --dry-run meldet 1 Eintrag", "1 Einträge würden geändert" in out, out[-200:])
        _, _, b = req(c, "/admin?q=legacy")
        check("Dry-Run ändert nichts", "&amp;amp;" in b)
        out = e.cli("unescape-db")
        check("unescape-db bereinigt 1 Eintrag", "1 Einträge bereinigt" in out, out[-200:])
        _, _, b = req(c, "/admin?q=legacy")
        check("Nach Bereinigung korrekt dargestellt", "Müller &amp; Söhne" in b and "It&#39;s fine" in b and "&amp;amp;" not in b)
        out = e.cli("unescape-db")
        check("zweiter Lauf wird verhindert", "Bereits ausgeführt" in out, out[-200:])

        # --- Logout ---
        s, h, _ = req(c, "/admin/logout", {"csrf_token": tok})
        check("Logout -> Redirect zum Login", s == 302 and "/admin/login" in h["Location"], f"{s}")
        s, h, _ = req(c, "/admin")
        check("nach Logout wieder geschützt", s == 302 and "/admin/login" in h["Location"], f"{s}")
        s, _, _ = req(c, "/admin/logout")
        check("Logout per GET nicht erlaubt (405)", s == 405, str(s))
        s, _, _ = req(c, "/")
        check("Gate-Session bleibt nach Admin-Logout bestehen", s == 200, str(s))

        # --- Login-Rate-Limit (zuletzt, verbraucht das Kontingent) ---
        c3 = new_client()
        pass_gate(c3)
        codes = []
        for i in range(13):
            _, _, bl = req(c3, "/admin/login")
            codes.append(req(c3, "/admin/login", {"csrf_token": csrf(bl), "username": USER, "password": f"x{i}"})[0])
        check("Login-Rate-Limit greift (429, nie ein Erfolg)", 429 in codes and set(codes) <= {401, 429}, str(codes))
    finally:
        e.stop()


def phase_closed():
    print("\n=== Phase B: RSVP geschlossen ===")
    e = Env("2026-05-01")
    e.seed()
    e.start()
    try:
        c = new_client()
        pass_gate(c)
        s, _, b = req(c, "/")
        check("RSVP zu: Formular ausgeblendet", 'action="/rsvp"' not in b and "Anmeldung geschlossen" in b)
        check("RSVP zu: kein 'Jetzt zusagen' im Hero", "Jetzt zusagen" not in b)
        check("RSVP zu: kein RSVP-Button in der Kopfzeile", 'class="btn btn--small">RSVP' not in b)
        check("RSVP zu: Vorschautext ohne 'jetzt zusagen'", "jetzt zusagen" not in b.lower())
        check("RSVP zu: Beschreibung ohne 'RSVP' im Meta-Text", "Übernachtung." in b)
        s, _, _ = req(c, "/rsvp", {"name": "X", "email": "x@example.com", "attendance": "no", "consent": "on"})
        check("RSVP zu: direkter POST wird abgewiesen", s in (400, 403), str(s))
    finally:
        e.stop()


if __name__ == "__main__":
    try:
        phase_open()
        phase_closed()
    except SystemExit as ex:
        print(ex)
        sys.exit(2)
    print(f"\n{sum(results)}/{len(results)} Tests bestanden")
    sys.exit(0 if all(results) else 1)
