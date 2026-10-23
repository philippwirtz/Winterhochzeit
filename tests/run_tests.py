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
import secrets
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
    def __init__(self, deadline, extra=None):
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
        self.env.update(extra or {})

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


def insert_ride(env, **fields):
    row = dict(token=secrets.token_hex(16), kind="offer", name="Test", origin="Villingen", direction="both",
               depart_time="", seats=3, seats_taken=0, phone="", email="t@example.com", note="",
               consent=1, active=1)
    row.update(fields)
    con = sqlite3.connect(env.db)
    con.execute(f"INSERT INTO ride ({','.join(row)}) VALUES ({','.join('?' * len(row))})", list(row.values()))
    con.commit()
    con.close()
    return row["token"]


def db_scalar(env, sql, *args):
    con = sqlite3.connect(env.db)
    try:
        return con.execute(sql, args).fetchone()[0]
    finally:
        con.close()


CONSENT_TEXT = ("Ich bin einverstanden, dass meine Angaben inklusive Kontaktdaten für andere Gäste dieser "
                "Seite sichtbar sind. Ich kann den Eintrag jederzeit löschen.")
RIDE_PATH = re.compile(r"/mitfahrt/mein/[0-9a-f]{32}$")


def ride_poster(client, tok):
    def post(**over):
        data = dict(csrf_token=tok, kind="offer", name="Anna", origin="78050 Villingen", direction="both",
                    depart_time="", seats="3", phone="", email="anna@example.com", note="", consent="on",
                    website="")
        data.update(over)
        return req(client, "/mitfahrt", data)
    return post


def phase_carpool():
    print("\n=== Phase C: Mitfahrbörse (Übersicht und Anlegen) ===")
    e = Env("2099-12-31", {"CARPOOL_RATE_LIMIT": "500/hour"})
    e.seed()
    e.start()
    try:
        c = new_client()
        s, h, _ = req(c, "/mitfahrt")
        check("Mitfahrt ohne Gate -> Gate", s == 302 and "/gate" in h["Location"], f"{s}")
        pass_gate(c)
        s, _, b = req(c, "/mitfahrt")
        check("Übersicht erreichbar", s == 200 and "Krähenlochhütte" in b and "Fahrer:in" in b, str(s))
        check("Leerzustand", "Noch keine Einträge" in b)
        check("Formular: Einwilligungstext, Hinweis und Honeypot",
              CONSENT_TEXT in b and "Vorname reicht" in b and 'name="website"' in b)
        _, _, b2 = req(c, "/mitfahrt?rolle=suche")
        check("?rolle=suche wählt die Rolle vor", re.search(r'value="seek"[^>]*checked', b2) is not None)
        post = ride_poster(c, csrf(b))

        s, h, _ = post()
        check("Anlegen per E-Mail -> Redirect auf Verwaltungslink", s == 302 and RIDE_PATH.search(h.get("Location", "")), f"{s} {h.get('Location')}")
        s, h, _ = post(kind="seek", name="Ben", origin="Freiburg", seats="1", phone="+49 (0) 176 1234567", email="")
        check("Anlegen per Telefon (Suche) -> 302", s == 302 and RIDE_PATH.search(h.get("Location", "")), f"{s}")
        _, _, b = req(c, "/mitfahrt")
        check("Übersicht zeigt neue Einträge", "Anna" in b and "Villingen" in b and "Ben" in b and "Freiburg" in b)
        check("Kontakt-Bereich mit Buttons und WhatsApp-Link",
              "<details" in b and "WhatsApp" in b and "Anrufen" in b and "E-Mail" in b and "https://wa.me/491761234567" in b)
        check("Telefonnummer steht im Klartext", "+49 (0) 176 1234567" in b)

        before = db_scalar(e, "SELECT COUNT(*) FROM ride")
        for label, over, part in [
            ("ohne Einwilligung", dict(consent=""), "Einwilligung"),
            ("ohne Kontakt", dict(email="", phone=""), "Telefon oder E-Mail"),
            ("ungültige E-Mail", dict(email="kaputt"), "gültige E-Mail"),
            ("ungültiges Telefon", dict(phone="0176 ABC"), "gültige Telefonnummer"),
            ("leerer Name", dict(name=" "), "Namen"),
            ("Plätze 9", dict(seats="9"), "1 bis 8"),
        ]:
            s, _, eb = post(**over)
            kept = 'value="Anna"' in eb or over.get("name") == " "
            check(f"Fehler {label}: 400, Meldung, Eingaben erhalten", s == 400 and part in eb and kept, f"{s}")
        check("Fehlerhafte Eingaben legen nichts an", db_scalar(e, "SELECT COUNT(*) FROM ride") == before)

        s, h, _ = post(name="Hanni", website="http://spam.example")
        check("Honeypot: Redirect auf /mitfahrt, nichts gespeichert",
              s == 302 and h["Location"].rstrip("/").endswith("/mitfahrt") and db_scalar(e, "SELECT COUNT(*) FROM ride") == before)

        s1, h1, _ = post(name="Dora", email="dora@example.com")
        s2, h2, _ = post(name="Dora", email="dora@example.com")
        check("Doppeltes Absenden: gleicher Verwaltungslink, eine Zeile",
              s1 == s2 == 302 and h1["Location"] == h2["Location"]
              and db_scalar(e, "SELECT COUNT(*) FROM ride WHERE name='Dora'") == 1)

        s, _, _ = post(name="O'Brien & <b>x</b> 🚗", email="ob@example.com")
        _, _, b = req(c, "/mitfahrt")
        check("Sonderzeichen: einfach escaped, kein HTML",
              s == 302 and "O&#39;Brien &amp; &lt;b&gt;x&lt;/b&gt; 🚗" in b and "<b>x</b>" not in b)
        s, _, _ = post(name="n" * 200, email="long@example.com")
        check("Überlanger Name wird auf 60 Zeichen gekürzt",
              s == 302 and db_scalar(e, "SELECT LENGTH(name) FROM ride WHERE email='long@example.com'") == 60)

        insert_ride(e, name="Voll Vera", seats=2, seats_taken=2, email="vera@example.com")
        insert_ride(e, name="Inaktiv Ida", active=0, email="ida@example.com")
        _, _, b = req(c, "/mitfahrt")
        check("Volles Angebot zeigt Badge 'Voll'", "Voll Vera" in b and re.search(r">\s*Voll\s*<", b) is not None)
        check("Inaktiver Eintrag erscheint nicht", "Inaktiv Ida" not in b)
    finally:
        e.stop()


def phase_carpool_manage():
    print("\n=== Phase C2: Mitfahrbörse (Verwaltung, Treffer, Aktionen) ===")
    import html as htmllib
    e = Env("2099-12-31", {"CARPOOL_RATE_LIMIT": "500/hour"})
    e.seed()
    e.start()
    try:
        c, c2 = new_client(), new_client()
        pass_gate(c)
        pass_gate(c2)
        seeker = insert_ride(e, kind="seek", name="Susi", origin="Villingen", direction="there", seats=2, email="susi@example.com")
        insert_ride(e, name="Olga", origin="Villingen-Schwenningen", phone="0176 1234567", email="o1@example.com")
        insert_ride(e, name="Otto", origin="Freiburg", email="o2@example.com")
        insert_ride(e, name="Voll Vic", origin="Villingen", seats=3, seats_taken=2, email="o3@example.com")
        insert_ride(e, name="Inaktiv Ina", origin="Villingen", active=0, email="o4@example.com")
        insert_ride(e, name="Rück Rita", origin="Villingen", direction="back", email="o5@example.com")
        insert_ride(e, name="O'Neil & <b>y</b>", origin='Villingen "Nord"', phone="0171 7654321", email='we"ird@example.com')

        s, _, b = req(c, f"/mitfahrt/mein/{seeker}")
        check("Verwaltungsseite erreichbar", s == 200 and "Susi" in b, str(s))
        head, _, rest = b.partition("Weitere Möglichkeiten")
        check("Treffer: passendes Angebot mit Badge 'Match' und Kontakt-Buttons",
              "Passende Treffer" in head and "Olga" in head and "Match" in head and "WhatsApp" in head)
        check("Weitere Möglichkeiten: Angebot ohne Orts-Treffer", "Otto" in rest and "Otto" not in head)
        check("Ausgeschlossen: volles, inaktives und Rückfahrt-Angebot",
              not any(x in b for x in ("Voll Vic", "Inaktiv Ina", "Rück Rita")))
        check("Sonderzeichen im Treffer sind escaped",
              "O&#39;Neil &amp; &lt;b&gt;y&lt;/b&gt;" in b and "<b>y</b>" not in b and "Villingen &#34;Nord&#34;" in b)
        hrefs = [htmllib.unescape(h) for h in re.findall(r'href="((?:mailto:|tel:|https://wa\.me/)[^"]*)"', b)]
        check("Kontakt-Links ohne Anführungszeichen, <, > oder Leerzeichen",
              len(hrefs) >= 4 and not any(ch in h for h in hrefs for ch in "\"<> "), str(hrefs[:3]))
        check("Link-Hinweis mit vollständiger URL", "Speichere diesen Link" in b and f"{BASE}/mitfahrt/mein/{seeker}" in b)

        _, _, ov = req(c, "/mitfahrt")
        _, _, ov2 = req(c2, "/mitfahrt")
        check("Session-Badge 'Dein Eintrag' nur nach Besuch des Links", "Dein Eintrag" in ov and "Dein Eintrag" not in ov2)

        # --- neuer Eintrag per Formular: Redirect führt auf eine funktionierende Verwaltungsseite ---
        _, _, f = req(c2, "/mitfahrt")
        s, h, _ = ride_poster(c2, csrf(f))(name="Neu Nina", email="nina@example.com")
        s2, _, nb = req(c2, h["Location"])
        _, _, ov2 = req(c2, "/mitfahrt")
        check("Neuer Eintrag: Verwaltungsseite lädt, Badge in der Übersicht",
              s == 302 and s2 == 200 and "Neu Nina" in nb and "Dein Eintrag" in ov2, f"{s} {s2}")

        # --- Plätze ---
        tok = csrf(b)
        offer = insert_ride(e, name="Seat Sam", seats=3, origin="Konstanz", email="sam@example.com")
        seat = lambda t: db_scalar(e, "SELECT seats_taken FROM ride WHERE token=?", t)

        def act(token, action, **data):
            return req(c, f"/mitfahrt/mein/{token}/{action}", {"csrf_token": tok, **data})

        codes = [act(offer, "platz-vergeben")[0] for _ in range(4)]
        check("Plätze: 4. 'Platz vergeben' geht nicht über 3 hinaus", codes == [302] * 4 and seat(offer) == 3, f"{codes} {seat(offer)}")
        codes = [act(offer, "platz-frei")[0] for _ in range(5)]
        check("Plätze: 'Platz frei' sinkt nie unter 0", codes == [302] * 5 and seat(offer) == 0, f"{codes} {seat(offer)}")
        s1, _, _ = act(seeker, "platz-vergeben")
        s2, _, _ = act(seeker, "platz-frei")
        check("Plätze: Aktionen gelten nur für Angebote", s1 in (302, 400) and s2 in (302, 400) and seat(seeker) == 0, f"{s1} {s2}")

        # --- schließen / öffnen ---
        kai = insert_ride(e, kind="seek", name="Kai", origin="Konstanz", direction="both", seats=1, email="kai@example.com")
        _, _, kb = req(c, f"/mitfahrt/mein/{kai}")
        check("Treffer enthält das Angebot vor dem Schließen", "Seat Sam" in kb)
        s, h, _ = act(offer, "schliessen")
        _, _, kb = req(c, f"/mitfahrt/mein/{kai}")
        _, _, ov = req(c2, "/mitfahrt")
        check("Schließen: Eintrag fehlt in Übersicht und Treffern",
              s == 302 and db_scalar(e, "SELECT active FROM ride WHERE token=?", offer) == 0
              and "Seat Sam" not in kb and "Seat Sam" not in ov)
        _, _, mb = req(c, f"/mitfahrt/mein/{offer}")
        check("Geschlossen: nur 'Wieder öffnen' und 'Löschen'",
              "Wieder öffnen" in mb and "Löschen" in mb and "Platz vergeben" not in mb and "Eintrag schließen" not in mb)
        act(offer, "oeffnen")
        _, _, ov = req(c2, "/mitfahrt")
        check("Wieder öffnen: Eintrag ist sichtbar", "Seat Sam" in ov)
        _, _, mb = req(c, f"/mitfahrt/mein/{offer}")
        check("Offener Eintrag zeigt Platz- und Schließen-Aktionen",
              "Platz vergeben" in mb and "Platz wieder frei" in mb and "Eintrag schließen" in mb)

        # --- löschen ---
        s, h, _ = act(offer, "loeschen")
        s404, _, _ = req(c, f"/mitfahrt/mein/{offer}")
        check("Löschen: Zeile weg, Redirect auf /mitfahrt, alter Link 404",
              s == 302 and h["Location"].rstrip("/").endswith("/mitfahrt")
              and db_scalar(e, "SELECT COUNT(*) FROM ride WHERE token=?", offer) == 0 and s404 == 404, f"{s} {s404}")

        # --- ungültige Kennungen, CSRF, Aktionen ---
        for path in ("/mitfahrt/mein/xyz", "/mitfahrt/mein/" + "a" * 32, "/mitfahrt/mein/" + "a" * 33,
                     "/mitfahrt/mein/..%2Fadmin", "/mitfahrt/mein/" + seeker.upper()):
            s, _, _ = req(c, path)
            check(f"Ungültige Kennung -> 404 ({path[:36]})", s == 404, str(s))
        s, _, _ = req(c, f"/mitfahrt/mein/{seeker}/schliessen", {})
        check("POST ohne CSRF-Token -> 403", s == 403, str(s))
        s, _, _ = act(seeker, "hacken")
        check("Unbekannte Aktion -> 404", s == 404, str(s))
    finally:
        e.stop()


def phase_carpool_limit():
    print("\n=== Phase D: Mitfahrbörse (Rate-Limit) ===")
    e = Env("2099-12-31")
    e.seed()
    e.start()
    try:
        c = new_client()
        pass_gate(c)
        _, _, b = req(c, "/mitfahrt")
        post = ride_poster(c, csrf(b))
        bad = [post(name=f"Fehler{i}", consent="")[0] for i in range(3)]
        check("Fehlerhafte Eingaben (400) verbrauchen kein Kontingent", bad == [400, 400, 400], str(bad))
        ok = [post(name=f"Gast{i}", email=f"gast{i}@example.com")[0] for i in range(6)]
        check("6 gültige Einträge pro Stunde sind erlaubt", ok == [302] * 6, str(ok))
        s, _, _ = post(name="Gast7", email="gast7@example.com")
        check("7. gültiger Eintrag -> 429", s == 429, str(s))
    finally:
        e.stop()


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


def phase_unit():
    print("\n=== Unit: carpool.py ===")
    from datetime import timedelta
    from types import SimpleNamespace

    sys.path.insert(0, str(ROOT))
    import carpool

    t0 = datetime(2026, 11, 1, 12, 0)
    counter = iter(range(1, 1000))

    def R(**kw):
        base = dict(id=next(counter), kind="offer", name="Anna", origin="Villingen", direction="both",
                    depart_time="", seats=3, seats_taken=0, phone="", email="", note="", active=True,
                    created_at=t0)
        base.update(kw)
        return SimpleNamespace(**base)

    ids = lambda rides: [r.id for r in rides]

    # --- Orts-Tokens und Score ---
    check("Tokens: Bindestrich trennt Wörter", carpool.place_tokens("Villingen-Schwenningen") == {"villingen", "schwenningen"})
    check("Tokens: PLZ-Vorwahl", carpool.place_tokens("78050 Villingen") == {"villingen", "plz780"})
    check("Tokens: ß wird ss", carpool.place_tokens("Straße") == {"strasse"})
    check("Tokens: zu kurz/leer", carpool.place_tokens("ab") == set() and carpool.place_tokens("") == set())
    check("Score: Teilwort", carpool.match_score("Villingen", "Villingen-Schwenningen") == 1)
    check("Score: gleiche PLZ-Vorwahl", carpool.match_score("78050 VS", "78054 Schwenningen") == 1)
    check("Score: kein Match / zu kurze Wörter", carpool.match_score("Freiburg", "Konstanz") == 0 and carpool.match_score("XY", "XY") == 0)
    check("Richtung", carpool.directions_overlap("both", "there") and not carpool.directions_overlap("there", "back") and carpool.directions_overlap("back", "both"))

    # --- Telefon ---
    check("Telefon: 0176", carpool.normalize_phone("0176 1234567") == "491761234567")
    check("Telefon: +49", carpool.normalize_phone("+49 176 1234567") == "491761234567")
    check("Telefon: 0049", carpool.normalize_phone("0049 176 1234567") == "491761234567")
    check("Telefon: +49 (0)", carpool.normalize_phone("+49 (0) 176 1234567") == "491761234567")
    check("Telefon: Trennzeichen", carpool.normalize_phone("0176/123-4567") == "491761234567")
    check("Telefon: andere Vorwahl bleibt", carpool.normalize_phone("+41 79 123 45 67") == "41791234567")
    check("Telefon: ungültig", all(carpool.normalize_phone(x) is None for x in ("", "12345", "0176 ABC4567", "+49 176 1234567 8901")))

    # --- Matching ---
    S = R(kind="seek", direction="there", seats=2)
    O1 = R(origin="Villingen-Schwenningen")
    O2 = R(origin="Freiburg")
    O3 = R(origin="Villingen", seats=3, seats_taken=2)
    O4 = R(origin="Villingen", active=False)
    O5 = R(origin="Villingen", direction="back")
    S2 = R(kind="seek", direction="there", seats=1)
    m, o = carpool.find_matches(S, [S, O1, O2, O3, O4, O5, S2])
    check("Match: nur Gegenrolle, passende Richtung, freie Plätze, aktiv; Rest unter 'others'",
          ids(m) == [O1.id] and ids(o) == [O2.id], f"{ids(m)} {ids(o)}")
    A = R(origin="Villingen Schwenningen", created_at=t0 + timedelta(hours=2))
    B = R(origin="Villingen", created_at=t0)
    C = R(origin="Villingen", created_at=t0 + timedelta(hours=1))
    Sx = R(kind="seek", origin="78050 Villingen Schwenningen", direction="both", seats=1)
    m, _ = carpool.find_matches(Sx, [C, B, A])
    check("Match: höherer Score zuerst, bei Gleichstand älterer Eintrag zuerst", ids(m) == [A.id, B.id, C.id], str(ids(m)))
    offer = R(kind="offer", seats=3, seats_taken=1, origin="Villingen")
    k2 = R(kind="seek", seats=2, origin="Villingen")
    k3 = R(kind="seek", seats=3, origin="Villingen")
    m, o = carpool.find_matches(offer, [k2, k3])
    check("Match: Platzregel gilt auch aus Sicht des Angebots", ids(m) == [k2.id] and ids(o) == [], f"{ids(m)} {ids(o)}")

    # --- Nachricht und Kontakt-Links ---
    msg_offer = carpool.message_text(R(kind="offer", name="Anna"))
    msg_seek = carpool.message_text(R(kind="seek", name="Ben", origin="Villingen"))
    check("Nachricht: Fahrtangebot", "Fahrtangebot" in msg_offer and "Anna" in msg_offer and "Krähenlochhütte" in msg_offer)
    check("Nachricht: Mitfahr-Anfrage", "Mitfahr-Anfrage" in msg_seek and "Villingen" in msg_seek)
    both = carpool.contact_links(R(phone="0176 1234567", email="anna@example.com"))
    check("Links: Reihenfolge und Arten bei Telefon+E-Mail", [x["kind"] for x in both] == ["whatsapp", "tel", "mail"], str(both))
    hrefs = {x["kind"]: x["href"] for x in both}
    check("Links: WhatsApp", hrefs["whatsapp"].startswith("https://wa.me/491761234567?text="))
    check("Links: Anrufen", hrefs["tel"] == "tel:+491761234567")
    check("Links: E-Mail", hrefs["mail"].startswith("mailto:anna@example.com?subject="))
    check("Links: nur E-Mail", [x["kind"] for x in carpool.contact_links(R(email="a@example.com"))] == ["mail"])
    check("Links: nur Telefon", [x["kind"] for x in carpool.contact_links(R(phone="0176 1234567"))] == ["whatsapp", "tel"])
    odd = carpool.contact_links(R(name="Ann\"a <b> & 'C'", phone="0176 1234567", email="anna@example.com"))
    check("Links: Sonderzeichen im Namen brechen keinen href", not any(c in x["href"] for x in odd for c in "\"<> "))

    # --- Eingabe-Validierung ---
    def email_ok(a):
        return "@" in a and "." in a.split("@")[-1] and " " not in a

    def F(**over):
        f = dict(kind="offer", name="Anna", origin="78050 Villingen", direction="both", depart_time="ca. 16:00",
                 seats="3", phone="", email="anna@example.com", note="", consent="on")
        f.update(over)
        return f

    def errs(**over):
        return carpool.validate_ride_input(F(**over), email_ok)[1]

    cleaned, e0 = carpool.validate_ride_input(F(), email_ok)
    check("Validierung: gültiges Angebot", e0 == [] and cleaned["seats"] == 3 and cleaned["kind"] == "offer", str(e0))
    check("Validierung: ohne Einwilligung", any("Einwilligung" in x for x in errs(consent="")))
    check("Validierung: ohne Kontakt", any("Telefon oder E-Mail" in x for x in errs(email="", phone="")))
    check("Validierung: ungültige E-Mail", any("gültige E-Mail" in x for x in errs(email="kaputt")))
    check("Validierung: ungültiges Telefon", any("gültige Telefonnummer" in x for x in errs(phone="0176 ABC")))
    check("Validierung: leerer Name", any("Namen" in x for x in errs(name="  ")))
    check("Validierung: leerer Startort", any("Startort" in x for x in errs(origin="")))
    check("Validierung: Angebot mit 0 oder 9 Plätzen", errs(seats="0") != [] and errs(seats="9") != [])
    check("Validierung: Suche mit 7 Personen oder Text", errs(kind="seek", seats="7") != [] and errs(seats="viele") != [])
    check("Validierung: ungültige Rolle/Richtung", errs(kind="x") != [] and errs(direction="x") != [])
    check("Validierung: Name auf 60 Zeichen gekürzt", len(carpool.validate_ride_input(F(name="a" * 100), email_ok)[0]["name"]) == 60)
    check("Validierung: Emoji bleiben erhalten", carpool.validate_ride_input(F(name="Anna 🚗"), email_ok)[0]["name"] == "Anna 🚗")


if __name__ == "__main__":
    try:
        phase_unit()
        phase_open()
        phase_closed()
        phase_carpool()
        phase_carpool_manage()
        phase_carpool_limit()
    except SystemExit as ex:
        print(ex)
        sys.exit(2)
    print(f"\n{sum(results)}/{len(results)} Tests bestanden")
    sys.exit(0 if all(results) else 1)
