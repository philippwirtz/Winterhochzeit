# Mitfahrbörse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Gäste bieten für Freitagabend (Krähenlochhütte) Fahrten an oder suchen Mitfahrten, bekommen Match-Vorschläge und nehmen per vorbefüllten Links Kontakt auf.

**Architecture:** Reine Logik in neuem `carpool.py` (kein Flask/DB), Persistenz als Modell `Ride` in `app.py`, server-gerenderte Seiten mit CSRF-Formularen. Verwaltung ohne Konto über einen geheimen Link pro Eintrag. Tests erweitern das bestehende `tests/run_tests.py`.

**Tech Stack:** Python 3.10, Flask 3, Flask-SQLAlchemy, Flask-Limiter 4, Jinja2, SQLite. Keine neuen Abhängigkeiten.

**Spec:** `docs/superpowers/specs/2026-10-23-mitfahrboerse-design.md`

## Global Constraints

- Python 3.10 kompatibel; nur Standardbibliothek in `carpool.py`; keine neuen Pakete in `requirements.txt`.
- Alle sichtbaren Texte deutsch. Zieltext der Fahrt: "Krähenlochhütte", Freitag 04.12., ab 17 Uhr.
- Dateien mit LF-Zeilenenden. Bearbeiten im WSL-Repo `/home/philippwirtz/Winterhochzeit/winterhochzeit` (Windows-Zugriff über `\\wsl.localhost\Ubuntu-22.04\...`).
- Testbefehl (**T**): `wsl.exe -e bash -lc 'cd /home/philippwirtz/Winterhochzeit/winterhochzeit && .venv/bin/python tests/run_tests.py'`. Erfolg = letzte Zeile `N/N Tests bestanden`, Exit-Code 0.
- Feldgrenzen: `name` ≤ 60, `origin` ≤ 80, `depart_time` ≤ 30, `note` ≤ 200, `phone` ≤ 40, `email` ≤ 120. Plätze: offer 1–8, seek 1–6. `token` = `secrets.token_hex(16)`.
- Werte: `kind` ∈ `offer`/`seek`; `direction` ∈ `there`/`back`/`both`; Telefon 6–15 Ziffern, erlaubte Zeichen nur Ziffern und `+ - ( ) /` und Leerzeichen.
- Limits: Anlegen `6/hour` per IP nur für Antworten mit Status < 400 (`deduct_when`); Aktionen `30/hour`. CSRF auf allen POSTs. Honeypot-Feld heißt `website`.
- `CARPOOL_ENABLED` (Standard `"1"`); bei `0` antworten alle Mitfahrt-Routen mit 404 und der Menüpunkt entfällt.
- Menüpunkt-Beschriftung: "Mitfahrt". CSS-Cache-Parameter in `base.html`: `?v=17` → `?v=18`.
- Commit-Nachrichten enden mit der Zeile `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Gepusht wird nur nach ausdrücklicher Freigabe des Nutzers.

## Review Focus

1. **Telefonformate:** `+49 (0) 176 1234567`, `0176/123-4567`, `0049 176 …` ergeben dieselbe WhatsApp-Nummer `491761234567`; Buchstaben oder zu kurze/lange Nummern werden abgelehnt (Task 1 + Task 2).
2. **Doppeltes Absenden (Doppelklick, Zurück-Button):** ein identischer aktiver Eintrag (gleiche `kind`, `name`, `origin`, `phone`, `email`) wird nicht zweimal angelegt, die zweite Anfrage führt auf den vorhandenen Eintrag (Task 2).
3. **Plätze:** wiederholtes "Platz vergeben" geht nie über `seats`, "Platz frei" nie unter 0; die Aktionen gelten nur für `offer` (Task 3).
4. **Ungültige, gelöschte oder manipulierte Kennung** (`../admin`, zu lang, Großbuchstaben, nach Löschen) → 404 ohne Fehlerseite (Task 3).
5. **Sonderzeichen, Emoji, überlange Eingaben** in Name/Startort/Notiz: kein Absturz, abgeschnitten, einfach escaped, kein Ausbruch aus `href` (Task 1 + Task 2).

---

## File Structure

| Datei | Verantwortung |
|---|---|
| `carpool.py` (neu) | reine Logik: Tokens, Telefon, Match, Nachrichtentext, Kontakt-Links, Eingabe-Validierung |
| `app.py` | `CARPOOL_ENABLED`, Modell `Ride`, Routen, Jinja-Globals, Context-Processor, CLI `purge-rides` |
| `templates/carpool.html` (neu) | Übersicht + Formular |
| `templates/carpool_mine.html` (neu) | Verwaltungsseite "Dein Eintrag" |
| `templates/admin_carpool.html` (neu) | Admin-Liste |
| `templates/base.html`, `index.html`, `privacy.html`, `admin_dashboard.html` | Menüpunkt, Hütten-Link, Datenschutz-Absatz, Admin-Link |
| `static/styles.css` | Klassen `.ride-*` |
| `tests/run_tests.py` | `phase_unit()`, `phase_carpool()`, Erweiterungen von `Env` und Phase B |
| `README.md` | Abschnitt Mitfahrbörse |

---

### Task 1: Reine Logik `carpool.py`

**Files:**
- Create: `carpool.py`
- Modify: `tests/run_tests.py` (neue Funktion `phase_unit()`, in `__main__` als erste Phase aufrufen; `sys.path.insert(0, str(ROOT))` und `import carpool` darin)

**Interfaces:**
- Produces (alle in `carpool.py`):
  - `DEST = "Krähenlochhütte"`, `KIND_LABELS = {"offer": "Fahrer:in", "seek": "Mitfahrer:in"}`, `DIRECTION_LABELS = {"there": "Hinfahrt", "back": "Rückfahrt", "both": "Hin und zurück"}`
  - `place_tokens(text: str) -> set[str]`
  - `normalize_phone(raw: str) -> str | None` (Ziffernstring mit Ländervorwahl oder `None` bei ungültig)
  - `directions_overlap(a: str, b: str) -> bool`
  - `match_score(origin_a: str, origin_b: str) -> int`
  - `find_matches(ride, candidates) -> tuple[list, list]` → `(matches, others)`
  - `message_text(ride) -> str`
  - `contact_links(ride) -> list[dict[str, str]]` (Schlüssel `kind` ∈ `whatsapp`/`tel`/`mail`, `label`, `href`)
  - `validate_ride_input(form: Mapping[str, str], valid_email: Callable[[str], bool]) -> tuple[dict, list[str]]` → `(cleaned, errors)`; `cleaned` hat `kind, name, origin, direction, depart_time, seats, phone, email, note`.
  - Ride-Objekte werden duck-typed gelesen: `id, kind, name, origin, direction, depart_time, seats, seats_taken, phone, email, note, active, created_at`.

- [ ] **Step 1: Failing tests in `phase_unit()`** (`check(...)`-Stil des Runners, `SimpleNamespace` als Ride):

```python
check("Tokens: Bindestrich trennt Wörter", carpool.place_tokens("Villingen-Schwenningen") == {"villingen", "schwenningen"})
check("Tokens: PLZ-Vorwahl", carpool.place_tokens("78050 Villingen") == {"villingen", "plz780"})
check("Tokens: ß wird ss", carpool.place_tokens("Straße") == {"strasse"})
check("Tokens: zu kurz/leer", carpool.place_tokens("ab") == set() and carpool.place_tokens("") == set())
check("Score: Teilwort", carpool.match_score("Villingen", "Villingen-Schwenningen") == 1)
check("Score: gleiche PLZ-Vorwahl", carpool.match_score("78050 VS", "78054 Schwenningen") == 1)
check("Score: kein Match / zu kurze Wörter", carpool.match_score("Freiburg", "Konstanz") == 0 and carpool.match_score("XY", "XY") == 0)
check("Richtung", carpool.directions_overlap("both", "there") and not carpool.directions_overlap("there", "back") and carpool.directions_overlap("back", "both"))
check("Telefon: 0176", carpool.normalize_phone("0176 1234567") == "491761234567")
check("Telefon: +49", carpool.normalize_phone("+49 176 1234567") == "491761234567")
check("Telefon: 0049", carpool.normalize_phone("0049 176 1234567") == "491761234567")
check("Telefon: +49 (0)", carpool.normalize_phone("+49 (0) 176 1234567") == "491761234567")
check("Telefon: Trennzeichen", carpool.normalize_phone("0176/123-4567") == "491761234567")
check("Telefon: andere Vorwahl bleibt", carpool.normalize_phone("+41 79 123 45 67") == "41791234567")
check("Telefon: ungültig", all(carpool.normalize_phone(x) is None for x in ("", "12345", "0176 ABC4567", "+49 176 1234567 8901")))
```

  Match-Filter-Test: Suchender `S` (origin "Villingen", direction `there`, seats 2) gegen Angebote `O1` ("Villingen-Schwenningen", `both`, 3/0), `O2` ("Freiburg", `both`, 3/0), `O3` ("Villingen", `both`, 3 Plätze, 2 vergeben → nur 1 frei), `O4` (inaktiv), `O5` (`back`), einen zweiten Suchenden und `S` selbst: `find_matches(S, alle) == ([O1], [O2])`. Sortierung: Score 2 vor Score 1; bei gleichem Score älteres `created_at` zuerst. Symmetrie: für ein Angebot als `ride` mit Suchenden als Kandidaten gilt dieselbe Platzregel (`offer.seats - offer.seats_taken >= seek.seats`).
  Weitere Tests: `message_text` (offer enthält "Fahrtangebot", Namen und "Krähenlochhütte"; seek enthält "Mitfahr-Anfrage" und den Startort); `contact_links` (phone+email → Arten `["whatsapp","tel","mail"]`, WhatsApp-href beginnt mit `https://wa.me/491761234567?text=`, tel-href `tel:+491761234567`, mail-href beginnt mit `mailto:anna@example.com?subject=`; nur E-Mail → `["mail"]`; nur Telefon → `["whatsapp","tel"]`; Name `Ann"a <b> & 'C'` ergibt hrefs ohne die Zeichen `"`, `<`, `>`, Leerzeichen); `validate_ride_input` (gültiges Angebot → `errors == []`, `cleaned["seats"] == 3`; je ein Fehlertest mit Teilstring in der Meldung: fehlende Einwilligung "Einwilligung", weder Telefon noch E-Mail "Telefon oder E-Mail", ungültige E-Mail, ungültiges Telefon, leerer Name, leerer Startort, offer-Plätze 0 und 9, seek-Personen 7, ungültige `kind`/`direction`; Name mit 100 Zeichen wird auf 60 gekürzt; Emoji bleiben erhalten).

- [ ] **Step 2: Run T** — Expected: `ModuleNotFoundError: No module named 'carpool'`.
- [ ] **Step 3: Implement `carpool.py`** mit den Signaturen oben. Tokens: Kleinbuchstaben, `ß`→`ss`, Wörter per `re.findall(r"[^\W_]+")`, ≥ 3 Zeichen und mit mindestens einem Buchstaben (reine Zahlen sind kein Wort); zusätzlich für jede Zahl mit ≥ 3 Ziffern das Token `plz` + die ersten 3 Ziffern. Telefon: Zeichenprüfung und 6–15 Ziffern, dann `+`/`00` entfernen, führende einzelne `0` → `49`, bei `49` gefolgt von `0` diese `0` streichen. `find_matches`: Regeln aus Spec-Abschnitt "Match-Logik"; Sortierung `(-score, created_at)`. Links: feste Schemata; Query-Werte (`text`, `subject`, `body`) mit `urllib.parse.quote(..., safe="")`, die E-Mail-Adresse im `mailto:`-Pfad mit `safe="@+"`.
- [ ] **Step 4: Run T** — Expected: alle neuen Prüfungen PASS, bisherige 74 weiter PASS, Exit-Code 0.
- [ ] **Step 5: Commit** `git add carpool.py tests/run_tests.py` — "Mitfahrbörse: reine Logik (Match, Telefon, Kontakt-Links, Validierung) mit Tests".

---

### Task 2: Modell, Übersicht und Anlegen

**Files:**
- Modify: `app.py` (Config, Modell, Jinja-Globals, Context-Processor, Routen), `tests/run_tests.py`, `static/styles.css`
- Create: `templates/carpool.html`

**Interfaces:**
- Consumes: alle Funktionen aus Task 1.
- Produces:
  - `CARPOOL_ENABLED: bool`; Context-Variable `carpool_enabled`; Jinja-Globals `contact_links`, `KIND_LABELS`, `DIRECTION_LABELS`.
  - Modell `Ride` (Tabelle `ride`) mit den Feldern der Spec; `token` unique+index; `created_at` mit `server_default=func.now()`.
  - Route-Endpoint `carpool` für `GET`/`POST /mitfahrt`.
  - `own_tokens() -> list[str]` liest `session["ride_tokens"]`; `remember_token(token: str) -> None` hängt an (max. 20, ohne Duplikate).
  - Test-Helfer `insert_ride(env: Env, **fields) -> str` in `tests/run_tests.py` (SQLite-Insert mit Defaults: `kind="offer"`, `direction="both"`, `seats=3`, `seats_taken=0`, `consent=1`, `active=1`, zufälliger `token`; liefert den `token`). `Env.__init__(self, deadline, extra=None)` übernimmt zusätzliche Umgebungsvariablen.

- [ ] **Step 1: Failing E2E-Tests** in neuer `phase_carpool()` (frischer Server, `Env("2099-12-31")`, Gate durchlaufen). Assertions:
  - `GET /mitfahrt` ohne Gate → 302 auf `/gate`; mit Gate → 200, enthält "Krähenlochhütte" und "Fahrer:in"; leere Liste zeigt einen Leerzustand-Text ("Noch keine Einträge").
  - Erfolg per E-Mail: `POST /mitfahrt` mit CSRF-Token (aus GET) und `kind=offer, name="Anna", origin="78050 Villingen", direction=both, seats=3, email=anna@example.com, consent=on` → 302, `Location` beginnt mit `/mitfahrt/mein/` + 32 Hex-Zeichen; danach zeigt die Übersicht "Anna" und "Villingen".
  - Erfolg per Telefon (`seek`, `phone="+49 (0) 176 1234567"`) → 302.
  - Fehler (je Status 400, Meldung als Teilstring, Eingaben im Formular erhalten): ohne Einwilligung, ohne Kontakt, ungültige E-Mail, Telefon `"0176 ABC"`, leerer Name, offer-Plätze 9.
  - Honeypot: `website="x"` → 302 auf `/mitfahrt`, es entsteht kein Eintrag (Zeilenzahl in der DB unverändert).
  - Doppeltes Absenden: derselbe gültige POST zweimal → beide Antworten führen auf dieselbe `Location`, die DB enthält genau eine Zeile.
  - Sonderzeichen: Name `O'Brien & <b>x</b> 🚗` → Übersicht enthält `O&#39;Brien &amp; &lt;b&gt;x&lt;/b&gt; 🚗`, nicht `<b>x</b>`; Name mit 200 Zeichen wird gespeichert gekürzt (60).
  - Kontakt-Bereich: Karte enthält `<details`, die Texte "WhatsApp", "Anrufen", "E-Mail" und den `href` `https://wa.me/491761234567` (Eintrag mit Telefon).
  - Eintrag aus `insert_ride(active=0)` erscheint nicht in der Übersicht; ein Angebot mit `seats=2, seats_taken=2` zeigt "Voll".
  - Das Formular enthält exakt den Einwilligungstext "Ich bin einverstanden, dass meine Angaben inklusive Kontaktdaten für andere Gäste dieser Seite sichtbar sind. Ich kann den Eintrag jederzeit löschen.", den Hinweis "Vorname reicht" und das versteckte Feld `name="website"`.
  - Rate-Limit (eigene `phase_carpool_limit()` mit frischem Server): 6 gültige, **unterschiedliche** POSTs → 302; ein 7. gültiger → 429; zwischendurch 3 fehlerhafte POSTs (400) verbrauchen kein Kontingent (der 6. gültige klappt trotzdem).
- [ ] **Step 2: Run T** — Expected: FAIL (404 auf `/mitfahrt`).
- [ ] **Step 3: Implement** in `app.py`: `CARPOOL_ENABLED` aus Umgebung; Modell `Ride`; Jinja-Globals; Context-Processor `inject_template_globals` um `carpool_enabled` erweitern; Route `carpool` (abort 404 bei deaktiviert; POST mit `@limiter.limit("6/hour", methods=["POST"], deduct_when=lambda r: r.status_code < 400)`; Ablauf: Honeypot → Redirect; `validate_ride_input` → Fehler: `render_template("carpool.html", ...)` mit Status 400, Eingaben erhalten; Duplikat-Suche über `kind, name, origin, phone, email` unter aktiven Einträgen → Redirect auf vorhandenen; sonst anlegen, `remember_token`, Redirect auf den Pfad `f"/mitfahrt/mein/{token}"` als String, weil der Endpoint `carpool_mine` erst in Task 3 entsteht und dort durch `url_for` ersetzt wird; bis dahin prüfen die Tests nur den `Location`-Header). In `__main__` die Phasen in der Reihenfolge `phase_unit`, `phase_open`, `phase_closed`, `phase_carpool`, `phase_carpool_limit` aufrufen. Übersicht: aktive Einträge je Rolle, neueste zuerst, Badge "Voll" (`seats_taken >= seats`), `?rolle=fahre|suche` wählt die Rolle vor. `carpool.html` erweitert `base.html`; Formular mit zwei Rollenkarten (Radio), kleines Inline-Script für die Beschriftung von Plätze/Personen. `styles.css`: Klassen `.ride-*` (Spalten, Karten, Rollenkarten, Badges, Formular) im Stil der vorhandenen `.card`/`.btn`; mobil einspaltig.
- [ ] **Step 4: Run T** — Expected: alle PASS. Danach Sichtprüfung im Browser (Testinstanz wie in früheren Läufen, Gate-Code `gate-test`): `/mitfahrt` auf Desktop- und Handybreite (375 px), Karten und Formular ohne Überlappung oder seitlichen Überlauf.
- [ ] **Step 5: Commit** `git add app.py templates/carpool.html static/styles.css tests/run_tests.py` — "Mitfahrbörse: Modell, Übersicht und Anlegen".

---

### Task 3: Verwaltung "Dein Eintrag", Treffer und Aktionen

**Files:**
- Modify: `app.py`, `templates/carpool.html` (Badge "Dein Eintrag"), `static/styles.css`, `tests/run_tests.py`
- Create: `templates/carpool_mine.html`

**Interfaces:**
- Consumes: `Ride`, `own_tokens`, `remember_token`, `find_matches`, `contact_links` (Task 1/2).
- Produces:
  - `get_ride_or_404(token: str) -> Ride` (Format `^[0-9a-f]{32}$`, sonst `abort(404)`; unbekannt → 404).
  - Endpoint `carpool_mine` für `GET /mitfahrt/mein/<token>` (fügt Token der Session hinzu).
  - Endpoint `carpool_action` für `POST /mitfahrt/mein/<token>/<aktion>` mit `aktion ∈ {platz-vergeben, platz-frei, schliessen, oeffnen, loeschen}`, `@limiter.limit("30/hour", methods=["POST"])`; Redirect auf `carpool_mine`, bei `loeschen` auf `carpool`.

- [ ] **Step 1: Failing E2E-Tests** (in `phase_carpool()`, Einträge über `insert_ride` bzw. POST):
  - Verwaltungsseite eines Suchenden "Villingen" (`there`, 2 Personen) zeigt unter "Passende Treffer" das Angebot "Villingen-Schwenningen" mit Badge "Match" und Kontakt-Buttons, das Angebot "Freiburg" nur unter "Weitere Möglichkeiten"; ein volles Angebot, ein inaktives und ein Angebot mit Richtung `back` fehlen.
  - Die Seite zeigt die vollständige URL des eigenen Links samt Hinweis "Speichere diesen Link".
  - Session-Badge: nach Besuch der Verwaltungsseite trägt die Karte dieses Eintrags in `/mitfahrt` "Dein Eintrag"; ein neuer Client ohne Besuch sieht das Badge nicht.
  - Plätze: `platz-vergeben` erhöht `seats_taken` bis `seats` (4. Klick bei `seats=3` bleibt 3, Status 302); `platz-frei` sinkt nie unter 0; beide Aktionen bei einem `seek`-Eintrag ändern nichts (Status 302 oder 400, `seats_taken` bleibt 0).
  - `schliessen` → Eintrag fehlt in Übersicht und in den Treffern anderer; Verwaltungsseite zeigt nur "Wieder öffnen" und "Löschen"; `oeffnen` → wieder sichtbar.
  - `loeschen` → Zeile weg, Redirect auf `/mitfahrt`, erneuter GET der alten Kennung → 404.
  - Kennungen: `/mitfahrt/mein/xyz`, `/mitfahrt/mein/` + 32× `a` (unbekannt), `/mitfahrt/mein/` + 33 Hex-Zeichen, `/mitfahrt/mein/..%2Fadmin`, Großbuchstaben-Variante einer echten Kennung → jeweils 404.
  - POST ohne CSRF-Token → 403; unbekannte `aktion` → 404.
  - Sonderzeichen im Namen/Startort der Treffer erscheinen escaped; in keinem `href` stehen `"`, `<`, `>` oder Leerzeichen.
- [ ] **Step 2: Run T** — Expected: FAIL (404 auf `/mitfahrt/mein/...`).
- [ ] **Step 3: Implement** `get_ride_or_404`, beide Routen (den Redirect-Pfad aus Task 2 durch `url_for("carpool_mine", token=...)` ersetzen) und `carpool_mine.html` (Zusammenfassung, Link-Hinweis, Treffer/Weitere Möglichkeiten mit Kontakt-Buttons, Aktionsformulare mit CSRF; Fahrer sehen "x von y Plätzen frei" und Buttons "Platz vergeben"/"Platz wieder frei"). Aktionen ändern `seats_taken` nur innerhalb 0…`seats` und nur bei `offer`. Badge "Dein Eintrag" in `carpool.html` über `own_tokens()`.
- [ ] **Step 4: Run T** — Expected: alle PASS. Sichtprüfung im Browser: Verwaltungsseite mit Treffern auf Desktop und 375 px.
- [ ] **Step 5: Commit** — "Mitfahrbörse: Verwaltung per Link, Treffer und Aktionen".

---

### Task 4: Admin-Ansicht und Aufräumbefehl

**Files:**
- Modify: `app.py`, `templates/admin_dashboard.html` (Link im Kopf neben dem Logout-Button), `tests/run_tests.py`
- Create: `templates/admin_carpool.html`

**Interfaces:**
- Consumes: `Ride`, `admin_protected`.
- Produces: Endpoint `admin_carpool` (`GET /admin/mitfahrt`), `admin_carpool_delete` (`POST /admin/mitfahrt/loeschen`, Feld `id`, `@limiter.limit("60/minute")`, Redirect zurück auf `admin_carpool`), CLI `flask purge-rides [--yes]`.

- [ ] **Step 1: Failing Tests** (in `phase_open()` oder `phase_carpool()` mit Admin-Login): `/admin/mitfahrt` ohne Login → 302 auf `/admin/login`; mit Login 200, listet aktive **und** geschlossene Einträge mit Telefon/E-Mail; `POST /admin/mitfahrt/loeschen` mit CSRF löscht genau einen Eintrag (unbekannte `id` → 404); ohne Login geschützt; Dashboard-HTML enthält einen Link auf `/admin/mitfahrt`; `e.cli("purge-rides")` meldet die Anzahl und löscht nichts; `e.cli("purge-rides", "--yes")` löscht alle (Übersicht danach leer).
- [ ] **Step 2: Run T** — Expected: FAIL.
- [ ] **Step 3: Implement** Routen, Template (Tabelle im Stil von `admin_dashboard.html`, Lösch-Button mit `tojson`-Bestätigung wie dort), CLI-Befehl mit `click.option("--yes", is_flag=True)`.
- [ ] **Step 4: Run T** — Expected: alle PASS.
- [ ] **Step 5: Commit** — "Mitfahrbörse: Admin-Liste und purge-rides".

---

### Task 5: Navigation, Datenschutz, Abschalter, Doku

**Files:**
- Modify: `templates/base.html`, `templates/index.html`, `templates/privacy.html`, `README.md`, `tests/run_tests.py` (`Env`-Extra `CARPOOL_ENABLED` in Phase B)

**Interfaces:** Consumes `carpool_enabled` (Task 2).

- [ ] **Step 1: Failing Tests:** Phase A: Kopfzeile enthält `href="/mitfahrt"` mit Text "Mitfahrt"; Freitags-Karte "Krähenlochhütte" enthält einen Link auf `/mitfahrt` mit Text "Fahrgemeinschaft"; `/privacy` enthält "Mitfahrbörse"; CSS-Link enthält `styles.css?v=18`. Phase B mit `extra={"CARPOOL_ENABLED": "0"}`: kein Menüpunkt "Mitfahrt", kein Link in der Hütten-Karte, `GET /mitfahrt` → 404, `GET /mitfahrt/mein/` + 32× `a` → 404.
- [ ] **Step 2: Run T** — Expected: FAIL.
- [ ] **Step 3: Implement:** Menüpunkt zwischen FAQ und Fotos (nur bei `carpool_enabled`); Link "Fahrgemeinschaft bilden →" im Text der Hütten-Karte (nur bei `carpool_enabled`); Datenschutz-Absatz "Mitfahrbörse" (Zweck, Sichtbarkeit nur hinter dem Zugangscode, Löschung über den eigenen Eintrag oder durch das Brautpaar, spätestens nach der Feier); `?v=18`; README: Abschnitt Mitfahrbörse, `CARPOOL_ENABLED` in der Variablentabelle, `purge-rides` bei den Wartungsbefehlen, Tests-Beschreibung ergänzen.
- [ ] **Step 4: Run T** — Expected: alle PASS.
- [ ] **Step 5: Commit** — "Mitfahrbörse: Menüpunkt, Datenschutz, Abschalter, README".

---

### Task 6: Gesamtprüfung

- [ ] **Step 1:** T einmal vollständig; Expected: alle PASS (74 bestehende + neue), Exit-Code 0.
- [ ] **Step 2:** Sichtprüfung der drei neuen Seiten (Übersicht, Verwaltung, Admin) und der geänderten Startseite auf Desktop und 375 px mit der Testinstanz; keine Überlappungen, kein seitlicher Überlauf (`document.documentElement.scrollWidth == innerWidth`).
- [ ] **Step 3:** Aufräumen: Testserver beenden, `/tmp/wh_test_*` löschen, `git status` zeigt nur beabsichtigte Dateien, echte `instance/rsvp.db` unverändert (Datum prüfen).
- [ ] **Step 4:** Dem Nutzer berichten und fragen, ob gepusht werden soll; Server-Schritte nennen: `git pull origin main`, `docker compose up -d --build` (die neue Tabelle entsteht beim Start durch `init-db`).
