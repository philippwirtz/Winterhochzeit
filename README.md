# Winterhochzeit – Event-Website (Flask)

Website für die Winterhochzeit von Jasmin & Philipp (05.12.2026, Bad Dürrheim): Infos, Ablauf,
Karten (Kurgarten, Krähenlochhütte, Parkplatz), Schlafmöglichkeiten, FAQ, RSVP-Formular,
Foto-Seite mit QR-Code und ein Admin-Bereich zur Auswertung der Antworten.

- **Zugangscode (Gate):** Die ganze Seite ist hinter einem gemeinsamen Code für alle Gäste.
- **RSVP:** Zu-/Absage, Tage (Fr/Sa/beide), Essenswunsch, Mitbringsel. Nach Ablauf von
  `RSVP_DEADLINE` wird das Formular ausgeblendet und serverseitig gesperrt.
- **Admin-Bereich** unter `/admin` (Login mit Benutzername/Passwort): Statistik, Filter, Suche,
  Bearbeiten, Löschen, CSV-Export.
- **Fotos** unter `/fotos`: zeigt "folgt bald", bis `PHOTOS_URL` gesetzt ist; danach Link + QR-Code.
- **Mail-Benachrichtigung** bei jeder neuen Antwort (optional, über SMTP).

## Schnellstart (lokal)

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

`.env` im Projektordner anlegen (wird nicht ins Git übernommen). Minimal:

```
SECRET_KEY=irgendein-langer-zufaelliger-string
FLASK_DEBUG=1
GATE_ENABLED=0
ADMIN_USER=admin
ADMIN_PASS=ein-sicheres-passwort
```

```bash
python app.py                      # http://127.0.0.1:5000
```

`FLASK_DEBUG=1` aktiviert Auto-Reload und erlaubt Cookies über http. Ohne Debug-Modus
setzt die App Cookies nur über https (Produktion).

## Konfiguration (Umgebungsvariablen / `.env`)

| Variable | Bedeutung | Standard |
|---|---|---|
| `SECRET_KEY` | Signiert Sessions und CSRF-Token. **Pflicht**, die App startet sonst nicht. | – |
| `ADMIN_USER` / `ADMIN_PASS` | Zugang zum Admin-Bereich. **Unbedingt setzen**, sonst gilt `admin` / `changeme`. | `admin` / `changeme` |
| `GATE_ENABLED` | `1` = Zugangscode für die ganze Seite, `0` = aus | `1` |
| `ACCESS_CODE` | Gemeinsamer Code für alle Gäste. Bei aktivem Gate nötig, sonst kommt niemand hinein. | leer |
| `EVENT_TITLE` | Titel der Seite | `Winterhochzeit Jasmin & Philipp` |
| `EVENT_DATETIME` | Zeitpunkt der Feier (`YYYY-MM-DD HH:MM`), Basis für den Countdown | `2026-12-05 14:00` |
| `FRIDAY_START` / `SATURDAY_START` | Beginn Freitag/Samstag (`YYYY-MM-DD HH:MM`) | `2026-12-04 17:00` / `2026-12-05 10:30` |
| `EVENT_LOCATION_NAME` / `EVENT_LOCATION_ADDRESS` | Hauptlocation (Anzeige und Kalenderdatei) | Kurgarten Bad Dürrheim |
| `RSVP_DEADLINE` | Letzter RSVP-Tag (`YYYY-MM-DD`), danach ist das Formular gesperrt | `2026-04-01` |
| `PHOTOS_URL` | Link zur Foto-Galerie; leer = "folgt bald", gesetzt = Link + QR-Code | leer |
| `CARPOOL_ENABLED` | `1` = Mitfahrbörse (`/mitfahrt`) an, `0` = aus (Seiten 404, Menüpunkt und Link entfallen) | `1` |
| `CARPOOL_RATE_LIMIT` | Limit für neue Mitfahr-Einträge pro IP. Nur erfolgreich angelegte Einträge zählen. | `6/hour` |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_USE_SSL` | Mailserver für Benachrichtigungen. Ohne `SMTP_HOST` oder `MAIL_TO` wird keine Mail gesendet. | Port `587` |
| `MAIL_FROM` / `MAIL_TO` | Absender / Empfänger (mehrere, kommagetrennt) | – |
| `DATABASE_URL` | Datenbank-URL | `sqlite:///instance/rsvp.db` |
| `DATABASE_FILE` | Dateiname der SQLite-DB im `instance/`-Ordner | `rsvp.db` |
| `FORCE_HTTPS` | Weiterleitung auf https | `1` (lokal im Debug `0`) |
| `FLASK_DEBUG` / `ENV` | `FLASK_DEBUG=1` oder `ENV=development` schaltet auf Entwicklungs-Modus | aus |
| `PORT` | Port für `python app.py` | `5000` |

## Admin-Bereich

- Login: `/admin/login` (Session-Cookie; "Angemeldet bleiben" = 30 Tage, sonst 8 Stunden).
  Falls das Gate aktiv ist, braucht man zuerst den Zugangscode.
- Dashboard: `/admin` (Statistik, Filter nach Status/Tage/Essen, Suche, Inline-Bearbeiten, Löschen).
- CSV-Export: `/admin/export.csv` (Trennzeichen `;`, deutsche Beschriftungen).
- Passwortversuche sind begrenzt (10 pro Minute und IP), alle Formulare sind CSRF-geschützt.

## Mitfahrbörse (Freitagabend)

Unter `/mitfahrt` (Menüpunkt "Mitfahrt", Link in der Freitags-Karte der Zeitleiste) bieten Gäste
eine Fahrt zur Krähenlochhütte an oder suchen eine Mitfahrt.

- **Eintrag:** Rolle (🚗 Ich fahre / 🙋 Ich suche), Vorname, Startort/PLZ, Hin-/Rückfahrt,
  optional Abfahrtszeit, freie Plätze bzw. Personenzahl, Telefon und/oder E-Mail, Notiz.
  Pflicht-Checkbox: Kontaktdaten sind für alle Gäste mit Zugangscode sichtbar.
- **Verwaltung ohne Konto:** Nach dem Eintragen gibt es einen privaten Link
  (`/mitfahrt/mein/<Kennung>`). Dort stehen passende Treffer (Match nach Orts-Wörtern/PLZ-Vorwahl,
  Richtung und freien Plätzen), "Platz vergeben", "Gefunden, Eintrag schließen" und "Löschen".
- **Kontakt:** hinter "Kontakt anzeigen" mit vorbefüllten Links für WhatsApp, Anruf und E-Mail.
  Der Server verschickt keine Mails.
- **Admin:** `/admin/mitfahrt` listet alle Einträge (auch geschlossene) mit Löschen-Button.
- **Nach der Feier:** `flask --app app.py purge-rides` zeigt die Anzahl, mit `--yes` werden alle
  Einträge gelöscht. Alternativ `CARPOOL_ENABLED=0` setzen, um die Seite abzuschalten.
- Die Tabelle `ride` wird beim Start automatisch angelegt (`init-db`), eine Migration ist nicht nötig.

## Betrieb (Docker + Caddy)

Auf dem Server läuft `docker-compose.yml` mit der App (Gunicorn, Port 8000) und Caddy als
Reverse-Proxy mit automatischem HTTPS. Die Konfiguration liegt in der `.env` auf dem Server,
die RSVP-Datenbank im Docker-Volume `app_instance` (bleibt bei Updates erhalten).

**Update einspielen:**

```bash
git pull origin main
docker compose up -d --build
```

- Änderungen an `app.py` oder `requirements.txt` brauchen den Rebuild (`--build`).
- `templates/` und `static/` sind als Volumes eingebunden: reine Template-/CSS-Änderungen
  sind nach `git pull` sofort aktiv (ggf. im Browser hart neu laden).
- Logs ansehen: `docker compose logs -f app`

## Wartung und Datenbank

```bash
flask --app app.py init-db                    # Tabellen anlegen (läuft beim Container-Start automatisch)
flask --app app.py test-mail                  # Testmail senden, prüft die SMTP-Konfiguration
flask --app app.py unescape-db --dry-run      # Altdaten prüfen (siehe unten)
flask --app app.py unescape-db                # Altdaten einmalig bereinigen
flask --app app.py purge-rides [--yes]        # Mitfahrbörse nach der Feier leeren
```

Im Container: `docker compose exec app flask --app app.py <befehl>`.

Einmalige Migrationen für sehr alte Datenbanken: `alter-db-add-days-contrib`, `alter-db-add-meal`.

**`unescape-db`:** Frühere Versionen haben Eingaben vor dem Speichern HTML-escaped, dadurch
erschienen Sonderzeichen (`&`, `'`) im Dashboard und im CSV als `&amp;` bzw. `&#39;`. Seit
der Umstellung wird nur noch beim Anzeigen escaped. Der Befehl wandelt vorhandene Einträge
einmalig zurück. Erst `--dry-run`, dann ohne Option. Ein zweiter Lauf wird verhindert
(Marker-Datei neben der DB), da er absichtlich eingegebene `&amp;` verfälschen würde.

## Tests

```bash
python tests/run_tests.py
```

Startet die App selbst auf Port 5100 mit temporärer Datenbank, Testzugangsdaten und
deaktiviertem Mailversand (die echte `.env` und die echte Datenbank werden nicht benutzt)
und prüft per HTTP u. a. Gate, Admin-Login (falsches Passwort, CSRF, Open-Redirect,
Rate-Limit), Dashboard und Filter, Bearbeiten/Löschen, deutschen CSV-Export,
Sonderzeichen und Script-Einschleusung, den Bereinigungsbefehl, die Mitfahrbörse
(Logik, Anlegen, Verwaltung, Admin, Rate-Limit) sowie das Verhalten bei offener und bei
abgelaufener RSVP-Frist. Läuft ohne zusätzliche Pakete aus
`requirements.txt` und endet mit Exit-Code 0 bei Erfolg.

## DSGVO

- Die Einwilligungs-Checkbox im Formular ist Pflicht, Datenschutzhinweise unter `/privacy`.
- Gespeichert werden nur Angaben, die für die Organisation nötig sind (Name, E-Mail, Zu-/Absage,
  Tage, Essen, Mitbringsel, Notizen).
- Löschung nach dem Event: Daten vorher per CSV-Export sichern, danach die Datenbank bzw. das
  Docker-Volume `app_instance` löschen.

## Projektstruktur

```
app.py            Flask-App (Routen, Modelle, Admin, CLI-Befehle)
carpool.py        Reine Logik der Mitfahrbörse (Matching, Telefon, Kontakt-Links, Validierung)
templates/        Jinja-Templates (index, gate, fotos, admin_*, ...)
static/           CSS, Schriften, Bilder
tests/            End-to-End-Tests (run_tests.py)
Dockerfile        Image für die App (Gunicorn)
docker-compose.yml, Caddyfile   Deployment mit Reverse-Proxy und HTTPS
```
