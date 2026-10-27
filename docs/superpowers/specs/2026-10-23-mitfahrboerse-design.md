# Mitfahrbörse für Freitagabend – Design

Stand: 2026-10-23. Status: Entwurf im Chat freigegeben ("Passt"), Spec zur Durchsicht.

## Ziel

Gäste, die am Freitag (04.12.2026, ab 17 Uhr) zur Krähenlochhütte in Gutmadingen fahren,
können eine Fahrt **anbieten** oder eine **Mitfahrt suchen**, finden sich über Vorschläge
selbst und nehmen über vorbefüllte Links Kontakt auf, ohne dass das Brautpaar vermitteln muss.

**Erfolgskriterium:** Eine Person findet in unter 2 Minuten passende Einträge und kann per
WhatsApp, Anruf oder E-Mail Kontakt aufnehmen.

## Festlegungen aus der Abstimmung

- Freitag, Hin- und Rückfahrt. Nachtrag 2026-10-27: Fahrten gelten auch für Samstag (Ziel Kurgarten
  Bad Dürrheim). Jeder Eintrag hat genau einen Tag (`day`: `fri`/`sat`, Standard `fri`), Treffer gibt es
  nur innerhalb desselben Tages; `init-db` rüstet die Spalte in bestehenden Datenbanken nach.
- Kontaktdaten (Telefon/E-Mail) sind für alle Gäste mit Zugangscode sichtbar, hinter einem
  aufklappbaren "Kontakt anzeigen". Wer einträgt, willigt per Pflicht-Checkbox ein.
- Keine neuen Konten, keine externen Dienste, kein Mailversand durch den Server.
- Daten werden nach der Feier gelöscht, die Datenschutzseite wird ergänzt.

## Nicht enthalten

Mailversand durch den Server, Benutzerkonten, Karte/Geocoding/Entfernungsberechnung,
Chat, automatisches Ausblenden nach dem Freitag, JavaScript-Single-Page.
(Nach dem Fest: `flask purge-rides` oder `CARPOOL_ENABLED=0`.)

## Architektur

Server-gerenderte Flask-Seiten, neue SQLAlchemy-Tabelle, normale CSRF-geschützte Formulare,
kein JavaScript außer einer kleinen Komfortfunktion im Formular. Bestehende Konventionen
bleiben: Gate, Rate-Limiter, `clean_text`, Jinja-Autoescape, deutsche Texte.

Einheiten:

| Einheit | Aufgabe | Abhängigkeiten |
|---|---|---|
| `carpool.py` (neu) | Reine Logik ohne Flask/DB: Orts-Tokens, Telefon normalisieren und prüfen, Matching/Score, Kontakt-Links bauen | nur Standardbibliothek |
| `Ride` (Modell in `app.py`) | Persistenz | `db` |
| Routen in `app.py` | Übersicht, Anlegen, Verwaltung per Kennung, Admin, CLI | `carpool.py`, `Ride` |
| `templates/carpool.html`, `carpool_mine.html`, `admin_carpool.html` | Darstellung | Jinja-Globals |
| `static/styles.css` | Klassen `.ride-*` (Cache-Parameter `?v=17` → `?v=18` in `base.html`) | – |

`carpool.py` ist bewusst frei von Flask und DB, damit die Logik direkt getestet werden kann.

## Daten: Tabelle `ride`

| Feld | Typ | Regel |
|---|---|---|
| `id` | Integer, PK | |
| `token` | String(32), unique, index | `secrets.token_hex(16)`, geheimer Verwaltungslink |
| `kind` | String(5) | `offer` (Fahrer:in) oder `seek` (Mitfahrer:in) |
| `name` | String(60) | Pflicht, `clean_text`, Hinweis "Vorname reicht" |
| `origin` | String(80) | Pflicht, Startort und/oder PLZ, `clean_text` |
| `direction` | String(4) | `there` (Hinfahrt), `back` (Rückfahrt), `both` |
| `depart_time` | String(30) | optional, freier Text, z. B. "ca. 16:00" |
| `seats` | Integer | offer: angebotene freie Plätze 1–8; seek: Personenzahl 1–6 |
| `seats_taken` | Integer, default 0 | nur offer, 0 ≤ `seats_taken` ≤ `seats` |
| `phone` | String(40) | optional |
| `email` | String(120) | optional |
| `note` | String(200) | optional, `clean_text` |
| `consent` | Boolean | muss `True` sein |
| `active` | Boolean, default True | "Gefunden/geschlossen" setzt `False` |
| `created_at` | DateTime, server default now | |

Mindestens eines von `phone`/`email` ist Pflicht. E-Mail: bestehende Regex `valid_email`.
Telefon: nur Ziffern und `+ - ( ) / Leerzeichen` erlaubt, nach Entfernen dieser Zeichen 6–15 Ziffern.
Die Tabelle wird von `db.create_all()` (Container-Start via `init-db`, lokal via `python app.py`)
angelegt; keine Migration nötig.

## Seiten und Routen

Alle Routen liegen hinter dem Gate (bestehendes `before_request`). Ist `CARPOOL_ENABLED=0`,
antworten sie mit 404 und der Menüpunkt entfällt.

| Route | Methode | Zweck |
|---|---|---|
| `/mitfahrt` | GET | Übersicht + Formular. `?rolle=fahre` / `?rolle=suche` wählt die Rolle vor. |
| `/mitfahrt` | POST | Eintrag anlegen (6/Stunde/IP; es zählen nur Antworten mit Status < 400, per `deduct_when`, damit Tippfehler kein Kontingent verbrauchen). Erfolg: Redirect auf `/mitfahrt/mein/<token>`. Fehler: 400 mit Meldungen und ausgefülltem Formular. |
| `/mitfahrt/mein/<token>` | GET | "Dein Eintrag": Zusammenfassung, passende Treffer, Aktionen. Unbekannte Kennung: 404. Merkt die Kennung in `session["ride_tokens"]` (max. 20). |
| `/mitfahrt/mein/<token>/<aktion>` | POST | `platz-vergeben`, `platz-frei` (nur offer), `schliessen`, `oeffnen`, `loeschen` (30/Stunde/IP). Danach Redirect auf die Verwaltungsseite, bei `loeschen` auf `/mitfahrt`. |
| `/admin/mitfahrt` | GET | Liste aller Einträge inkl. geschlossener, mit Kontaktdaten. |
| `/admin/mitfahrt/loeschen` | POST | Einzelnen Eintrag löschen. |

**Übersicht:** Kopf mit Ziel und Zeit, zwei Spalten (🚗 Fahrer:innen, 🙋 Mitfahrer:innen) mit
aktiven Einträgen, neueste zuerst. Karte: Name, Startort, Richtung, Zeit, bei Fahrern
"x von y Plätzen frei" bzw. Badge "Voll", Notiz, Badge "Dein Eintrag" bei Einträgen aus der
Session, aufklappbares "Kontakt anzeigen" mit Buttons WhatsApp / Anrufen / E-Mail (nur die
vorhandenen) und dem Klartext der Kontaktdaten. Darunter das Formular: zwei große
Rollenkarten (Radio), Name, Startort/PLZ, Richtung, Abfahrtszeit, Plätze bzw. Personen
(Beschriftung wechselt per kleinem Script mit der Rolle; ohne Script steht ein neutraler
Text), Telefon, E-Mail, Notiz, Einwilligungs-Checkbox, verstecktes Honeypot-Feld `website`.

**Verwaltungsseite:** Zusammenfassung, Hinweis "Speichere diesen Link, um den Eintrag später zu
ändern" mit der vollständigen URL, Abschnitt "Passende Treffer" (Match-Liste mit Kontaktbuttons),
darunter "Weitere Möglichkeiten", dann die Aktionsbuttons. Bei geschlossenem Eintrag stehen
nur "Wieder öffnen" und "Löschen" zur Verfügung.

## Match-Logik (`carpool.py`)

Kandidaten sind aktive Einträge der **Gegenrolle**, deren Richtung sich überschneidet
(`both` passt zu allem; `there` passt nicht zu `back`) und, wenn eine Seite `offer` ist,
bei denen `seats - seats_taken` ≥ Personenzahl des `seek`-Eintrags.

- **Orts-Tokens** eines Textes: in Kleinbuchstaben, Wörter aus Buchstaben/Ziffern mit ≥ 3
  Zeichen (Umlaute bleiben, `ß`→`ss`); zusätzlich für jede Zahl mit ≥ 3 Ziffern das Token
  `plz` + die ersten 3 Ziffern.
- **Score** = Anzahl gemeinsamer Tokens beider `origin`-Texte.
- **Sortierung:** Score absteigend, dann `created_at` aufsteigend.
- **Ergebnis:** `matches` (Score > 0, mit Badge "Match") und `others` (Score = 0, Kandidaten
  trotzdem gültig). Es ist ein Vorschlag; Entfernung wird nicht berechnet.

Eigene Einträge und der Eintrag selbst sind nie Kandidaten.

## Kontakt-Links (`carpool.py`)

- Telefon wird zu Ziffern normalisiert: führendes `+` entfernen; führendes `00` entfernen;
  führende einzelne `0` → `49` + Rest (Annahme: Deutschland). Das Ergebnis ist `digits`.
- WhatsApp: `https://wa.me/<digits>?text=<urlencode(Nachricht)>`
- Anrufen: `tel:+<digits>`
- E-Mail: `mailto:<email>?subject=<urlencode>&body=<urlencode>`
- Nachrichtentext: bei Fahrer-Eintrag "Hallo {name}, ich habe dein Fahrtangebot für Freitag
  (Krähenlochhütte) gesehen. Hast du noch einen Platz für mich?", bei Such-Eintrag "Hallo {name},
  ich habe deine Mitfahr-Anfrage für Freitag (Krähenlochhütte) gesehen. Ich kann dich ab
  {origin} mitnehmen."
- Schemata sind fest (`https`, `tel`, `mailto`), Werte stammen nur aus validierten Feldern und
  werden mit `urllib.parse.quote` kodiert. Jinja escaped zusätzlich im Attribut.

## Datenschutz und Missbrauchsschutz

- Pflicht-Checkbox: "Ich bin einverstanden, dass meine Angaben inklusive Kontaktdaten für andere
  Gäste dieser Seite sichtbar sind. Ich kann den Eintrag jederzeit löschen."
- `privacy.html` bekommt einen Abschnitt zur Mitfahrbörse (Zweck, Sichtbarkeit nur hinter dem
  Zugangscode, Löschung über den Eintrag oder durch das Brautpaar, spätestens nach der Feier).
- Kontaktdaten erscheinen nur auf Seiten hinter dem Gate.
- Eingaben: `clean_text`, keine HTML-Speicherung von Escapes, Jinja-Autoescape beim Anzeigen,
  keine Verwendung unvalidierter Werte in Links.
- Honeypot-Feld `website`: ist es ausgefüllt, wird nichts gespeichert, die Antwort sieht wie
  Erfolg aus (Redirect auf `/mitfahrt`).
- Rate-Limits wie oben, CSRF auf allen POSTs.
- Fremde Kennungen sind nicht erratbar (128 Bit Zufall). Einträge anderer lassen sich über die
  Übersicht nicht verändern, da Aktionen nur über die Kennung laufen.
- Admin: `/admin/mitfahrt` (Login wie bisher) zum Ansehen und Löschen; Link im Dashboard-Kopf.
- CLI `flask purge-rides [--yes]`: ohne `--yes` nur Anzahl anzeigen, mit `--yes` alle löschen.

## Konfiguration

`CARPOOL_ENABLED` (Standard `1`). Bei `0`: Routen 404, Menüpunkt und Hütten-Link entfallen.
Dafür stellt der Context-Processor `carpool_enabled` bereit.

## Einbindung in die bestehende Seite

- Menüpunkt "Mitfahrt" in `base.html` (zwischen FAQ und Fotos), nur bei `carpool_enabled`.
- In der Freitags-Karte "Krähenlochhütte" der Zeitleiste ein Link "Fahrgemeinschaft bilden →"
  zu `/mitfahrt`.
- README: Abschnitt Mitfahrbörse, Variable `CARPOOL_ENABLED`, Befehl `purge-rides`.

## Tests

Erweiterung von `tests/run_tests.py` (E2E, temporäre DB) plus direkte Unit-Tests für
`carpool.py` (reine Funktionen, kein Server nötig), zusammen ca. 25–30 Prüfungen:

1. **Orts-Tokens/Score:** Gleichheit, Teilwort ("Villingen" vs. "Villingen-Schwenningen"),
   PLZ-Vorwahl, Umlaute, kein Match.
2. **Match-Filter:** Gegenrolle, Richtung (`there` vs. `back`, `both`), freie Plätze, inaktive
   Einträge, Sortierung.
3. **Telefon:** Normalisierung (`0176…`, `+49 176…`, `0049…`), Ablehnung zu kurzer/ungültiger Werte.
4. **Kontakt-Links:** korrekte Schemata, Sonderzeichen/Anführungszeichen im Namen sauber kodiert.
5. **Zugriff:** `/mitfahrt` ohne Gate → Gate; mit Gate 200; `CARPOOL_ENABLED=0` → 404.
6. **Anlegen:** Erfolg mit E-Mail, mit Telefon; Fehler ohne Einwilligung, ohne Kontakt, mit
   ungültiger E-Mail/Telefon, Pflichtfelder, Plätze außerhalb des Bereichs; Honeypot speichert nichts.
7. **Verwaltung:** gültige Kennung → Seite mit Treffern; fremde/ungültige Kennung → 404;
   Platz vergeben/frei respektiert Grenzen; schließen/öffnen/löschen; Eintrag taucht nach
   Schließen nicht mehr in Übersicht und Treffern auf.
8. **Darstellung:** Sonderzeichen werden einfach escaped, keine Skript-Einschleusung in
   `href`/Text, "Dein Eintrag"-Badge aus der Session.
9. **Admin:** ohne Login geschützt, Liste zeigt auch geschlossene, Löschen funktioniert.
10. **Rate-Limit:** in einer eigenen Testphase mit frischem Server: 6 erfolgreiche Einträge,
    der 7. → 429; fehlgeschlagene Eingaben (400) verbrauchen kein Kontingent. Die übrigen
    Tests legen Match-Testdaten direkt in der Test-DB an und bleiben unter dem Limit.
11. **CLI:** `purge-rides` ohne `--yes` löscht nichts, mit `--yes` alles.
12. **Navigation:** Menüpunkt und Hütten-Link vorhanden bzw. bei `CARPOOL_ENABLED=0` weg.

## Annahmen und offene Punkte

- Rufnummern ohne Ländervorwahl werden als deutsche Nummern behandelt (`0…` → `49…`).
- Die Seite wird nach dem 04.12. nicht automatisch ausgeblendet; Abschalten bzw. Löschen ist ein
  bewusster Schritt (`CARPOOL_ENABLED=0`, `flask purge-rides --yes`).
- Keine weiteren offenen Fragen.
