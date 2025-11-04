# Winterhochzeit – Python-only Event-Seite (Flask)

**Keine JavaScript-Abhängigkeit nötig.** Countdown, Formularvalidierung und Speicherung passieren serverseitig.

## Schnellstart

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=app.py  # Windows: set FLASK_APP=app.py
python app.py
# Öffnen: http://127.0.0.1:5000
```

## Konfiguration (Umgebungsvariablen)

- `EVENT_TITLE` (Standard: "Winterhochzeit")
- `EVENT_DATETIME` – Format `YYYY-MM-DD HH:MM` (Standard: `2025-12-20 15:00`)
- `EVENT_LOCATION_NAME` / `EVENT_LOCATION_ADDRESS`
- `RSVP_DEADLINE` – Format `YYYY-MM-DD` (Standard: `2025-11-15`)
- `ADMIN_KEY` – für CSV-Export `GET /admin/export.csv?key=<ADMIN_KEY>`
- `SECRET_KEY` – Flask-Session/CSRF (ändere für Produktion)
- `DATABASE_URL` – optional (z. B. `sqlite:///rsvp.db`)

## Datenbank

```bash
flask init-db
```

## Deployment

- **Docker**: siehe `Dockerfile` unten.
- **Render/Fly/Heroku/railway**: setze Umgebungsvariablen und starte `python app.py`.
- **NGINX/Apache**: Nutze Gunicorn/Uvicorn + Reverse Proxy.

## DSGVO

- Consent-Checkbox ist verpflichtend.
- Datenlöschung nach dem Event manuell (z. B. SQL oder CSV Export + DB löschen).
