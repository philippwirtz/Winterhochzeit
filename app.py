from datetime import datetime, timezone
import os
import csv
from io import StringIO, BytesIO
from dataclasses import dataclass
import re
from functools import wraps
from dotenv import load_dotenv

import smtplib
from email.message import EmailMessage
from markupsafe import escape

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_basicauth import BasicAuth
from sqlalchemy.sql import func, or_, desc
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix

import mimetypes
mimetypes.add_type('font/woff2', '.woff2')
mimetypes.add_type('font/woff', '.woff')
# ---------- Configuration ----------
load_dotenv()
EVENT_TITLE = os.getenv("EVENT_TITLE", "Winterhochzeit Jasmin & Philipp")
# Use local time string "YYYY-MM-DD HH:MM" (24h). We'll parse and treat as naive local.
EVENT_DATETIME_STR = os.getenv("EVENT_DATETIME", "2026-12-05 14:00")
EVENT_LOCATION_NAME = os.getenv("EVENT_LOCATION_NAME", "Kurgarten Bad Dürrheim")
EVENT_LOCATION_ADDRESS = os.getenv("EVENT_LOCATION_ADDRESS", "Luisenstraße 16, 78073 Bad Dürrheim")
RSVP_DEADLINE_STR = os.getenv("RSVP_DEADLINE", "2026-04-01")

# ---------- Flask app ----------
IS_DEV = os.getenv("FLASK_DEBUG", "0") == "1" or os.getenv("ENV", "").lower() == "development"
FORCE_HTTPS = os.getenv("FORCE_HTTPS", "0" if IS_DEV else "1") == "1"
app = Flask(__name__, static_folder="static", template_folder="templates")

# Stelle sicher, dass die DB IMMER an einem existierenden, beschreibbaren Ort liegt
# -> Flask "instance"-Ordner (standard: <projekt>/instance)
os.makedirs(app.instance_path, exist_ok=True)

db_file = os.getenv("DATABASE_FILE", "rsvp.db")
db_abs_path = os.path.join(app.instance_path, db_file)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{db_abs_path}"  # absolute, OS-sicher
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.logger.info(f"instance_path = {app.instance_path}")
app.logger.info(f"DB path      = {db_abs_path}")
app.logger.info(f"SQLA URI     = {app.config['SQLALCHEMY_DATABASE_URI']}")


# app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///rsvp.db")
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Grundkonfiguration
app.config.update(
    DEBUG=IS_DEV is True,
    ENV="development" if IS_DEV else "production",
    SECRET_KEY=os.getenv("SECRET_KEY"),

    # nur in Produktion strikt
    SESSION_COOKIE_SECURE=not IS_DEV,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=512 * 1024,
    PREFERRED_URL_SCHEME="https" if not IS_DEV else "http",
)


EVENT_TITLE = os.getenv("EVENT_TITLE")
ADMIN_USER  = os.getenv("ADMIN_USER", "admin")  # z.B. "admin"
ADMIN_PASS  = os.getenv("ADMIN_PASS", "changeme")  # z.B. langer zufälliger String
# ADMIN_KEY kannst du weiterverwenden, ist aber nach BasicAuth nicht mehr nötig

# Basic Auth für Admin
if ADMIN_USER and ADMIN_PASS:
    app.config["BASIC_AUTH_USERNAME"] = ADMIN_USER
    app.config["BASIC_AUTH_PASSWORD"] = ADMIN_PASS
    basic_auth = BasicAuth(app)
else:
    basic_auth = None  # fallback: kein Adminschutz (nicht empfohlen)
app.logger.info(f"ADMIN_USER: {repr(ADMIN_USER)}")
app.logger.info(f"ADMIN_PASS set: {bool(ADMIN_PASS)}")
app.logger.info(f"Using BasicAuth: {basic_auth is not None}")


# Security-Header / HTTPS / CSP
csp = {
    "default-src": "'self'",
    "img-src": "'self' data:",
    "style-src": "'self' 'unsafe-inline'",
    "script-src": "'self' 'unsafe-inline'",  # Countdown ist inline
    "frame-src": "https://www.openstreetmap.org",
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=FORCE_HTTPS,              # in Dev: kein HTTPS-Zwang
    strict_transport_security=FORCE_HTTPS # HSTS nur in Prod
)


# CSRF-Schutz (gilt global)
CSRFProtect(app)

# Rate-Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200/hour"])

# Reverse-proxy fix (useful on Vercel/Render/Heroku etc.)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

db = SQLAlchemy(app)

# ---------- Model ----------
class RSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    attendance = db.Column(db.String(10), nullable=False)  # "yes" or "no"
    guests = db.Column(db.Integer, nullable=False, default=1)
    notes = db.Column(db.String(500))
    song = db.Column(db.String(300))
    consent = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    attendance_days = db.Column(db.String(10), nullable=False, default="sat") # "fri"| "sat"|"both"
    contribution = db.Column(db.String(300)) # Salat/Kuchen etc.

# ---------- Helpers ----------
def parse_local_date(s: str) -> datetime:
    # Expects "YYYY-MM-DD" or "YYYY-MM-DD HH:MM"
    try:
        if " " in s:
            return datetime.strptime(s, "%Y-%m-%d %H:%M")
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        # fallback future date
        return datetime(2099, 1, 1, 0, 0)

def remaining(event_dt: datetime) -> dict:
    now = datetime.now()
    diff = event_dt - now
    if diff.total_seconds() <= 0:
        return {"days": 0, "hours": 0, "minutes": 0, "seconds": 0, "over": True}
    seconds = int(diff.total_seconds())
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return {"days": days, "hours": hours, "minutes": minutes, "seconds": secs, "over": False}

def valid_email(addr: str) -> bool:
    return re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", addr or "") is not None

def safe_csv_cell(v: str | None) -> str:
    if not v:
        return ""
    v = str(v)
    # Formula-Injection verhindern (= + - @ am Zeilenanfang)
    if v[0] in ("=", "+", "-", "@"):
        return "'" + v
    return v


EVENT_DT = parse_local_date(EVENT_DATETIME_STR)
RSVP_DEADLINE = parse_local_date(RSVP_DEADLINE_STR).date()

def send_rsvp_mail(entry: RSVP):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd  = os.getenv("SMTP_PASS")
    mail_from = os.getenv("MAIL_FROM", user or "robot@localhost")
    mail_to = os.getenv("MAIL_TO", "")

    if not host or not mail_to:
        # Kein Mail-Setup vorhanden → still überspringen
        return

    tos = [addr.strip() for addr in mail_to.split(",") if addr.strip()]
    msg = EmailMessage()
    msg["Subject"] = f"[RSVP] {entry.name} – {'Zusage' if entry.attendance=='yes' else 'Absage'}"
    msg["From"] = mail_from
    msg["To"] = ", ".join(tos)

    body = [
    f"Neue RSVP für {EVENT_TITLE}",
    "",
    f"Name: {entry.name}",
    f"E-Mail: {entry.email}",
    f"Status: {'Zusage' if entry.attendance=='yes' else 'Absage'}",
    f"Tage: {entry.attendance_days or '-'}",              # NEU
    f"Spende: {entry.contribution or '-'}",               # NEU
    f"Personen: {entry.guests}",
    f"Notizen: {entry.notes or '-'}",
    f"Zeitpunkt: {entry.created_at}",
]

    msg.set_content("\n".join(body))

    with smtplib.SMTP(host, port, timeout=10) as s:
        s.starttls()
        if user and pwd:
            s.login(user, pwd)
        s.send_message(msg)

def admin_protected(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if basic_auth is None:
            abort(403)  # Admin nicht konfiguriert
        if not basic_auth.authenticate():
            return basic_auth.challenge()
        return view(*args, **kwargs)
    return wrapper

# ---------- Routes ----------
@app.route("/")
def index():
    timeleft = remaining(EVENT_DT)
    return render_template("index.html",
                           event_title=EVENT_TITLE,
                           event_dt=EVENT_DT,
                           event_location_name=EVENT_LOCATION_NAME,
                           event_location_address=EVENT_LOCATION_ADDRESS,
                           timeleft=timeleft,
                           rsvp_deadline=RSVP_DEADLINE)

@app.route("/privacy")
def privacy():
    return render_template("privacy.html", event_title=EVENT_TITLE)

@app.route("/rsvp", methods=["POST"])
@limiter.limit("5/minute")
def submit_rsvp():
    # Eingaben härten & begrenzen
    name = escape((request.form.get("name") or "").strip())[:120]
    email = escape((request.form.get("email") or "").strip())[:200]
    attendance = (request.form.get("attendance") or "").strip()
    guests_raw = (request.form.get("guests") or "1").strip()
    notes = escape((request.form.get("notes") or "").strip())[:500]
    song = escape((request.form.get("song") or "").strip())[:300]  # falls später wieder im Formular
    consent = request.form.get("consent") == "on"
    attendance_days = (request.form.get("attendance_days") or "").strip()
    contribution = escape((request.form.get("contribution") or "").strip())[:300]

    errors = []
    if not name:
        errors.append("Bitte gib deinen Namen an.")
    if not email or not valid_email(email):
        errors.append("Bitte gib eine gültige E-Mail-Adresse an.")
    if attendance not in ("yes", "no"):
        errors.append("Bitte wähle, ob du kommen kannst.")
    valid_days = ("fri", "sat", "both")
    if attendance == "yes":
        if attendance_days not in valid_days:
            errors.append("Bitte wähle, für welche Tage du zusagst (Fr/Sa/Beide).")
    else:
    # bei Absage Tage ignorieren
        attendance_days = ""
        contribution = ""

    try:
        guests = int(guests_raw or 1)
        if guests < 1 or guests > 10:
            errors.append("Gästeanzahl muss zwischen 1 und 10 liegen.")
    except ValueError:
        errors.append("Ungültige Gästeanzahl.")
    if not consent:
        errors.append("Bitte bestätige die Datenschutzhinweise.")

    deadline_over = (datetime.now().date() > RSVP_DEADLINE)
    if deadline_over and attendance == "yes":
        errors.append("Die RSVP-Deadline ist vorbei. Bitte kontaktiere uns direkt.")

    if errors:
        return render_template("result.html", ok=False, messages=errors, event_title=EVENT_TITLE), 400

    entry = RSVP(
        name=name, email=email, attendance=attendance,
        guests=guests, notes=notes, song=song, consent=consent,
        attendance_days=attendance_days,
        contribution=contribution
    )

    db.session.add(entry)
    db.session.commit()

    try:
        send_rsvp_mail(entry)
    except Exception as e:
        # Optional: loggen, aber User nicht mit Fehler belasten
        app.logger.warning(f"Send mail failed: {e}")

    return redirect(url_for("thank_you", name=name))

    # return render_template("result.html", ok=True, messages=["Danke! Deine Rückmeldung wurde gespeichert."], event_title=EVENT_TITLE), 200

@app.route("/thank-you")
def thank_you():
    name = request.args.get("name", "")
    return render_template("thank_you.html", name=name, event_title=EVENT_TITLE)

# Optional: Gesamtzahl der eingeladenen Personen (für Response-Rate)
INVITED_TOTAL = int(os.getenv("INVITED_TOTAL", "0"))

@app.route("/admin")
@limiter.limit("10/minute")
@admin_protected
def admin_dashboard():
    # Auth (BasicAuth handled in @admin_protected)
    # --- Filter & Query-Params ---
    attendance = (request.args.get("attendance") or "").strip()   # "", "yes", "no"
    days       = (request.args.get("days") or "").strip()         # "", "fri","sat","both"
    q          = (request.args.get("q") or "").strip()
    order      = (request.args.get("order") or "created_desc").strip()
    page       = max(int(request.args.get("page", 1)), 1)
    per_page   = max(min(int(request.args.get("per_page", 25)), 200), 5)

    # --- Kennzahlen ---
    total      = db.session.query(RSVP).count()
    yes_count  = db.session.query(RSVP).filter(RSVP.attendance == "yes").count()
    no_count   = db.session.query(RSVP).filter(RSVP.attendance == "no").count()
    guests_yes = db.session.query(db.func.coalesce(db.func.sum(RSVP.guests), 0))\
                    .filter(RSVP.attendance == "yes").scalar() or 0

    fri_count  = db.session.query(RSVP).filter(RSVP.attendance=="yes", RSVP.attendance_days=="fri").count()
    sat_count  = db.session.query(RSVP).filter(RSVP.attendance=="yes", RSVP.attendance_days=="sat").count()
    both_count = db.session.query(RSVP).filter(RSVP.attendance=="yes", RSVP.attendance_days=="both").count()

    # --- Hauptliste mit Filtern ---
    query = RSVP.query

    if attendance in ("yes", "no"):
        query = query.filter(RSVP.attendance == attendance)

    if days in ("fri", "sat", "both"):
        query = query.filter(RSVP.attendance_days == days)

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(RSVP.name.ilike(like),
                RSVP.email.ilike(like),
                RSVP.notes.ilike(like),
                RSVP.contribution.ilike(like))
        )

    # Sortierung
    if order == "created_asc":
        query = query.order_by(RSVP.created_at.asc())
    elif order == "name_asc":
        query = query.order_by(RSVP.name.asc())
    elif order == "name_desc":
        query = query.order_by(RSVP.name.desc())
    else:  # "created_desc" default
        query = query.order_by(RSVP.created_at.desc())

    total_filtered = query.count()
    rsvps = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total_filtered + per_page - 1) // per_page

    return render_template(
        "admin_dashboard.html",
        event_title=EVENT_TITLE,
        # Kennzahlen
        total=total,
        yes_count=yes_count,
        no_count=no_count,
        guests_yes=guests_yes,
        fri_count=fri_count, sat_count=sat_count, both_count=both_count,
        # Liste
        rsvps=rsvps, total_filtered=total_filtered,
        attendance=attendance, days=days, q=q, order=order,
        page=page, pages=pages, per_page=per_page
    )

# --- Admin: Liste (optional; falls du sie noch nicht hast) ---
@app.route("/admin/rsvps")
@limiter.limit("10/minute")
@admin_protected
def admin_rsvps():
    
    attendance = (request.args.get("attendance") or "").strip()
    q = (request.args.get("q") or "").strip()
    page = max(int(request.args.get("page", 1)), 1)
    per_page = 25

    query = RSVP.query.order_by(desc(RSVP.created_at))
    if attendance in ("yes", "no"):
        query = query.filter(RSVP.attendance == attendance)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(RSVP.name.ilike(like),
                                 RSVP.email.ilike(like),
                                 RSVP.notes.ilike(like)))

    total = query.count()
    rsvps = query.offset((page - 1)*per_page).limit(per_page).all()
    pages = (total + per_page - 1)//per_page

    return render_template("admin_rsvps.html",
                           rsvps=rsvps, total=total, page=page, pages=pages,
                           per_page=per_page, attendance=attendance, q=q,
                           event_title=EVENT_TITLE)

# --- Admin: Update ---
@app.route("/admin/rsvps/update", methods=["POST"])
@limiter.limit("10/minute")
@admin_protected
def admin_rsvps_update():
    
    rid = request.form.get("id")
    if not rid:
        abort(400)
    r = RSVP.query.get(int(rid))
    if not r:
        abort(404)

    # nur ausgewählte Felder bearbeitbar
    attendance = (request.form.get("attendance") or r.attendance).strip()
    if attendance not in ("yes","no"):
        attendance = r.attendance

    try:
        guests = int(request.form.get("guests", r.guests))
        guests = 1 if guests < 1 else (10 if guests > 10 else guests)
    except ValueError:
        guests = r.guests

    notes = escape((request.form.get("notes") or r.notes or "").strip())[:500]
    # NEU: Tage & Spende übernehmen
    attendance_days = (request.form.get("attendance_days") or r.attendance_days or "").strip()
    if attendance_days not in ("fri", "sat", "both", ""):
        attendance_days = r.attendance_days

    contribution = escape((request.form.get("contribution") or r.contribution or "").strip())[:300]

    r.attendance = attendance
    r.attendance_days = attendance_days
    r.guests = guests
    r.notes = notes
    r.contribution = contribution
    db.session.commit()
    return redirect(url_for("admin_rsvps"))

# --- Admin: Delete ---
@app.route("/admin/rsvps/delete", methods=["POST"])
@limiter.limit("10/minute")
@admin_protected
def admin_rsvps_delete():

    rid = request.form.get("id")
    if not rid:
        abort(400)
    r = RSVP.query.get(int(rid))
    if not r:
        abort(404)

    db.session.delete(r)
    db.session.commit()
    return redirect(url_for("admin_rsvps"))


@app.route("/admin/export.csv")
@limiter.limit("5/minute")
@admin_protected
def export_csv():

    rows = RSVP.query.order_by(RSVP.created_at.desc()).all()

    import io
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["Datum", "Name", "E-Mail", "Status", "Tage", "Personen", "Spende", "Notizen"])
    for r in rows:
        writer.writerow([
        r.created_at.strftime("%d.%m.%Y %H:%M"),
        safe_csv_cell(r.name),
        safe_csv_cell(r.email),
        "Zusage" if r.attendance == "yes" else "Absage",
        r.attendance_days or "",
        r.guests or 1,
        safe_csv_cell(r.contribution or ""),
        safe_csv_cell(r.notes or ""),
    ])


    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = 'attachment; filename="rsvps.csv"'
    return resp

@app.route("/event.ics")
def event_ics():
    # Start/Ende grob – passe es bei Bedarf an
    start = EVENT_DT           # naive lokale Zeit
    end = EVENT_DT.replace(hour=EVENT_DT.hour + 4 if EVENT_DT.hour <= 20 else EVENT_DT.hour)  # +4h als Beispiel

    def ics_dt(dt: datetime) -> str:
        # ical ohne TZ: lokale Zeit im Format YYYYMMDDTHHMMSS
        return dt.strftime("%Y%m%dT%H%M%S")

    uid = f"event-{EVENT_DT.strftime('%Y%m%dT%H%M%S')}@winterhochzeit.local"

    ics = "\r\n".join([
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Winterhochzeit//RSVP//DE",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{ics_dt(datetime.now())}",
        f"DTSTART:{ics_dt(start)}",
        f"DTEND:{ics_dt(end)}",
        f"SUMMARY:{EVENT_TITLE}",
        f"LOCATION:{EVENT_LOCATION_NAME}, {EVENT_LOCATION_ADDRESS}",
        "END:VEVENT",
        "END:VCALENDAR",
        ""
    ])

    resp = make_response(ics)
    resp.headers["Content-Type"] = "text/calendar; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="event.ics"'
    return resp


@app.errorhandler(403)
def forbidden(e):
    return render_template("result.html", ok=False, messages=["Nicht erlaubt."], event_title=EVENT_TITLE), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("result.html", ok=False, messages=["Seite nicht gefunden."], event_title=EVENT_TITLE), 404

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Datenbank initialisiert.")

@app.cli.command("alter-db-add-days-contrib")
def alter_db_add_days_contrib():
    """Einmalige, einfache Migration für bestehende SQLite-DB."""
    with app.app_context():
        # prüfen & hinzufügen (SQLite: ALTER TABLE ADD COLUMN ist idempotent genug, wenn wir try/except nutzen)
        try:
            db.session.execute(text("ALTER TABLE rsvp ADD COLUMN attendance_days VARCHAR(10) NOT NULL DEFAULT 'sat'"))
        except Exception as e:
            app.logger.info(f"attendance_days evtl. schon vorhanden: {e}")
        try:
            db.session.execute(text("ALTER TABLE rsvp ADD COLUMN contribution VARCHAR(300)"))
        except Exception as e:
            app.logger.info(f"contribution evtl. schon vorhanden: {e}")
        db.session.commit()
        print("Migration abgeschlossen.")


@app.context_processor
def inject_now():
    # stellt in allen Templates die Funktion now() bereit
    return {"now": datetime.now}

@app.errorhandler(429)  # Too Many Requests
def ratelimit_handler(e):
    return render_template("result.html", ok=False,
                           messages=["Zu viele Anfragen. Bitte versuche es gleich erneut."],
                           event_title=EVENT_TITLE), 429

@app.errorhandler(CSRFError)
def handle_csrf(e):
    return render_template("result.html", ok=False,
                           messages=["Ungültiges oder fehlendes CSRF-Token."],
                           event_title=EVENT_TITLE), 403


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG","0")=="1")
