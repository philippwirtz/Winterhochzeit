"""Reine Logik der Mitfahrbörse: kein Flask, keine Datenbank.

Ride-Objekte werden nur über Attribute gelesen (id, kind, name, origin, day, direction,
seats, seats_taken, phone, email, active, created_at), damit die Funktionen ohne
Datenbank testbar sind.
"""
import re
from collections.abc import Callable, Iterable, Mapping
from urllib.parse import quote

DAY_LABELS = {"fri": "Freitag", "sat": "Samstag"}
DAY_DEST = {"fri": "Krähenlochhütte", "sat": "Kurgarten Bad Dürrheim"}
KIND_LABELS = {"offer": "Fahrer:in", "seek": "Mitfahrer:in"}
DIRECTION_LABELS = {"there": "Hinfahrt", "back": "Rückfahrt", "both": "Hin und zurück"}
SEATS_MAX = {"offer": 8, "seek": 6}

_PHONE_ALLOWED = re.compile(r"[0-9+\-()/ ]+")


def clean_text(value: str | None, max_len: int) -> str:
    # Einzeilig, Whitespace normalisiert. Kein HTML-Escaping: das übernimmt Jinja beim Rendern.
    return " ".join((value or "").split())[:max_len]


def place_tokens(text: str) -> set[str]:
    """Wörter (>= 3 Zeichen, mit Buchstabe) plus 'plz' + erste 3 Ziffern jeder Zahl mit >= 3 Ziffern."""
    text = (text or "").lower().replace("ß", "ss")
    tokens = {w for w in re.findall(r"[^\W_]+", text) if len(w) >= 3 and any(ch.isalpha() for ch in w)}
    tokens.update("plz" + n[:3] for n in re.findall(r"\d+", text) if len(n) >= 3)
    return tokens


def normalize_phone(raw: str) -> str | None:
    """Ziffernstring mit Ländervorwahl (ohne '+'), None bei ungültiger Eingabe. Annahme: 0... = Deutschland."""
    raw = (raw or "").strip()
    if not raw or not _PHONE_ALLOWED.fullmatch(raw):
        return None
    digits = re.sub(r"\D", "", raw)
    if not 6 <= len(digits) <= 15:
        return None
    if not raw.startswith("+"):
        if digits.startswith("00"):
            digits = digits[2:]
        elif digits.startswith("0"):
            digits = "49" + digits[1:]
    if digits.startswith("490"):
        digits = "49" + digits[3:]
    return digits


def directions_overlap(a: str, b: str) -> bool:
    return a == "both" or b == "both" or a == b


def match_score(origin_a: str, origin_b: str) -> int:
    return len(place_tokens(origin_a) & place_tokens(origin_b))


def find_matches(ride, candidates: Iterable) -> tuple[list, list]:
    """(matches, others): passende Einträge der Gegenrolle, Score > 0 bzw. = 0."""
    scored = []
    for c in candidates:
        if c.id == ride.id or not c.active or c.kind == ride.kind or c.day != ride.day:
            continue
        if not directions_overlap(ride.direction, c.direction):
            continue
        offer, seek = (ride, c) if ride.kind == "offer" else (c, ride)
        if offer.seats - offer.seats_taken < seek.seats:
            continue
        scored.append((match_score(ride.origin, c.origin), c))
    scored.sort(key=lambda sc: (-sc[0], sc[1].created_at))
    return [c for s, c in scored if s > 0], [c for s, c in scored if s == 0]


def day_trip(ride) -> str:
    """Tag und Ziel eines Eintrags, z. B. 'Samstag (Kurgarten Bad Dürrheim)'."""
    return f"{DAY_LABELS[ride.day]} ({DAY_DEST[ride.day]})"


def message_text(ride) -> str:
    if ride.kind == "offer":
        return (f"Hallo {ride.name}, ich habe dein Fahrtangebot für {day_trip(ride)} gesehen. "
                "Hast du noch einen Platz für mich?")
    return (f"Hallo {ride.name}, ich habe deine Mitfahr-Anfrage für {day_trip(ride)} gesehen. "
            f"Ich kann dich ab {ride.origin} mitnehmen.")


def contact_links(ride) -> list[dict[str, str]]:
    links = []
    text = quote(message_text(ride), safe="")
    digits = normalize_phone(ride.phone) if ride.phone else None
    if digits:
        links.append({"kind": "whatsapp", "label": "WhatsApp", "href": f"https://wa.me/{digits}?text={text}"})
        links.append({"kind": "tel", "label": "Anrufen", "href": f"tel:+{digits}"})
    if ride.email:
        subject = quote(f"Fahrgemeinschaft {day_trip(ride)}", safe="")
        links.append({"kind": "mail", "label": "E-Mail",
                      "href": f"mailto:{quote(ride.email, safe='@+')}?subject={subject}&body={text}"})
    return links


def validate_ride_input(form: Mapping[str, str], valid_email: Callable[[str], bool]) -> tuple[dict, list[str]]:
    def get(key: str) -> str:
        return form.get(key) or ""

    cleaned = {
        "kind": get("kind").strip(),
        "name": clean_text(get("name"), 60),
        "origin": clean_text(get("origin"), 80),
        "day": get("day").strip(),
        "direction": get("direction").strip(),
        "depart_time": clean_text(get("depart_time"), 30),
        "seats": 0,
        "phone": clean_text(get("phone"), 40),
        "email": clean_text(get("email"), 120),
        "note": clean_text(get("note"), 200),
    }
    errors = []
    kind = cleaned["kind"]
    if kind not in KIND_LABELS:
        errors.append("Bitte wähle, ob du fährst oder eine Mitfahrt suchst.")
    if not cleaned["name"]:
        errors.append("Bitte gib deinen Namen an.")
    if not cleaned["origin"]:
        errors.append("Bitte gib deinen Startort an.")
    if cleaned["day"] not in DAY_LABELS:
        errors.append("Bitte wähle, ob es um Freitag oder Samstag geht.")
    if cleaned["direction"] not in DIRECTION_LABELS:
        errors.append("Bitte wähle Hinfahrt, Rückfahrt oder beides.")

    limit = SEATS_MAX.get(kind, 8)
    try:
        cleaned["seats"] = int(get("seats").strip())
        if not 1 <= cleaned["seats"] <= limit:
            raise ValueError
    except ValueError:
        what = "Personenzahl" if kind == "seek" else "Freie Plätze"
        errors.append(f"{what}: bitte 1 bis {limit} angeben.")

    if not cleaned["phone"] and not cleaned["email"]:
        errors.append("Bitte gib Telefon oder E-Mail an, damit man dich erreichen kann.")
    if cleaned["phone"] and normalize_phone(cleaned["phone"]) is None:
        errors.append("Bitte gib eine gültige Telefonnummer an.")
    if cleaned["email"] and not valid_email(cleaned["email"]):
        errors.append("Bitte gib eine gültige E-Mail-Adresse an.")
    if get("consent") != "on":
        errors.append("Bitte stimme der Sichtbarkeit deiner Angaben für andere Gäste zu (Einwilligung).")
    return cleaned, errors
