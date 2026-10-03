"""Reading and checking submitted form fields."""

import re
import unicodedata
from datetime import date, datetime

EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+")
DATETIME_FORMAT = "%Y-%m-%dT%H:%M"
DATE_FORMAT = "%Y-%m-%d"


def normalize_email(value):
    return value.strip().lower()[:254]


def valid_email(email):
    return len(email) <= 254 and EMAIL_RE.fullmatch(email) is not None


def _has_control_chars(value, multiline):
    allowed = "\n\t" if multiline else ""
    return any(unicodedata.category(c) == "Cc" and c not in allowed for c in value)


class FormReader:
    """Collects errors while reading fields, so a form can show all of them at once."""

    def __init__(self, form):
        self.form = form
        self.errors = []

    def text(self, name, label, max_len, required=True, multiline=False):
        value = self.form.get(name, "").replace("\r\n", "\n").replace("\r", "\n").strip()
        if not value:
            if required:
                self.errors.append(f"{label} can't be empty.")
            return ""
        if len(value) > max_len:
            self.errors.append(f"{label} can be at most {max_len} characters.")
            return ""
        if _has_control_chars(value, multiline):
            self.errors.append(f"{label} contains characters that aren't allowed.")
            return ""
        return value

    def datetime(self, name, label, required=True):
        value = self.form.get(name, "").strip()
        if not value:
            if required:
                self.errors.append(f"{label} is required.")
            return None
        try:
            return datetime.strptime(value, DATETIME_FORMAT).strftime(DATETIME_FORMAT)
        except ValueError:
            self.errors.append(f"{label} isn't a valid date and time.")
            return None

    def date(self, name, label, required=False):
        value = self.form.get(name, "").strip()
        if not value:
            if required:
                self.errors.append(f"{label} is required.")
            return None
        try:
            return datetime.strptime(value, DATE_FORMAT).date().isoformat()
        except ValueError:
            self.errors.append(f"{label} isn't a valid date.")
            return None

    def member(self, name, label, allowed_ids):
        """An optional id that must be one of allowed_ids (members of the user's own family)."""
        value = self.form.get(name, "").strip()
        if not value:
            return None
        if not value.isdigit() or len(value) > 18 or int(value) not in allowed_ids:
            self.errors.append(f"{label} must be someone in your family.")
            return None
        return int(value)


def format_datetime(value):
    if not value:
        return ""
    return datetime.strptime(value, DATETIME_FORMAT).strftime("%a %-d %b %Y, %H:%M")


def format_date(value):
    if not value:
        return ""
    return date.fromisoformat(value).strftime("%a %-d %b %Y")


def now_local():
    return datetime.now().strftime(DATETIME_FORMAT)


def today():
    return date.today().isoformat()
