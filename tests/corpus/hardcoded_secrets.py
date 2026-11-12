"""Corpus: passwords and keys written in the code (SL104)."""

import os

DB_USER = "admin"
DB_PASSWORD = "hunter2"  # expect: SL104
SECRET_KEY = "django-insecure-4f9x2k"  # expect: SL104
API_KEY: str = "sk-live-51Hxyz"  # expect: SL104
GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnop"  # expect: SL104

SETTINGS = {
    "user": "app",
    "password": "hunter2",  # expect: SL104
}


class Mailer:
    def __init__(self):
        self.smtp_password = "s3cr3t!"  # expect: SL104


def connect():
    return Database(host="db.local", user="app", password="hunter2")  # expect: SL104


def configure(app):
    app.secret_key = b"_5#y2LF4Q8z"  # expect: SL104
    app.config["JWT_SECRET"] = "jwt-signing-secret"  # expect: SL104


def login(user, password="admin123"):  # missed: SL104
    return check(user, password)


def is_admin(password):
    return password == "letmein"  # missed: SL104


SESSION_TOKEN = "abc123"  # missed: SL104
CREDENTIALS = ("admin", "hunter2")  # missed: SL104
DATABASE_URL = "postgres://app:hunter2@db.local/app"  # missed: SL104


# ---- Safe code: nothing below is dangerous. ----

password = os.environ["DB_PASSWORD"]
api_key = os.environ.get("API_KEY")
EMPTY_PASSWORD = ""
EXAMPLE_PASSWORD = "<your password>"
TEMPLATE_PASSWORD = "${DB_PASSWORD}"
PASSWORD_FIELD = "password"
PASSWORD_MIN_LENGTH = 12
TOKEN_URL = "https://example.com/oauth/token"
CACHE_KEY = "user:42"
PRIMARY_KEY = "id"
RESET_PASSWORD = "/account/reset-password"  # false-alarm: SL104
LABEL_PASSWORD = "Password:"  # false-alarm: SL104
