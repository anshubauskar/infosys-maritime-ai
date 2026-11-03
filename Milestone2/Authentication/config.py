"""Shared configuration for FreightQuote AI and Franchise."""

import os
import secrets

KIND = os.environ.get("APP_KIND", "Franchise")

APP_DIR = os.path.dirname(os.path.abspath(__file__))

_default = (
    "/content/app_data"
    if os.path.isdir("/content")
    else os.path.join(APP_DIR, "runtime_data")
)

DATA_DIR = (
    os.environ.get("PERSIST_DIR")
    or os.environ.get("APP_DATA_DIR")
    or os.environ.get("FRANCHISEOPS_DATA_DIR")
    or os.environ.get("FREIGHTQUOTE_DATA_DIR")
    or _default
)

os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(
    DATA_DIR,
    "franchise_database.db"
    if KIND == "Franchise"
    else "freight_database.db"
)


def _secret(key, default=""):
    """Read a secret from Colab Secrets or environment variables."""
    try:
        from google.colab import userdata
        value = userdata.get(key)
        if value:
            return str(value).strip()
    except Exception:
        pass

    return str(os.environ.get(key, default) or "").strip()


HF_TOKEN = _secret("HF_TOKEN") or _secret("HUGGINGFACE_TOKEN")


def _persisted_secret():
    """Generate and persist a JWT secret if one is not configured."""
    path = os.path.join(DATA_DIR, ".jwt_secret")

    try:
        if os.path.exists(path):
            with open(path, "r") as file:
                return file.read().strip()

        value = secrets.token_urlsafe(48)

        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )

        with os.fdopen(fd, "w") as file:
            file.write(value)

        return value

    except Exception:
        return secrets.token_urlsafe(48)


# JWT configuration
JWT_SECRET_KEY = (
    _secret("JWT_SECRET")
    or _secret("JWT_SECRET_KEY")
    or _persisted_secret()
)

# Admin configuration
ADMIN_EMAIL_ID = _secret("ADMIN_EMAIL_ID")

DEMO_MODE = os.environ.get("DEMO_MODE", "0") != "0"


def _admin_pw():
    value = _secret("ADMIN_PASSWORD")
    if not value:
        raise RuntimeError(
            "ADMIN_PASSWORD is required. Add it in Google Colab → Secrets; "
            "do not use a hard-coded demo password."
        )
    return value

ADMIN_PASSWORD = _admin_pw()

# Email configuration for password-reset OTP
EMAIL_ID = (
    _secret("EMAIL_ADDRESS")
    or _secret("EMAIL_ID")
)

EMAIL_PASSWORD = _secret("EMAIL_PASSWORD").replace(" ", "")

# Model configuration
MODEL_NAME = os.environ.get("LLM_MODEL", "")

NLLB_MODEL = os.environ.get(
    "NLLB_MODEL",
    "facebook/nllb-200-distilled-600M"
)
