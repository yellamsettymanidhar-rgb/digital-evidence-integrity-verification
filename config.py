"""
Configuration for the Digital Evidence Integrity Verification System.

All secrets/paths come from environment variables (loaded from .env in
development). Nothing sensitive is hardcoded here — see .env.example.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    # Flask signs session cookies with this — must be secret and stable.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")

    # SQLite by default (see README for MySQL migration notes).
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "database" / "evidence.db"))

    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    REPORTS_FOLDER = os.environ.get("REPORTS_FOLDER", str(BASE_DIR / "reports"))

    # 100 MB default cap — plenty for a demo, prevents disk-fill abuse.
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "100")) * 1024 * 1024

    # Deliberately broad but not unrestricted: covers the evidence types the
    # brief calls out (images, PDFs, docs, video, audio) while still blocking
    # anything directly executable.
    ALLOWED_EXTENSIONS = {
        "png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp",
        "pdf", "doc", "docx", "txt", "rtf", "odt",
        "mp4", "avi", "mov", "mkv", "webm",
        "mp3", "wav", "ogg", "m4a",
        "zip", "csv", "log", "json", "xml",
    }

    HASH_ALGORITHM = "SHA-256"
    HASH_CHUNK_SIZE = 65536  # 64 KB streaming chunks — see utils/hashing.py

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
