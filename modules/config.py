from pathlib import Path
import sys

#project directory
if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Project folders
FEEDS_DIR = PROJECT_ROOT / "feeds"
OUTPUT_DIR = PROJECT_ROOT / "output"
DATABASE_DIR = PROJECT_ROOT / "database"

UPLOADED_DIR = FEEDS_DIR / "uploaded"
DOWNLOADED_DIR = FEEDS_DIR / "downloaded"

# Create required folders automatically
FEEDS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
UPLOADED_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADED_DIR.mkdir(parents=True, exist_ok=True)

# SQLite database
DATABASE_FILE = DATABASE_DIR / "threatintel.db"
# Download helper
save_path = DOWNLOADED_DIR / "filename"