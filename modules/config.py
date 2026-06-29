# Detect whether running as .exe or Python script
from pathlib import Path
import sys

if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

FEEDS_DIR = PROJECT_ROOT / "feeds"
OUTPUT_DIR = PROJECT_ROOT / "output"
DATABASE_DIR = PROJECT_ROOT / "database"
UPLOADED_DIR = FEEDS_DIR / "uploaded"
DOWNLOADED_DIR = FEEDS_DIR / "downloaded"
DATABASE_FILE = DATABASE_DIR / "threatintel.db"
save_path = DOWNLOADED_DIR / "filename"