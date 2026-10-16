import os
from pathlib import Path

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = os.getenv(
    "TEMPLATES_DIR",
    str(Path(__file__).resolve().parents[2] / "frontend" / "templates"),
)

templates = Jinja2Templates(directory=TEMPLATES_DIR)
