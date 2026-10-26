import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = os.getenv(
    "TEMPLATES_DIR",
    str(Path(__file__).resolve().parents[2] / "frontend" / "templates"),
)

templates = Jinja2Templates(directory=TEMPLATES_DIR)


def resource_link_info(url: str) -> tuple[str, bool]:
    """Match the browser's decoded path when choosing open vs download."""
    path = unquote(urlsplit(url).path, errors="replace")
    name = path.rstrip("/").rsplit("/", 1)[-1]
    downloadable = bool(name and not path.endswith("/")
                        and not name.lower().endswith((".html", ".htm")))
    return name, downloadable


templates.env.globals["resource_link_info"] = resource_link_info
