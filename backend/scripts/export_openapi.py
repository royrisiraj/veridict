"""Export deterministic API schemas without starting collectors or connecting to chain."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.main import app

parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
destination = Path(__file__).resolve().parents[2] / "frontend/openapi.json"
content = json.dumps(app.openapi(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
if args.check:
    if not destination.exists() or destination.read_text(encoding="utf-8") != content:
        raise SystemExit("OpenAPI drift: run uv run python scripts/export_openapi.py")
else:
    destination.write_text(content, encoding="utf-8")
