from pathlib import Path
import json
from site_diagnostics.adapters.inbound.api import app

expected = json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n"
if Path("contracts/openapi.json").read_text() != expected:
    raise SystemExit("OpenAPI drift: run make generate")
print("OpenAPI matches API implementation")
