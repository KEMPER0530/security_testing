import json
from pathlib import Path
from site_diagnostics.adapters.inbound.api import app

Path("contracts/openapi.json").write_text(json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n")
