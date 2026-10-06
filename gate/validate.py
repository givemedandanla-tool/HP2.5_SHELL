import json
import sys
from pathlib import Path

from approval_manifest import evaluate

if len(sys.argv) != 3:
    raise SystemExit("usage: validate.py MANIFEST STATE")

manifest = json.loads(Path(sys.argv[1]).read_text("utf-8"))
state = json.loads(Path(sys.argv[2]).read_text("utf-8"))
result = evaluate(manifest, state)
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["allowed"] else 1)
