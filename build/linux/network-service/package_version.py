#!/usr/bin/env python3
import re
import sys
from pathlib import Path
match = re.search(r'^version: "([A-Za-z0-9._+-]+)"$', Path(sys.argv[1]).read_text(), re.MULTILINE)
if not match:
    raise SystemExit("Cannot determine Linux package version")
print(match.group(1))
