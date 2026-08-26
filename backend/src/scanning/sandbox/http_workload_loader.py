"""Loads the container-side HTTP workload as a base64 argv payload.

Keeping the loader separate from the workload source lets the transport
inject the program through ``docker exec ... python -c <b64>`` without any
image coupling: the executed code is always byte-identical to the repo.
"""

from __future__ import annotations

import base64
from pathlib import Path

_SOURCE = Path(__file__).with_name("http_workload.py").read_text(encoding="utf-8")
WORKLOAD_B64 = base64.b64encode(_SOURCE.encode("utf-8")).decode("ascii")
# Ready-to-pass ``python -c`` argument that materializes and runs the
# workload inside the sandbox container.
WORKLOAD_EXEC_CODE = "import base64;exec(base64.b64decode('" + WORKLOAD_B64 + "').decode())"
