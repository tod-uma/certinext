import json
import subprocess
import sys

data = json.load(sys.stdin)
cmd = data.get("tool_input", {}).get("command", "")

if not cmd.startswith("git commit"):
    sys.exit(0)

for step in [
    (["uv", "run", "mypy", "certinext"], "mypy failed"),
    (["uv", "run", "pytest"], "tests failed"),
]:
    command, reason = step
    result = subprocess.run(command)
    if result.returncode != 0:
        print(json.dumps({
            "continue": False,
            "stopReason": f"{reason} — fix before committing",
        }))
        sys.exit(1)
