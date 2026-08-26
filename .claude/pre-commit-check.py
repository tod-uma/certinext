import json
import re
import subprocess
import sys

# Matches `git <options...> commit` anywhere in the command. This was a
# `startswith` test, which matched neither shape the house convention
# produces: `cd <repo> && git commit -F msg.txt` starts with `cd`, and
# `git -C <repo> commit` puts an option before the subcommand. The gate
# therefore passed every commit made the documented way without running.
_GIT_COMMIT = re.compile(r"\bgit\b(?:\s+\S+)*?\s+commit\b")

data = json.load(sys.stdin)
cmd = data.get("tool_input", {}).get("command", "")

if not _GIT_COMMIT.search(cmd):
    sys.exit(0)

for step in [
    (["uv", "run", "mypy", "certinext"], "mypy failed"),
    (["uv", "run", "pytest"], "tests failed"),
]:
    command, reason = step
    result = subprocess.run(command)
    if result.returncode != 0:
        # Exit 2 with the reason on stderr is the only combination the hook
        # contract treats as blocking. Exit 1 is a non-blocking error and
        # stdout JSON is read only on exit 0, so the previous form announced
        # a failure and then let the commit through regardless.
        print(f"{reason} - fix before committing", file=sys.stderr)
        sys.exit(2)
