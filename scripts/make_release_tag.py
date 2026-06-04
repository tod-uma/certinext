#!/usr/bin/env python3
# Copyright 2026 University of Maine System
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Create an annotated release tag with a curated changelog.

The release notes published by GitLab CI are taken verbatim from the
annotated tag message, so the tag message must contain the full changelog
for the release. For a stable release (``X.Y.Z``) that means every change
since the *previous stable* tag -- including everything that shipped in the
intervening alpha/beta/rc pre-releases.

This script removes the guesswork: it reads the version from
``pyproject.toml``, finds the correct comparison tag, assembles a grouped
changelog from the git history of that range, opens it in your git editor
for curation, and then creates the annotated tag. Run it from any clone with
full history -- no AI assistant required.
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Maps a conventional-commit type to the changelog section it appears under.
# Order here is the order sections are rendered.
SECTIONS: list[tuple[str, tuple[str, ...]]] = [
    ("Features", ("feat",)),
    ("Fixes", ("fix",)),
    ("Performance", ("perf",)),
    ("Refactoring", ("refactor",)),
    ("Documentation", ("docs",)),
    ("Tests", ("test",)),
    ("CI / Build", ("ci", "build", "chore", "style")),
    ("Other", ()),  # catch-all; matched last
]

# Matches "type(scope): description" or "type: description" (conventional commits).
_SUBJECT_RE = re.compile(r"^(?P<type>\w+)(?:\((?P<scope>[^)]+)\))?(?P<bang>!)?:\s*(?P<desc>.+)$")

# A stable version has no pre-release/dev suffix, e.g. "0.1.0" but not "0.1.0rc6".
_STABLE_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Matches a stable release *tag*, e.g. "v0.1.0" but not "v0.1.0a1".
_STABLE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")


def _run(args: list[str]) -> str:
    """Run a git command and return its stripped stdout.

    Args:
        args: The argument list passed to ``git`` (without the leading "git").

    Returns:
        The command's standard output with surrounding whitespace removed.

    Raises:
        SystemExit: If the git command exits non-zero.
    """
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"git {' '.join(args)} failed:\n{result.stderr}", file=sys.stderr)
        raise SystemExit(1)
    return result.stdout.strip()


def read_version(pyproject: Path) -> str:
    """Read the project version from ``pyproject.toml``.

    Uses a regex rather than a TOML parser to avoid a hard dependency on
    ``tomllib`` (Python 3.11+) while the project still supports 3.10.

    Args:
        pyproject: Path to the ``pyproject.toml`` file.

    Returns:
        The version string, e.g. "0.1.0" or "0.2.1rc6".

    Raises:
        SystemExit: If no version field is found.
    """
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    if not match:
        print(f"No version field found in {pyproject}", file=sys.stderr)
        raise SystemExit(1)
    return match.group(1)


def is_stable(version: str) -> bool:
    """Return whether a version string is a stable release.

    Args:
        version: A PEP 440 version string, e.g. "0.1.0" or "0.1.0rc1".

    Returns:
        True if the version has no pre-release or dev suffix.
    """
    return bool(_STABLE_RE.match(version))


def previous_tag(current_tag: str, stable_only: bool) -> str | None:
    """Find the most recent tag preceding ``current_tag`` by version order.

    Only tags that are ancestors of HEAD are considered (``git tag --merged
    HEAD``). ``git tag --list`` otherwise reports tags from every fetched
    remote -- including unrelated repositories sharing the clone -- which can
    produce a "previous" tag that is not even in this project's history.

    Args:
        current_tag: The tag being created, e.g. "v0.1.0".
        stable_only: If True, consider only stable release tags (no a/b/rc
            suffix). Used when the new tag is itself stable, so the changelog
            spans every pre-release since the last stable release.

    Returns:
        The previous tag name, or None if there is no earlier tag.
    """
    tags = _run(["tag", "--list", "v*", "--merged", "HEAD", "--sort=-version:refname"]).splitlines()
    pattern = _STABLE_TAG_RE if stable_only else re.compile(r"^v")
    candidates = [t for t in tags if pattern.match(t) and t != current_tag]
    return candidates[0] if candidates else None


def commit_log(rev_range: str | None) -> list[tuple[str, str]]:
    """Return the non-merge commits for a revision range as (sha, subject) pairs.

    The abbreviated SHA is included so each changelog entry can carry a bare
    commit reference, which GitLab Flavored Markdown auto-links to the commit.

    Args:
        rev_range: A git revision range like "v0.1.0..HEAD", or None to list
            every commit reachable from HEAD (used when no previous tag exists).

    Returns:
        A list of (abbreviated_sha, subject) tuples, newest first.
    """
    # %x1f is the ASCII unit separator -- a delimiter that cannot appear in a
    # commit subject, so the split is unambiguous.
    args = ["log", "--no-merges", "--format=%h%x1f%s"]
    if rev_range:
        args.append(rev_range)
    out = _run(args)
    commits: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        sha, _, subject = line.partition("\x1f")
        commits.append((sha, subject))
    return commits


def group_commits(commits: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Group commits into changelog sections by conventional-commit type.

    Each entry ends with its bare abbreviated SHA in parentheses; GitLab
    Flavored Markdown renders that as a link to the commit.

    Args:
        commits: (abbreviated_sha, subject) tuples from commit_log.

    Returns:
        A mapping of section title to its list of formatted bullet entries,
        containing only sections that have at least one entry.
    """
    buckets: dict[str, list[str]] = {title: [] for title, _ in SECTIONS}
    for sha, subject in commits:
        match = _SUBJECT_RE.match(subject)
        if match:
            ctype = match.group("type").lower()
            scope = match.group("scope")
            desc = match.group("desc")
            entry = f"{scope}: {desc}" if scope else desc
        else:
            ctype = ""
            entry = subject
        bullet = f"{entry} ({sha})"
        for title, types in SECTIONS:
            if ctype in types or not types:  # "" types == catch-all "Other"
                buckets[title].append(bullet)
                break
    return {title: entries for title, entries in buckets.items() if entries}


def build_changelog(tag: str, prev: str | None, grouped: dict[str, list[str]]) -> str:
    """Assemble the draft tag message from grouped changelog entries.

    Args:
        tag: The tag being created, e.g. "v0.1.0".
        prev: The previous tag the changelog is measured against, or None.
        grouped: Section-title -> bullet-entries mapping from group_commits.

    Returns:
        The full draft tag message as a single string.
    """
    heading = f"## Changes since {prev}" if prev else "## Initial release"
    lines = [tag, "", heading, ""]
    for title, _ in SECTIONS:
        entries = grouped.get(title)
        if not entries:
            continue
        lines.append(f"### {title}")
        lines.extend(f"- {entry}" for entry in entries)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def summarize_with_claude(draft: str, tag: str, prev: str | None) -> str | None:
    """Polish a mechanical changelog into prose release notes via the claude CLI.

    Pipes the draft through ``claude -p`` (headless mode). Authentication is
    inherited from the installed CLI's existing login -- this function passes
    no credentials. Any failure (CLI missing, not logged in, timeout, error,
    empty output) is treated as a soft failure so the caller can fall back to
    the mechanical draft; summarization only ever improves, never blocks.

    Args:
        draft: The mechanically generated changelog.
        tag: The tag being created, e.g. "v0.1.0".
        prev: The previous tag the changelog spans from, or None.

    Returns:
        The polished release notes, or None if summarization was unavailable
        or failed for any reason.
    """
    claude = shutil.which("claude")
    if not claude:
        print("--summarize: 'claude' CLI not found on PATH; using raw draft.", file=sys.stderr)
        return None

    span = f"since {prev}" if prev else "for the initial release"
    instructions = (
        f"You are writing GitLab release notes for {tag}, covering changes {span}. "
        "The text piped to you is an auto-generated changelog built from commit "
        "subjects. Rewrite it into polished release notes:\n"
        "- Keep the first line exactly as the tag name.\n"
        "- Add a '## Highlights' section with a short prose summary (2-4 sentences) "
        "of the most important user-facing changes.\n"
        "- Keep a grouped detail list below the highlights; merge closely related "
        "entries and drop pure noise (e.g. trivial CI tweaks) where it improves "
        "readability.\n"
        "- Preserve the bare commit SHAs in parentheses verbatim -- GitLab "
        "auto-links them.\n"
        "- Use GitLab Flavored Markdown. Do not invent changes that are not in the "
        "input. Output only the release notes, with no preamble or code fences."
    )
    print("--summarize: polishing changelog with claude...", file=sys.stderr)
    try:
        result = subprocess.run(
            [claude, "-p", instructions],
            input=draft,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"--summarize: claude invocation failed ({exc}); using raw draft.", file=sys.stderr)
        return None
    if result.returncode != 0:
        print(f"--summarize: claude exited {result.returncode}; using raw draft.", file=sys.stderr)
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        return None
    polished = result.stdout.strip()
    if not polished:
        print("--summarize: claude returned no output; using raw draft.", file=sys.stderr)
        return None
    return polished + "\n"


def edit_in_editor(message_file: Path) -> None:
    """Open the draft message file in the user's configured git editor.

    The file is edited in place. We invoke the editor on our own file directly
    -- rather than relying on ``git tag --edit`` -- so that git does not inject
    its instructional comment lines, which would otherwise survive the
    verbatim tag-message cleanup. The editor is resolved exactly as git would
    (``core.editor`` / GIT_EDITOR / VISUAL / EDITOR / built-in default).

    Args:
        message_file: Path to the draft message file to edit.
    """
    editor = subprocess.run(
        ["git", "var", "GIT_EDITOR"], capture_output=True, text=True
    ).stdout.strip()
    if not editor:
        print("No git editor configured; skipping edit step.", file=sys.stderr)
        return
    # GIT_EDITOR may include arguments (e.g. "code --wait"), so invoke it the
    # way git does -- through the shell -- rather than as a bare executable.
    subprocess.run(f'{editor} "{message_file}"', shell=True)


def create_tag(tag: str, message_file: Path, force: bool) -> None:
    """Create the annotated git tag from a message file, verbatim.

    Uses ``--cleanup=verbatim`` so the message is stored exactly as written.
    git's default tag cleanup is ``strip``, which removes lines beginning with
    ``#`` as comments -- that would silently delete every Markdown heading
    (``## Highlights``, ``### Features``, ...) from the release notes.

    Args:
        tag: The tag name to create, e.g. "v0.1.0".
        message_file: Path to the file holding the final tag message.
        force: If True, replace an existing tag of the same name (git -f).

    Raises:
        SystemExit: If the underlying ``git tag`` command fails.
    """
    args = ["git", "tag", "-a", tag, "-F", str(message_file), "--cleanup=verbatim"]
    if force:
        args.append("-f")
    result = subprocess.run(args)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> None:
    """Parse arguments and drive the release-tag creation flow."""
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "version",
            nargs="?",
            help="Version to tag (default: read from pyproject.toml). The 'v' prefix is added automatically.",
        )
        parser.add_argument(
            "--no-edit",
            action="store_true",
            help="Use the generated changelog as-is without opening an editor.",
        )
        parser.add_argument(
            "--print",
            dest="print_only",
            action="store_true",
            help="Print the draft changelog and exit without creating a tag.",
        )
        parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Replace an existing tag of the same name.",
        )
        parser.add_argument(
            "--summarize",
            action="store_true",
            help="Polish the changelog into prose release notes via the installed "
            "claude CLI (falls back to the raw draft if unavailable).",
        )
        args = parser.parse_args()

        root = Path(__file__).resolve().parent.parent
        version = args.version or read_version(root / "pyproject.toml")
        version = version.lstrip("v")
        tag = f"v{version}"
        stable = is_stable(version)

        prev = previous_tag(tag, stable_only=stable)
        rev_range = f"{prev}..HEAD" if prev else None
        commits = commit_log(rev_range)
        grouped = group_commits(commits)
        changelog = build_changelog(tag, prev, grouped)

        kind = "stable" if stable else "pre-release"
        base = prev or "(none -- initial release)"
        print(f"Tag:      {tag}  ({kind})", file=sys.stderr)
        print(f"Since:    {base}", file=sys.stderr)
        print(f"Commits:  {len(commits)}", file=sys.stderr)
        print(file=sys.stderr)

        if args.summarize:
            polished = summarize_with_claude(changelog, tag, prev)
            if polished:
                changelog = polished

        if args.print_only:
            print(changelog)
            return

        with tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(changelog)
            message_file = Path(handle.name)
        try:
            if not args.no_edit:
                edit_in_editor(message_file)
            create_tag(tag, message_file, force=args.force)
        finally:
            message_file.unlink(missing_ok=True)

        print(file=sys.stderr)
        print(f"Created tag {tag}. Review it with:", file=sys.stderr)
        print(f"    git show {tag}", file=sys.stderr)
        print("Then push it to publish the release:", file=sys.stderr)
        print(f"    git push origin {tag}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
