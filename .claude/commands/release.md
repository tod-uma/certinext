---
description: Cut a release tag with a curated, full-range changelog
argument-hint: "[version, e.g. 0.2.1 — optional]"
---

Help the user cut a release for this repository. The release notes published on
**both GitLab and GitHub** come **verbatim from the annotated tag message**.
The full process is documented in [RELEASING.md](../../RELEASING.md) — follow it.

Target version (optional): **$ARGUMENTS**

Steps:

1. **Confirm the version.** Read `version` from `pyproject.toml`. If `$ARGUMENTS`
   was given and differs, the version bump must land on `main` first (branch →
   MR → merge) before tagging.

2. **Be on an up-to-date `main` with full history.** Run `git checkout main &&
   git pull`. The changelog generator needs the commits between the previous tag
   and `HEAD`.

3. **Generate the mechanical draft.** Run:

   ```bash
   python scripts/make_release_tag.py --print
   ```

   For a **stable** release, confirm the "Since:" line is the previous *stable*
   tag so the notes span every intermediate rc/beta/alpha. (You are the LLM —
   do NOT pass `--summarize`; polish it yourself in the next step.)

4. **Polish into release notes.** Rewrite the draft:
   - Lead with `## Highlights`: a short prose summary (2-4 sentences) of the
     most important user-facing changes.
   - Keep a grouped detail list; merge related entries, drop noise.
   - **Preserve the bare commit SHAs** — GitLab auto-links them.
   - Where you name a specific file, use an explicit blob link at the tag
     (GLFM does not auto-link file paths). Issues `#N`, MRs `!N`, users
     `@name` do auto-link on GitLab; on GitHub, bare SHAs auto-link too.

   Show the polished notes to the user as plain text and get approval.

5. **Create the tag.**

   ```bash
   git tag -a vX.Y.Z -F <notes-file> --cleanup=verbatim   # add -f to re-cut
   ```

   `--cleanup=verbatim` is required — git's default strips `#` lines as
   comments, deleting every Markdown heading. Keep the first line as `vX.Y.Z`.

6. **Push to publish.** Get explicit approval, then:

   ```bash
   git push gitlab vX.Y.Z
   ```

   This triggers GitLab CI (`release_build` + `release_job`). The GitLab→GitHub
   mirror picks up the tag within a few minutes and GitHub Actions then builds
   the wheel, publishes to PyPI, and creates a matching GitHub release — both
   with the same curated notes from the tag message.

   Do **not** push the tag to `github` directly — the mirror handles it.

Apply this repo's normal conventions: annotated tags only, plain-text approval
before any push, branch pipeline green before relying on the release.
