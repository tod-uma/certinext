---
name: first-stable-release
description: First stable release checklist for certinext. Use when tagging a stable version (X.Y.Z with no alpha/beta/rc suffix) — the release_job has not been tested on a stable tag in this repo yet.
---

This is the first stable release of certinext. The `release_job` reads the annotated tag message via the Tags API and posts it verbatim as the release description. This approach is confirmed working in ums-certinext-scripts but not yet tested here on a stable tag.

## Before tagging

- Confirm the tag message is well-formed Markdown (it becomes the release description on both GitLab and GitHub)
- Use the `/release` skill to create the annotated tag

## After tagging — check all three destinations

1. **GitLab `release_job`** — watch the tag pipeline. Confirm:
   - `release_job` passes
   - A release appears at `sysadmin/python-libs/certinext/-/releases` with the correct description

2. **GitHub Actions** — triggered by the mirrored tag. Confirm:
   - `publish-pypi` job passes
   - GitHub release appears with the same description as GitLab

3. **PyPI** — stable versions are visible without `--pre`. Confirm the new version appears.

## If everything passes

Delete this skill: remove `.claude/skills/first-stable-release/` and its contents from the certinext repo.
