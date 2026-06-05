# certinext-release skill

This is a **repo-specific release skill** for the certinext repository. When you run `/release` in this repo, the global skill detects this file and follows certinext-specific instructions instead of the generic steps — handling version confirmation, changelog drafting, and verification across all three publish destinations.

## How the delegation works

The global `/release` skill runs:

```bash
git rev-parse --show-toplevel | xargs basename
```

It then checks for `.claude/skills/{name}-release/SKILL.md` in the current directory. When it finds this file, it reads and follows these instructions instead. The naming convention is `{dirname}-release`, where `dirname` is the repository's root directory name.

## What makes this skill certinext-specific

- **Three publish destinations** — GitLab release, GitHub release (via mirror), and PyPI (stable tags only, via GitHub Actions `publish-pypi` job)
- **No changelog script** — certinext does not have `scripts/make_release_tag.py`; the changelog is written manually from `git log`
- **Version confirmation** — the version in `pyproject.toml` must already be on `main` before tagging; tag only what's merged

## Creating a repo-specific release skill for your own project

1. Create `.claude/skills/{your-repo-name}-release/SKILL.md` in your repo, where `{your-repo-name}` matches `basename $(git rev-parse --show-toplevel)`.
2. Add frontmatter with `name: {your-repo-name}-release` and a descriptive `description:`.
3. Write the full release steps for your repo. At minimum include:
   - Version confirmation against `pyproject.toml` and a check that any bump is on `main`
   - `git checkout main && git pull` — full history is required; shallow clones break changelog tools
   - Changelog generation (use a script like `scripts/make_release_tag.py` if available, otherwise `git log`)
   - `git tag -a vX.Y.Z --cleanup=verbatim -F <notes-file>` — never a lightweight tag; `--cleanup=verbatim` preserves Markdown headings that git would otherwise strip
   - The `-f` flag note for re-cutting a tag: `git tag -a vX.Y.Z --cleanup=verbatim -F <notes-file> -f`
   - Push confirmation and post-release verification steps for every destination
4. Add a `README.md` alongside `SKILL.md` (like this file) so collaborators understand what they're looking at.
5. Commit both files. Other Claude Code users who clone the repo will get the skill automatically.
