# certinext

## GitLab project path

`sysadmin/python-libs/certinext` — use for GitLab CI references, clone URLs, and API calls.

## Publish chain

Releases follow: **local → GitLab → GitHub → PyPI**.

To release: tag on GitLab and push to GitLab only — GitHub and PyPI follow automatically.

- GitLab CI publishes to the GitLab package registry on tag.
- GitLab **auto-mirrors** to GitHub — do not push to the GitHub remote manually (it will say "Everything up-to-date" if the mirror already beat you to it).
- GitHub Actions triggers on the mirrored tag and publishes to public PyPI via OIDC trusted publishing.

Pre-release versions (rc, alpha, beta) land on PyPI but are only visible with `pip install --pre certinext`.

## Wishlist awareness

Deferred ideas live in `docs/wishlist/` (index in its README). When making code changes or improvements, keep them in mind: prefer designs that keep parked ideas cheap rather than foreclosing them, and mention in the MR when a change materially advances or blocks one. Example: the 1.0 refactor keeps CLI bodies as thin presentation over library functions specifically so IDEA-001 (TUI) and IDEA-002 (MCP server) can reuse the operations layer.
