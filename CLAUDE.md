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
