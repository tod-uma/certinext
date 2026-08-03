# Architecture Decision Records

Records of decisions with a lasting effect on how this library is built —
hard to reverse, spanning more than one plan, or the kind of choice a
newcomer might reasonably have made differently. Format follows
[MADR](https://adr.github.io/madr/). ADRs are immutable once accepted: a
changed decision gets a *new* ADR marking the old one superseded, never an
edit to the old one's content.

**Statuses:** proposed → accepted | rejected | deprecated | superseded by NNNN.
Numbering is sequential and never reused.

## Records

| ID | Title | Status |
| --- | --- | --- |
| [0001](0001-non-fatal-format-downloads.md) | Non-fatal error handling for optional certificate format downloads | accepted |
| [0002](0002-track-vendor-api-bugs-in-gitlab-issues.md) | Track vendor API bugs in GitLab issues, with vendor-ticket cross-references | accepted |
| [0003](0003-adopt-pydantic-typer-httpx-settings-rich-for-1.0.md) | Adopt pydantic v2, typer, httpx, pydantic-settings, and rich for the 1.0 rewrite | accepted |
| [0004](0004-single-cli-app-with-alias-entry-points.md) | Ship one `certinext` CLI app; keep the eleven script names as aliases through 1.x | accepted |
| [0005](0005-lenient-models-validated-against-live-payload-corpus.md) | Lenient response models, validated against a captured live-payload corpus | accepted |
| [0006](0006-tomlkit-for-config-writes-tomllib-for-reads.md) | tomlkit for config-file writes, tomllib for reads | accepted |
| [0007](0007-logfmt-default-for-non-interactive-logging.md) | Default non-interactive log output to logfmt, not JSON; add --log-format to opt back into JSON | accepted |
| [0008](0008-org-scoped-dcv-inheritance-not-dns-zone-boundary.md) | DCV inheritance eligibility is org-scoped, not gated by DNS zone boundaries | accepted |

See also: [docs/wishlist/](../wishlist/) for deferred ideas not yet committed to.
