# IDEA-013: Run `ruff format` and enforce it in CI

- **Status:** Proposed
- **Created:** 2026-08-26
- **Updated:** 2026-08-26
- **Coordinating issue:** #33

## Context

`pyproject.toml` declares `[tool.ruff] line-length = 120`, but the formatter has
never been run against this repo. The code is wrapped at ruff's **default 88**
columns, so the declared configuration and the actual code disagree — and
nothing surfaces that, because neither `.gitlab-ci.yml` nor
`.claude/pre-commit-check.py` runs `ruff format --check`. Measured 2026-08-26:

```console
$ uv run ruff format --check .
65 files would be reformatted, 14 files already formatted
```

This surfaced while setting up `certinext-spec-watch`, which was seeded from this
repo's conventions. Its copied pre-commit hook *did* include a
`ruff format --check` step, and that step failed against its own tree from the
first commit — a gate that could never pass. That repo formatted at 120 and now
enforces the check in both pipelines (GitLab and GitHub Actions), so the two
repos have deliberately diverged and this one is the odd case.

The trap generalizes: any hook, CI job, or contributor instruction copied out of
this repo that mentions the formatter is a gate that fails on arrival. A
contributor who runs `ruff format` before opening an MR — the reasonable thing to
do given the config file says 120 — produces a 65-file diff.

## The idea

1. Run `uv run ruff format .` and land it as a single `style:` commit that
   changes nothing but whitespace and wrapping.
2. Add `.git-blame-ignore-revs` at the repo root naming that commit, so
   `git blame` skips it (`git config blame.ignoreRevsFile .git-blame-ignore-revs`
   locally; GitLab's blame view honours the file at the repo root — **verify on
   this instance before relying on it**).
3. Add `uv run ruff format --check .` to the `lint` job in `.gitlab-ci.yml` and
   to `.github/workflows/ci.yml`, and to `.claude/pre-commit-check.py`.

`certinext-spec-watch` is the worked example of the end state.

## Why not now

The reformat touches 65 of 79 files. That is not risky — the formatter does not
change semantics, and the test suite (949 passing) would prove it — but it is
maximally disruptive to anything in flight: **every open branch conflicts**, and
the conflicts are the tedious kind that a merge tool resolves badly.

Right now that matters. The repo is mid-`1.3.0rc` line, and the
`certinext-spec-watch` publication work
(`certinext-spec-snapshots/docs/plans/publish-spec-watch-tooling.md`) is still
running through Phase 1 with more changes expected here.

**What would change this:** a quiet point with no long-lived branches open —
ideally immediately after a stable tag, before the next line of work starts. The
cost is entirely in collision with concurrent work, so it drops to near zero at
the right moment and is otherwise self-inflicted.

## Pros

- Removes a latent trap: any copied hook or CI job that checks formatting
  currently fails on arrival, and the failure looks like the *copy's* fault.
- Gives outside contributors one mechanical rule instead of a reviewer's
  judgement about line wrapping — this repo push-mirrors to public GitHub and
  publishes to PyPI, so it does take outside eyes.
- Makes the declared `line-length = 120` true rather than aspirational.
- Realigns with `certinext-spec-watch`, which already enforces it.

## Cons / costs

- 65-file churn in one commit, and a conflict with every branch open at the time.
- `git blame` noise until `.git-blame-ignore-revs` is in place and honoured —
  and the GitLab side of that is unverified.
- Some 88-column wrapping is genuinely more readable than the 120-column
  collapse the formatter would produce: multi-clause boolean returns and chained
  set unions become long single lines. This is a real loss, not just churn, and
  it argues for the alternative below being taken seriously rather than dismissed.

## The alternative, and why it is not cheaper

The obvious inverse — set `line-length = 88` to match the code as written, near-zero
churn — was measured and is **worse**:

```console
$ uv run ruff check --line-length 88 --select E501 .
Found 850 errors.
```

`[tool.ruff.lint] select` includes `"E"`, which contains `E501`. The tree has 850
lines longer than 88 characters today; they survive only because `line-length =
120` means `E501` never fires. The formatter does not split long strings, URLs,
or comments, so those 850 are overwhelmingly manual fixes. Changing the number is
a bigger job than running the formatter.

A third option — keep 120 for `E501` but pin the formatter to 88 via
`[tool.ruff.format]` — is possible, but ruff treats `line-length` as shared
between linter and formatter, so this means carrying a deliberate split that has
to be explained every time someone reads the config.

## Effort

Small and mostly mechanical: one `ruff format` run, one commit, three CI/hook
lines, one `.git-blame-ignore-revs` file. The scheduling is the hard part, not
the work.

## Open questions & caveats

- Does GitLab's blame view on this instance actually honour a repo-root
  `.git-blame-ignore-revs`? Unverified. If not, the blame noise is permanent
  for anyone using the web UI.
- Should `certinext-zabbix` land the same change at the same time? It has the
  identical mismatch at a much smaller scale (5 of 8 files) — see
  `certinext-zabbix` `IDEA-006`.
- Do the same for `nm` and `ums-certinext-scripts`? Neither repo's hook checks
  formatting today, so neither is failing; they were not measured.

## Next steps

None until the scheduling condition above is met. When it is: format, ignore-revs,
enforce, and update this idea's status.

## References

- [ruff formatter](https://docs.astral.sh/ruff/formatter/) — behaviour and the
  `line-length` interaction with the linter.
- [ruff configuration](https://docs.astral.sh/ruff/configuration/) — `line-length`,
  `[tool.ruff.format]`.
- [ruff rule E501](https://docs.astral.sh/ruff/rules/line-too-long/) — line-too-long.
- [git blame `--ignore-revs-file`](https://git-scm.com/docs/git-blame#Documentation/git-blame.txt---ignore-revs-fileltfilegt)

---

> **AI-assistant disclaimer:** Drafted by Claude Code (Claude Opus 5 (1M context),
> `claude-opus-5[1m]`) from a conversation with Tod Detre. May contain inaccuracies
> or hallucinated details; verify specifics against current sources before relying
> on them.
