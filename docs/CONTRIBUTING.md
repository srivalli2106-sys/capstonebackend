# Contributing

How to contribute changes to this repository. Read this once; the rest of the
team will expect it.

## 1. Git workflow (trunk-based, batch deploys)

```
main  ← production (deploys to Render; only ever contains tested, released code)
   └── develop (integration branch used for release/deploy pulls)
         └── feature/<short-name>   (your work branch)
              └── ... commits ...   →  push → PR into develop → CI → review
```

- `main` is protected: never push to it directly; only PRs merged after review + CI go there, and only via `develop`.
- Work on a feature branch off **`develop`**: `git checkout develop; git checkout -b feature/<short-name>`.
- Keep the branch small and focused — one logical change per branch/PR (e.g. `feature/mongodb-timeouts`, not a grab-bag).
- Rebase on `develop` to keep the history linear; resolve conflicts by re-running the affected tests.

## 2. Branch & commit conventions

- Branch names: `feature/<short-name>` (lowercase, hyphens). No `hotfix/`/
  `WIP` unless actively coordinated.
- Verbed imperative commit subjects, ≤ ~72 chars, e.g.:
  - `fix: serve the consumed OPK on bundle fetch`
  - `test: cover atomic OPK consumption under concurrency`
  - `docs: document the Render deployment path`
  - `feat: add issuer claim validation`
- One commit per self-contained change; squash fixups into the feature branch.
- No secrets, tokens, `.env` dumps, or personal artifacts in any commit. See §5.

## 3. Definition of Done (every PR must have all four)

1. **Green CI**: ruff clean (`ruff check server tests protocol`), unit tests
   pass, integration tests pass (CI runs them against disposable Mongo/Redis
   containers), Docker build succeeds.
2. **Tests**: new behavior adds/updates tests; existing coverage is preserved
   (current targets ≈ 96% server+protocol branch coverage, `protocol/` 100%).
3. **Docs in sync**: any public behavior change updates the relevant
   `docs/*.md` in the **same PR** (see §4). No stale phase notes.
4. **No regression**: the diff changes only what it intends to; no unrelated
   reformatting, no refactors bundled with feature work.

Local check before pushing:

```powershell
ruff check server tests protocol
pytest -m "not integration"
$env:RUN_INTEGRATION="1"; pytest -m integration   # local/dev DBs only
```

See [docs/TESTING.md](docs/TESTING.md) for the full test model.

## 4. Documentation rules

The `docs/` folder is a first-class artifact — it is the onboarding and
operating runbook (`docs/README-INDEX`-style links live in the README). When
you change behavior:

- update the doc(s) that describe that behavior **in the same PR**;
- keep one source of truth: a fact lives in exactly one doc, others link to it;
- do not duplicate large tables or flows across docs;
- document environment effects in [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md)
  when you add or change a setting;
- docs are prose + tables, PowerShell examples on Windows first; commands must
  be copy-paste-correct.

## 5. Security rules (non-negotiable)

- **Never** commit: real passwords, tokens, private keys, `.env` files, Mongo/
  Redis URIs with live credentials, or screenshots of logs containing tokens.
  `.env` is git-ignored; keep it that way.
- Production databases (Mongo/Redis) are **never** used for local development,
  tests, or manual pokes. Local work uses `docker compose` throwaway services
  or a dedicated dev instance — see [docs/DATABASE.md](docs/DATABASE.md).
- Do not weaken fail-closed behavior (auth revocation, challenge consumption,
  WS token watcher) "because tests are annoying". Those degradations are
  deliberate — see [docs/WEBSOCKET.md](docs/WEBSOCKET.md) and
  [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md).
- Report security consequences of a change in the PR description (e.g. new
  side-channel, key lifecycle change).

## 6. PR expectations

- Title: `<type>: short summary` (same rules as commits).
- Description: what, why, how it was verified (commands + outcomes, e.g.
  "446 passed, ruff clean, coverage 96%"), and the docs updated.
- Reference the issue/phase if one exists (e.g. `Closes #123`).
- Small diffs get faster reviews; split large changes across PRs.
- After review feedback, push follow-up commits on the same branch (no force
  push unless it's a rebase you announced).

## 7. Review conventions

- Reviewers check the **four** DoD items, not just the diff.
- A reviewer must be able to run the PR's own verification commands.
- Approve only when all requested changes are addressed; unresolved security
  concerns block the merge.
- Mystery changes fail review: if a diff needs more than a sentence to explain,
  it needs a commit message that explains it.

## 8. Releases / deploys

- Release = merge `develop` → `main` after a full CI green on `main`.
- Render deploys from `main` (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md));
  a deploy is an immutable snapshot — verify `/health` and `/health/ready` after
  it lands, then smoke-test per [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) §7.
- If a deploy regresses, re-deploy the previous successful deploy; fix forward
  in a branch.

## 9. Getting help

- Read the docs first: `docs/README-INDEX`-style starting points are the README
  table (§Documentation) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Ask in the team channel with the `X-Request-ID` from the failing call and the
  surrounding server log lines — logs are correlated by request id.