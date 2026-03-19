# Contributing

## Setup

```bash
git clone https://github.com/your-org/auth.git
cd auth
pnpm install        # installs deps + sets up husky git hooks
```

Node 22 LTS is required. Use [nvm](https://github.com/nvm-sh/nvm):
```bash
nvm use             # reads .nvmrc automatically
```

## Development workflow

```bash
pnpm build          # compile TypeScript → dist/
pnpm build:watch    # recompile on save
pnpm typecheck      # type-check without emitting
pnpm lint           # lint + auto-fix
pnpm lint:check     # lint only (no fix — used in CI)
pnpm format         # prettier auto-fix
pnpm format:check   # prettier check only (used in CI)
pnpm test           # run unit tests
pnpm test:watch     # watch mode
pnpm test:cov       # tests + coverage report
pnpm ci:check       # typecheck + lint + format + test in one shot
```

## Commit messages

This repo uses [Conventional Commits](https://www.conventionalcommits.org).
Every commit message **must** follow the format:

```
<type>(<optional scope>): <subject>

[optional body]

[optional footer: BREAKING CHANGE: ...]
```

**Allowed types:**

| Type | When to use | Triggers release? |
|---|---|---|
| `feat` | New capability or API | ✅ minor |
| `fix` | Bug fix | ✅ patch |
| `perf` | Performance improvement | ✅ patch |
| `refactor` | Code restructure, no behaviour change | ✅ patch |
| `docs` | Documentation only | ❌ |
| `style` | Formatting, whitespace | ❌ |
| `test` | Adding or updating tests | ❌ |
| `chore` | Deps, build, tooling | ❌ |
| `ci` | CI/CD changes | ❌ |
| `revert` | Revert a previous commit | depends |

A `BREAKING CHANGE:` footer (or `!` after the type) always triggers a major release.

The `commit-msg` hook will reject any message that does not conform.

## Branching

| Branch | Purpose |
|---|---|
| `main` | Production — every merge triggers a release |
| `beta` | Pre-release channel — merges publish `x.y.z-beta.n` |
| `alpha` | Unstable — merges publish `x.y.z-alpha.n` |

Always branch from `main` and open a PR back to `main`.

## Adding an adapter

1. Define the port in `src/interfaces/ports/` if it doesn't exist yet.
2. Add a DI token in `src/constants/index.ts`.
3. Create `src/adapters/my-adapter.adapter.ts` implementing the port.
4. Add a default wiring in `src/core/auth.module.ts`.
5. Export from `src/adapters/index.ts` and `src/index.ts`.
6. Write unit tests in `src/adapters/my-adapter.adapter.spec.ts`.
7. Document in `src/adapters/README.md`.

## Tests

Unit tests live next to their source file as `*.spec.ts`.
Coverage thresholds are enforced: **80 % branches / functions / lines / statements**.

Mock all ports via NestJS's `overrideProvider()` — never let real crypto or
DB calls run in unit tests.

## Pull requests

- Fill in the PR template completely.
- Keep PRs focused — one concern per PR.
- `pnpm ci:check` must pass locally before opening the PR.
- The CI pipeline will enforce lint, typecheck, tests, and build.
