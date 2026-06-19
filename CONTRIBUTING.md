# Contributing to qjsync

Thanks for your interest in improving qjsync. This is a security-tooling project, so
correctness and clear, reviewable changes matter more than speed.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

A local PostgreSQL is only needed to run the connector end-to-end; the unit tests run
against in-memory SQLite and mock all HTTP, so they need neither Qualys, Jira, nor Postgres.

## Before you open a PR

Run the full gate locally — CI expects all three green:

```bash
ruff check .          # lint + import order
mypy                  # static types (the project is fully typed)
pytest -q             # unit tests (no live APIs)
```

Guidelines:

- **Type everything.** New code must pass `mypy` with no new ignores.
- **No live APIs in tests.** Mock HTTP with `responses` and use fixtures under `tests/fixtures/`.
- **Keep the canonical model the contract.** Sources translate to `qjsync.models.canonical`;
  everything downstream speaks only that vocabulary.
- **Don't hardcode Jira field IDs.** Fields are discovered by name at runtime.
- **Add a test for the behaviour you change** — especially around prioritisation and the lifecycle.
- **Never commit secrets.** Credentials live in the environment / a gitignored `.env`, never in `rules.yml` or code.

## Project layout

```
src/qjsync/    models · config · sources/qualys · rules · jira · state · sync · cli
docs/          architecture, field mapping, lifecycle
examples/      a realistic, commented rules.yml
tests/         pytest suite + fixtures
migrations/    Alembic schema
docker/        Dockerfile + docker-compose (app + postgres)
```

## Commit & PR conventions

- Small, focused commits with imperative subjects (`Add network-scan purge grace`).
- Describe *why*, not just *what*, in the PR body.
- Link the issue you're addressing.

## Adding a new source (WAS/Container)

Implement `qjsync.sources.base.SourceModule` once more — yield canonical
`MergedVulnerability` objects and refresh your KnowledgeBase cache. Nothing else in the
pipeline needs to change.
