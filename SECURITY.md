# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
suspected vulnerability. Use GitHub's **"Report a vulnerability"** (Security →
Advisories) on this repository, or contact the maintainers directly.

We aim to acknowledge a report within a few business days and will coordinate a fix
and disclosure timeline with you.

## Handling secrets

qjsync talks to Qualys and Jira with credentials and stores state in PostgreSQL.
A few rules the project enforces and asks you to follow:

- **Credentials live in the environment only** (or a local, gitignored `.env`) —
  never in `rules.yml`, never in code, never in commits. See `.env.example`.
- The shipped `.gitignore` excludes `.env`. Double-check before committing.
- Use a **scoped, least-privilege** Jira API token and a Qualys API user limited to
  the read operations the connector needs (Host List Detection + KnowledgeBase).
- Rotate any credential that may have been exposed.

## Supported versions

This project is pre-1.0; security fixes target the latest `main`. Pin a commit/tag
for production use and watch releases for advisories.

## Scope

qjsync only **reads** from Qualys and **writes work items** to Jira — it never writes
back to Qualys. State (mappings, snapshots, KB cache) is stored in a PostgreSQL
database you host and control.
