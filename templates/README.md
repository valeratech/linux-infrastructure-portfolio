# Templates

Canonical copies of the commit-gate tooling described in [../WORKFLOW.md](../WORKFLOW.md).
Because pre-commit and GitHub Actions both read config from a repo root, each project
carries its own working copy rather than referencing these.

| Template | Copy to | Then |
|---|---|---|
| `gitleaks.toml` | `<project>/.gitleaks.toml` | add rules for that domain's secret shapes |
| `pre-commit-config.yaml` | `<project>/.pre-commit-config.yaml` | `pre-commit install` |
| `audit-sanitize.sh` | `<project>/scripts/` | **retune the pattern classes to that project's leak surface** |
| `workflows/ci.yml` | `<project>/.github/workflows/ci.yml` | — |

The audit script is the one that must be retuned, not just copied. Its value is entirely
in matching the specific sensitive-data classes a given project produces: an
infrastructure lab leaks identifiers and addressing, an investigation writeup leaks
hostnames and artifact paths, a records project leaks people. Copying the pattern classes
unchanged from one project to another produces a script that runs green while missing the
things that actually leak.
