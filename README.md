# linux-infrastructure-portfolio

Index of my Linux infrastructure and platform engineering projects. Each project is a
separate repository with its own build history; this repo is the map and the shared
conventions they all follow.

All work is performed in a private VMware Workstation lab on isolated host-only
networking, using synthetic hostnames and disposable credentials. No employer or
production configuration, customer data, or real domain appears in any repository here.
See [CONVENTIONS.md](CONVENTIONS.md) for the sanitization rules this applies to every
commit.

## Projects

| Project | Focus | Status |
|---|---|---|
| [secure-nginx-apache-platform](https://github.com/valeratech/secure-nginx-apache-platform) | Hand-built nginx → Apache → PHP-FPM hosting stack; de-abstraction of a Plesk-managed architecture, with break/fix failure analysis | In progress |

<!-- Add rows as projects land. Update the link to the real repo URL once pushed. -->

## Why these exist

I administer Linux hosting infrastructure through a control panel in production. These
projects rebuild pieces of that stack by hand to examine the request paths, trust
boundaries, failure modes, and configuration decisions the panel normally abstracts
away — and to document the reasoning, not just the resulting config.

## Shared standards

- [CONVENTIONS.md](CONVENTIONS.md) — lab evidence workflow, sanitization policy, lab
  entry format, commit and snapshot naming.
- [WORKFLOW.md](WORKFLOW.md) — the gated commit pipeline: author → verify → sanitize →
  stage → commit → push → confirm CI.
- [templates/](templates/) — canonical gitleaks, pre-commit, audit, and CI configs that
  each project copies in and retunes.
