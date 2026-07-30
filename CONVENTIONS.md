# Conventions

Standards shared across every project in this portfolio.

## Method: predict, then verify

Before introducing any deliberate fault, the prediction is written down first — what the
client will see, which component will generate the response, which log will hold the
first useful evidence, and whether the failure will be immediate, queued, or
timeout-driven.

The prediction is committed **as written**, including when it turns out to be wrong. A
corrected prediction is worthless; an incorrect prediction next to the observed result is
the entire point. Wrong predictions get a "corrected model" section, not an edit.

## Repository layout

Each project follows the same shape:

```text
README.md            purpose, safety boundaries, current state
SCOPE.md             locked release scope; what is explicitly deferred
ENVIRONMENT.md       lab topology, VM sizing, addressing, snapshot names
lab/                 break/fix entries, one file per exercise
reference/           the clean, authoritative final configuration
scripts/             validation and evidence-capture tooling
```

`reference/` is prescriptive and clean. `lab/` contains visible mistakes. They are kept
structurally separate so the mistakes do not make the reference look uncertain, and the
reference does not make the lab look sanitized.

Architecture documents, threat models, and diagrams are **derived at the end** from what
was actually built. They are not written up front, because an architecture document
written before the build describes a system that never quite gets built.

## Lab entry format

Every entry in `lab/` uses `lab/TEMPLATE.md`: expected behavior, deliberate fault,
prediction, actual result, investigation path, root cause, remediation, verification,
lesson. The polished entry is derived from raw captured evidence — never reconstructed
from memory.

## Evidence workflow

Raw evidence is captured live, into a working directory that is **not** committed:

```text
evidence-working/<lab-id>/
├── prediction.txt
├── terminal.log          (script --timing, or asciinema)
├── <service>-access.log
├── <service>-error.log
├── journal.log
├── ss-before.txt
├── ss-during.txt
└── notes.md
```

`evidence-working/` is gitignored. Excerpts are sanitized before they enter a lab entry.

## Sanitization policy

Nothing derived from an employer or production system enters any repository here. Before
any evidence excerpt is committed, remove or replace:

- real hostnames and domains (use `site-a.lab`, `site-b.lab`)
- public IP addresses
- customer names, subscription names, internal path layouts, naming conventions
- usernames and absolute home paths
- MAC addresses and VMware identifiers
- license or subscription identifiers
- private keys and CA state, in any form
- shell history containing unrelated activity

Private lab RFC1918 addresses may be published or masked, but the choice is applied
consistently within a project.

## Snapshots

Snapshot names match build-stage boundaries, not individual config edits:

```text
NN-<stage-description>-clean
```

Architectural stage snapshots are taken powered off for consistency. Snapshots of
pathological runtime states (pool saturation, memory pressure) are taken with the VM
running so that reverting restores that exact condition.

Each exercise runs: revert to clean stage → start capture → record prediction →
introduce one fault → generate traffic → collect evidence → revert.

One fault at a time. Compound faults produce uninterpretable evidence.

## Commits

The commit history is evidence that the build was staged. Commit at each stage boundary
with a message describing the architectural change, not the file touched:

```text
build Apache single-vhost baseline
document Apache default-vhost selection failure
move Apache to loopback backend
place nginx reverse proxy at public edge
restore trusted client IP logging for RFC1918 lab clients
```

A lab entry is committed only after raw evidence is collected, sensitive content is
scrubbed, the write-up matches the actual observed result, and the clean reference
configuration has been restored.

## Sources

Primary sources only: upstream project documentation (httpd, nginx, PHP), distribution
packaging docs, man pages, and Mozilla TLS guidance. Blog posts are secondary context.

For any directive copied from anywhere, confirm before committing it: it applies to the
installed version, its inheritance context is understood, its default behavior is known,
its presence can be explained, and a test exists that would fail if it were removed.
