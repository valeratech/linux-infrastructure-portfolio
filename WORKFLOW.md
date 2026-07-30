# Commit workflow

Gated pipeline. Nothing reaches the remote until every gate is green. A failure at any
gate halts the flow until it is resolved.

```text
Author → Verify → Sanitize → Stage → Commit → Push → Confirm CI
```

Canonical tool configs live in [`templates/`](templates/) and are copied into each project
repo. They are per-repo files by necessity — pre-commit and CI both read them from the
repo root.

## 0. Redact at the source

The governing principle, and the only one that actually prevents leaks. Write clean from
the start: synthetic hostnames, lab addressing, placeholder credentials. Never write a real
value and rely on a gate to catch it. **The gates are backstops, not the control.**

## 1. Author

Two paths, because infrastructure projects have two kinds of deliverable:

**Prose, lab writeups, documentation** — authored outside the repo, delivered as an
archive:

```bash
tar czf deliverable.tar.gz path/to/file1 path/to/file2
sha256sum deliverable.tar.gz | cut -c1-16
```

**Configuration** — never hand-authored into the repo. `reference/` claims to be what is
actually running; hand-written config drifts from the box within days and the claim
silently becomes false. Config arrives by copying it off the VM:

```bash
./scripts/sync-from-lab.sh fetch    # package on VM, transfer, verify checksums, audit
./scripts/sync-from-lab.sh diff     # review against committed reference/
./scripts/sync-from-lab.sh apply
```

## 2. Extract and verify

Know the transfer path once, reuse the block forever.

- WSL/Ubuntu: `/mnt/c/Users/<user>/Downloads/`
- macOS / native Linux: `~/Downloads/`

```bash
cd ~/<repo>
git log --oneline -1                                          # know the base commit
sha256sum <download-path>/deliverable.tar.gz | cut -c1-16      # transfer integrity
tar xzf <download-path>/deliverable.tar.gz
sha256sum <extracted-files> | awk '{print substr($1,1,12),$2}' # extracted content
```

Checksums matter most on the **VM → host** hop, where a truncated log excerpt is a real
possibility and silently wrong. For markdown authored on the host they are ceremony; run
them anyway if the habit is cheaper than the exception.

## 3. Verify — content integrity

Small, rerunnable scripts that fail loud **before** staging:

```bash
./scripts/lint-labs.sh     # required sections present, prediction non-empty,
                           # status table matches files on disk, no placeholders left
./scripts/validate.sh      # (lab projects) the stack behaves as reference/ claims
shellcheck scripts/*.sh
```

## 4. Sanitize

Two complementary layers, catching different failure modes:

**a. Custom audit — tuned to this project's actual leak surface.**

```bash
./scripts/audit-sanitize.sh          # staged + tracked
./scripts/audit-sanitize.sh --all    # whole working tree
```

Matches are **classified**, not merely listed: approved lab placeholders pass silently,
and only genuinely undecided items surface. Output is `CLEAN` or a decision list.

For infrastructure projects the pattern classes are:

| Class | Why it matters here |
|---|---|
| Unapproved IPs | a stray `10.x` is what a production paste looks like |
| Unapproved domains | customer domains arrive inside panel-generated config |
| Private key material | lab CA and leaf keys must never leave the VM |
| License identifiers | panel and CloudLinux license keys |
| Credential literals | app config, htpasswd, shadow entries |
| MAC / hypervisor IDs | `.vmx`/`.vmdk` paths, adapter addresses |
| Absolute home paths | leaks host username and local layout |
| Denylisted terms | employer and customer strings, from a **gitignored** list |

`.audit-denylist` is gitignored on purpose — a committed list of things you must never
commit is itself the leak. `.audit-allow` is committed, because every approval should be
reviewable.

Exempt a single line with an inline `audit-ok` comment where the line is a detection
pattern rather than a real value.

**b. gitleaks — the secrets backstop.**

```bash
gitleaks dir . --config .gitleaks.toml --no-banner
```

gitleaks catches secret *shapes* (keys, tokens, connection strings). The custom audit
catches project-*specific* identifiers. They overlap on purpose and fail differently;
keep both.

**Binaries and screenshots are the standard blind spot** — EXIF, embedded identifiers,
and secrets visible in the frame. Images are blocked outright by hook; to include one,
strip metadata (`exiftool -all=`) and add a reviewed `.audit-allow` entry.

## 5. Stage and run local hooks

```bash
git add -A
pre-commit run --all-files
```

A failing hook blocks the commit. That is the point.

## 6. Commit

```bash
git commit -F- <<'EOF'
docs: <concise summary>

<what changed and WHY — reasoning, decisions, findings. Not just the what.>
Sensitive values are held outside the repo and are not committed.
EOF
```

Conventional prefixes for scannable history: `build:`, `lab:`, `docs:`, `config:`, `fix:`.

For lab projects the commit history is itself evidence that the build was staged — commit
at stage boundaries with messages describing the architectural change.

## 7. Push and confirm CI

```bash
git push && sleep 5
SHA=$(git log --oneline -1 | cut -d' ' -f1)
RUN=$(gh run list -L5 --json databaseId,headSha \
      -q ".[] | select(.headSha|startswith(\"$SHA\")) | .databaseId")
gh run watch "$RUN" && gh run view "$RUN" --log | grep -E 'Scanned [0-9]+ commit'
```

The SHA→run-ID pattern ties the confirmation to *this* commit's run, not a stale one.

Server-side CI is the authoritative gate. It runs gitleaks across the **full commit
history** rather than the working tree, and cannot be bypassed the way a local hook can
with `--no-verify`. The full-history scan is what catches a secret introduced in an
earlier commit and "removed" in a later one — the working tree is clean, the history is
not.

## Principles

- **Redact at the source.** Gates are backstops.
- **Four layers, different failure modes:** source discipline → custom audit → pre-commit
  hooks → CI full-history scan.
- **Verify at every hop** where content can silently change: package → transfer →
  extract → stage.
- **Scale ceremony to leak surface.** A pure-config lab with synthetic data needs less
  than a project that touches real records. Tune the audit's pattern classes rather than
  running the same ritual everywhere.
- **Never assert clean without running the check.** Verify, then state.
