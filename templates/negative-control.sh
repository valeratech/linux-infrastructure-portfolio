#!/usr/bin/env bash
# Proves audit-sanitize.sh can still FAIL. A gate that only ever passes is not a gate.
#
# Exists because a real bug shipped: grep omits the filename prefix when given exactly
# one file, so the field parse shifted and every pattern silently missed. The audit
# reported CLEAN on a file holding a production address and a real email — and
# single-file is precisely how pre-commit invokes it.
#
# NOTE ON CONSTRUCTION: the fixtures are ASSEMBLED at runtime, never written literally.
# A file containing a literal key header or plausible address is itself a finding, so a
# naive version of this script trips the audit, detect-private-key, and gitleaks all at
# once. Allowlisting it would blunt three gates to test one. Joining the pieces below
# keeps the committed file clean while the generated fixtures are genuinely bad.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
sp=' '
octets=(10 42 7 99)
bad_ip="$(IFS=.; printf '%s' "${octets[*]}")"
bad_domain="$(printf '%s%s%s' realcorp . com)"
bad_email="$(printf '%s@%s' admin "$bad_domain")"
dashes="$(printf -- '-%.0s' 1 2 3 4 5)"
key_header="${dashes}BEGIN RSA PRIVATE${sp}KEY${dashes}"

printf 'production host %s\ncustomer domain %s\ncontact %s\n' \
  "$bad_ip" "$bad_domain" "$bad_email" > "$TMP/bad-identifiers.txt"
printf '%s\n' "$key_header" > "$TMP/bad-keymaterial.txt"

fails=0
for f in "$TMP/bad-identifiers.txt" "$TMP/bad-keymaterial.txt"; do
  if ./scripts/audit-sanitize.sh "$f" >/dev/null 2>&1; then
    printf 'FAIL: audit passed a file it must reject: %s\n' "$(basename "$f")"; fails=1
  fi
done

# Both together — the multi-file path parses grep output differently from single-file.
if ./scripts/audit-sanitize.sh "$TMP"/bad-*.txt >/dev/null 2>&1; then
  printf 'FAIL: audit passed multi-file known-bad input\n'; fails=1
fi

# Control: a file with only approved lab values must still PASS, or the audit is
# simply rejecting everything and the tests above prove nothing.
printf 'lab server 192.168.92.10 serving site-a.lab\n' > "$TMP/good.txt"
if ! ./scripts/audit-sanitize.sh "$TMP/good.txt" >/dev/null 2>&1; then
  printf 'FAIL: audit rejected a file containing only approved lab values\n'; fails=1
fi

# ---------------------------------------------------------------------------------------
# Deny-list, pragma, and output-redaction guards. Each one exists because the condition it
# tests once passed silently (HN-004, O1/O2/O4). The deny-list is a temp file passed via
# AUDIT_DENYLIST, so the project's real deny-list is never read or touched.
# ---------------------------------------------------------------------------------------
deny_term="$(printf '%s%s' Fixture Corp)"
printf '%s\n' "$deny_term" > "$TMP/denylist"
export AUDIT_DENYLIST="$TMP/denylist"

# O1: the audit-ok pragma must NOT exempt a deny-listed term.
printf 'see %s for details  # audit-%s\n' "$deny_term" ok > "$TMP/deny-pragma.txt"
if AUDIT_REDACT=0 ./scripts/audit-sanitize.sh "$TMP/deny-pragma.txt" >/dev/null 2>&1; then
  printf 'FAIL: a deny-listed term passed because its line carried the pragma\n'; fails=1
fi

# O2: deny-list matching must be case-insensitive.
printf 'see %s for details\n' "$(tr '[:upper:]' '[:lower:]' <<<"$deny_term")" > "$TMP/deny-lower.txt"
if AUDIT_REDACT=0 ./scripts/audit-sanitize.sh "$TMP/deny-lower.txt" >/dev/null 2>&1; then
  printf 'FAIL: a deny-listed term passed in different case\n'; fails=1
fi

# Control: the pragma must still exempt pattern classes, or the fix above broke it.
printf 'pattern line %s  # audit-%s\n' "$bad_ip" ok > "$TMP/pragma-ok.txt"
if ! AUDIT_REDACT=0 ./scripts/audit-sanitize.sh "$TMP/pragma-ok.txt" >/dev/null 2>&1; then
  printf 'FAIL: the pragma no longer exempts pattern-class lines\n'; fails=1
fi

# O4: a credential value must never appear in output, even locally.
cred_val="$(printf '%s%s%s%s' Qz7 Lm4 Wp9 Rt2)"
printf 'pass%s = %s\n' word "$cred_val" > "$TMP/cred.txt"
out="$(AUDIT_REDACT=0 ./scripts/audit-sanitize.sh "$TMP/cred.txt" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then
  printf 'FAIL: credential literal was not caught\n'; fails=1
elif grep -qF -- "$cred_val" <<<"$out"; then
  printf 'FAIL: credential value was echoed in audit output\n'; fails=1
fi

# O4: under AUDIT_REDACT=1 (CI), no matched identifier may appear in output.
out="$(AUDIT_REDACT=1 ./scripts/audit-sanitize.sh "$TMP/bad-identifiers.txt" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ]; then
  printf 'FAIL: identifiers not caught under AUDIT_REDACT=1\n'; fails=1
else
  for v in "$bad_ip" "$bad_domain" "$bad_email"; do
    grep -qF -- "$v" <<<"$out" && { printf 'FAIL: a matched value was printed under AUDIT_REDACT=1\n'; fails=1; break; }
  done
fi

# B01: classes overlap, so a secret can be reported by a class that prints values. A dotted
# credential is domain-shaped, PLSK.<id> is a domain, and an @ in a credential makes an
# email. For each: the line must be caught AND the secret must not appear in the output,
# locally or under AUDIT_REDACT=1. A non-zero exit alone proves nothing about disclosure.
sec="$(printf '%s%s%s' Qz7 Lm4 Wp9)"
lic="$(printf '%s%s' QZLM WPRT)"
xdom="$(printf '%s.%s' synthetic invalidity)"   # fails the approved-domain list on purpose
printf 'pass%s=%s.%s\n' word "$sec" "$xdom"     > "$TMP/xc-dotted-cred.txt"
printf '%s.%s\n' PLSK "$lic"                       > "$TMP/xc-domain-license.txt"
printf 'tok%s=%s@%s\n' en "$sec" "$xdom"        > "$TMP/xc-email-cred.txt"
for f in "$TMP"/xc-*.txt; do
  case "$f" in *license*) v="$lic" ;; *) v="$sec" ;; esac
  for r in 0 1; do
    out="$(AUDIT_REDACT=$r ./scripts/audit-sanitize.sh "$f" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf 'FAIL: %s not caught (AUDIT_REDACT=%s)\n' "$(basename "$f")" "$r"; fails=1
    elif grep -qiF -- "$v" <<<"$out"; then
      printf 'FAIL: %s disclosed its secret through another class (AUDIT_REDACT=%s)\n' "$(basename "$f")" "$r"; fails=1
    fi
  done
done

# Control: local identifier visibility is policy, not an accident. On a line carrying no
# secret, an identifier must still print when AUDIT_REDACT=0, or redaction has overreached.
out="$(AUDIT_REDACT=0 ./scripts/audit-sanitize.sh "$TMP/bad-identifiers.txt" 2>&1)"
grep -qF -- "$bad_ip" <<<"$out" || { printf 'FAIL: identifiers no longer shown locally on non-secret lines\n'; fails=1; }

# B02: a deny-listed value can also match an identifier class that prints values — a
# deny-listed host is domain-shaped, a deny-listed address is IP-shaped. The deny-list must
# win: detected, never printed, in either mode. A separate deny-list file keeps these
# fixtures from disturbing the visibility control below.
dhost="$(printf '%s%s' fixture corp)"
dip_octets=(10 42 7 98)
dip="$(IFS=.; printf '%s' "${dip_octets[*]}")"
printf '%s\n%s\n' "$dhost" "$dip" > "$TMP/deny-overlap"
printf 'host %s.%s\n' "$dhost" "$xdom" > "$TMP/do-domain.txt"
printf 'upstream %s\n' "$dip"          > "$TMP/do-ip.txt"
for f in "$TMP"/do-*.txt; do
  case "$f" in *ip*) v="$dip" ;; *) v="$dhost" ;; esac
  for r in 0 1; do
    out="$(AUDIT_DENYLIST="$TMP/deny-overlap" AUDIT_REDACT=$r ./scripts/audit-sanitize.sh "$f" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
      printf 'FAIL: %s not caught (AUDIT_REDACT=%s)\n' "$(basename "$f")" "$r"; fails=1
    elif grep -qiF -- "$v" <<<"$out"; then
      printf 'FAIL: %s disclosed a deny-listed value through another class (AUDIT_REDACT=%s)\n' "$(basename "$f")" "$r"; fails=1
    fi
  done
done

# Control: with a deny-list loaded, an ordinary identifier that is NOT deny-listed must still
# print locally, or the deny-list redaction has overreached.
out="$(AUDIT_DENYLIST="$TMP/deny-overlap" AUDIT_REDACT=0 ./scripts/audit-sanitize.sh "$TMP/bad-identifiers.txt" 2>&1)"
grep -qF -- "$bad_ip" <<<"$out" || { printf 'FAIL: a non-deny-listed identifier was withheld locally when a deny-list was loaded\n'; fails=1; }

unset AUDIT_DENYLIST

[ "$fails" -eq 0 ] && { printf 'negative control PASS — audit rejects known-bad, accepts known-good, withholds values\n'; exit 0; }
exit 1
