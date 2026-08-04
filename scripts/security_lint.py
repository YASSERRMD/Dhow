#!/usr/bin/env python3
"""security_lint.py - source-level checks for the claims nothing else enforces.

The Phase 32 traceability table in docs/THREAT-MODEL.md found six controls that
the threat model asserts and no test or gate checks. Two of them are not worth
testing: observing a zeroized buffer means reading freed memory, and
photographing a screen is not a unit test. The other four are each a scan over a
small, well-defined surface, and this is that scan.

    1. No secret-dependent branching in dhow-crypt     (threat model row 9)
    2. No raw key bytes across the C ABI               (row 14)
    3. Every FFI entry point catches unwinds           (row 45)
    4. No networking dependency                        (row 46, via cargo deny)

The fourth is enforced by a `[bans]` denylist in deny.toml rather than here,
because cargo deny already walks the resolved dependency graph and a scan of
Cargo.toml would miss a transitive one. This script checks the denylist exists
and names the crates it is supposed to name, so the two cannot drift apart.

Exclusions are written down with the reason each one is not a finding, the way
scripts/triage.sh does. A gate that reports findings on a clean tree is a gate
people learn to ignore, and the next real one arrives unnoticed.

Usage: scripts/security_lint.py
Exits 0 when every check passes, 1 otherwise.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRYPT = ROOT / "core" / "dhow-crypt" / "src"
FFI = ROOT / "core" / "dhow-ffi" / "src"
HEADER = ROOT / "core" / "include" / "dhow.h"
DENY = ROOT / "deny.toml"

findings: list[str] = []
checks_run = 0


def report(check: str, message: str) -> None:
    findings.append(f"{check}: {message}")


# --- 1. No secret-dependent branching in dhow-crypt -------------------------

# The types that hold, or are derived from, key material. A comparison of any
# of these with == or != is a branch whose timing depends on a secret, and the
# codebase uses subtle::ConstantTimeEq for exactly this reason. The risk is not
# that today's code is wrong; it is that == compiles and reads correctly.
SECRET_TYPES = [
    "OperatorKey",
    "IdentityKey",
    "TransferKeys",
    # Renamed to TransferParameters in Phase 39, because its own doc comment
    # said neither field is secret. Kept here so the name cannot come back
    # attached to something that is.
    "TransferSecrets",
    "SessionKey",
    "PayloadKey",
]

# Names of local bindings that hold secret bytes, for the case where the
# comparison is on the bytes rather than on the wrapper.
SECRET_BINDINGS = re.compile(
    r"\b("
    r"payload_key|session_key|signing_key|secret_key|key_bytes|"
    r"expected_mac|expected_tag|expected_digest"
    r")\b"
)

# Files under dhow-crypt that are tests. A test comparing two keys for equality
# is asserting a property, not making a decision on a secret in the data path,
# and forbidding it would mean the crate could not test its own key handling.
def is_test_file(path: Path) -> bool:
    return path.name.endswith("_test.rs") or path.name == "property_test.rs"


def check_no_secret_comparisons() -> None:
    """Flags `==` and `!=` anywhere a secret is in reach.

    Two ways a secret gets compared. It is named on the line, which is the
    obvious one; or the comparison sits inside the secret type's own `impl`
    block and reads `self.bytes == other.bytes`, which names nothing. The
    second is the one that actually gets written, and the first version of this
    check missed it: replacing the `ct_eq` in `OperatorKey`'s equality with
    `==` produced no finding at all.
    """
    global checks_run
    checks_run += 1

    impl_of = re.compile(r"^\s*impl(?:<[^>]*>)?\s+(?:[\w:<>]+\s+for\s+)?(\w+)")

    for path in sorted(CRYPT.glob("*.rs")):
        if is_test_file(path):
            continue
        in_test_module = False
        current_impl: str | None = None
        depth = 0

        for number, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()

            if stripped.startswith("#[cfg(test)]"):
                in_test_module = True
            if in_test_module:
                continue

            # Track which impl block we are inside, so a comparison that names
            # nothing is still attributed to the type it belongs to.
            match = impl_of.match(line)
            if match and depth == 0:
                current_impl = match.group(1)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                depth = 0
                if not (match and depth == 0):
                    current_impl = current_impl if match else None

            if stripped.startswith("//") or stripped.startswith("///"):
                continue
            if "==" not in line and "!=" not in line:
                continue
            if stripped.startswith("#[derive"):
                continue

            named = [k for k in SECRET_TYPES if re.search(rf"\b{k}\b", line)]
            if current_impl in SECRET_TYPES and current_impl not in named:
                named.append(current_impl)

            for kind in named:
                report(
                    "secret comparison",
                    f"{path.relative_to(ROOT)}:{number}: `==` or `!=` reachable from "
                    f"{kind}; secrets are compared with subtle::ConstantTimeEq\n"
                    f"    {stripped}",
                )
            if not named and SECRET_BINDINGS.search(line):
                report(
                    "secret comparison",
                    f"{path.relative_to(ROOT)}:{number}: `==` or `!=` against a "
                    f"secret-looking binding; use subtle::ConstantTimeEq\n    {stripped}",
                )


def check_derives_on_secret_types() -> None:
    """A derived PartialEq on a secret type is a short-circuiting comparison
    that no call site has to write out to be vulnerable."""
    global checks_run
    checks_run += 1

    for path in sorted(CRYPT.glob("*.rs")):
        if is_test_file(path):
            continue
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if "PartialEq" not in line or not line.strip().startswith("#["):
                continue
            # Look at the next few lines for the type this derive applies to.
            following = " ".join(lines[number : number + 3])
            for kind in SECRET_TYPES:
                if re.search(rf"\bstruct\s+{kind}\b", following):
                    report(
                        "derived comparison",
                        f"{path.relative_to(ROOT)}:{number}: PartialEq derived on {kind}; "
                        f"the generated comparison short circuits on the first differing byte",
                    )


# --- 2. No raw key bytes across the C ABI -----------------------------------

# Arguments whose name says "key" and whose type is a byte pointer would be raw
# key material crossing the boundary. The handle design exists so that this is
# impossible; nothing checked it.
#
# Written down: the parameters below are named like keys and are not key
# material.
HEADER_KEY_EXCEPTIONS = {
    # Public halves of signing identities are public by definition; the whole
    # point of a public key is that it crosses boundaries.
    "public_key",
    "public_key_len",
}

KEY_POINTER = re.compile(
    r"(?:const\s+)?uint8_t\s*\*\s*(\w*key\w*)|"
    r"(?:const\s+)?char\s*\*\s*(\w*key\w*)|"
    r"(?:const\s+)?void\s*\*\s*(\w*key\w*)"
)


def check_no_raw_keys_in_header() -> None:
    global checks_run
    checks_run += 1

    if not HEADER.exists():
        report("raw keys", f"{HEADER} does not exist; run scripts/gen_header.sh")
        return

    for number, line in enumerate(HEADER.read_text().splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        for match in KEY_POINTER.finditer(line):
            name = next(g for g in match.groups() if g)
            if name in HEADER_KEY_EXCEPTIONS:
                continue
            # A `const char *` named like a key is a filesystem path, which is
            # how keys are actually named across this ABI.
            if "char *" in match.group(0) and ("path" in name or name.endswith("_path")):
                continue
            report(
                "raw keys",
                f"{HEADER.relative_to(ROOT)}:{number}: parameter `{name}` is a byte pointer "
                f"named like a key; key material crosses this ABI as an opaque handle\n"
                f"    {stripped}",
            )


# --- 3. Every FFI entry point catches unwinds -------------------------------

GUARDS = ("guard(", "guard_ptr(", "guard_int(", "guard_unit(")

# Written down: entry points whose whole body is a call to a helper that opens
# with a guard. The helper is named here and verified below, so the exclusion
# cannot outlive the guard it depends on.
DELEGATING = {
    "dhow_manifest_session_id": "manifest_field",
    "dhow_manifest_salt": "manifest_field",
    "dhow_manifest_nonce": "manifest_field",
}

# Written down: entry points whose bodies contain no operation that can panic.
#
# A bare allowlist would rot the moment somebody added a line, so the exclusion
# is conditional: the body must stay short and must not contain any of the
# constructs below. A guard on a function returning a constant would need a
# fourth guard variant and a wider return-type story for no benefit; a body that
# grows past this is a body that should be guarded.
TRIVIAL = {
    "dhow_abi_version": "returns a compile-time constant",
    "dhow_status_string": "matches an integer against literals, returning &'static str",
    "dhow_version_string": "returns a compile-time string literal",
}

CAN_PANIC = (
    "unwrap",
    "expect(",
    "panic!",
    "borrow()",
    "borrow_mut()",
    "[",
    "?",
    ".await",
    "assert",
    "unreachable!",
    "todo!",
)


def check_every_entry_point_guards() -> None:
    global checks_run
    checks_run += 1

    entry = re.compile(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)')

    for path in sorted(FFI.glob("*.rs")):
        if path.name.endswith("_test.rs"):
            continue
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            match = entry.search(line)
            if not match:
                continue
            name = match.group(1)

            # Find the opening brace, which may be several lines down for a
            # multi-line signature.
            brace = index
            while brace < len(lines) and "{" not in lines[brace]:
                brace += 1
            body = "\n".join(lines[brace + 1 : brace + 8])

            if any(g in body for g in GUARDS):
                continue

            trivial = TRIVIAL.get(name)
            if trivial:
                whole = whole_body(lines, brace)
                offending = [c for c in CAN_PANIC if c in whole]
                if len(whole.splitlines()) > 40 or offending:
                    report(
                        "unwind guard",
                        f"{path.relative_to(ROOT)}:{index + 1}: `{name}` is excluded as "
                        f"{trivial}, and no longer qualifies "
                        f"({'; '.join(offending) or 'the body grew past 40 lines'})",
                    )
                continue

            helper = DELEGATING.get(name)
            if helper and helper in body:
                if not helper_guards(path, helper):
                    report(
                        "unwind guard",
                        f"{name} delegates to `{helper}`, which no longer opens with a guard",
                    )
                continue

            report(
                "unwind guard",
                f"{path.relative_to(ROOT)}:{index + 1}: `{name}` does not open with a guard; "
                f"an unwind across the ABI is undefined behaviour",
            )


def whole_body(lines: list[str], brace: int) -> str:
    """Returns a function body, from its opening brace to the closing brace in
    column zero."""
    end = brace + 1
    while end < len(lines) and not lines[end].startswith("}"):
        end += 1
    return "\n".join(lines[brace + 1 : end])


def helper_guards(path: Path, helper: str) -> bool:
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if re.search(rf"\bfn\s+{helper}\b", line):
            brace = index
            while brace < len(lines) and "{" not in lines[brace]:
                brace += 1
            body = "\n".join(lines[brace + 1 : brace + 6])
            return any(g in body for g in GUARDS)
    return False


# --- 4. No networking dependency --------------------------------------------

# The master spec says CI fails the build on any dependency that opens a socket
# in the data path, and nothing did. cargo deny walks the resolved graph, which
# a scan of Cargo.toml would not, so the enforcement lives there; this checks
# the denylist exists and still names these.
BANNED_NETWORK_CRATES = [
    "tokio",
    "hyper",
    "reqwest",
    "ureq",
    "curl",
    "mio",
    "socket2",
    "tungstenite",
    "quinn",
    "rustls",
    "native-tls",
    "openssl",
]


def check_network_denylist() -> None:
    global checks_run
    checks_run += 1

    if not DENY.exists():
        report("network denylist", "deny.toml does not exist")
        return

    text = DENY.read_text()
    if "deny = [" not in text:
        report(
            "network denylist",
            "deny.toml has no [bans] deny list; nothing stops a networking crate "
            "from being added",
        )
        return

    for crate in BANNED_NETWORK_CRATES:
        if not re.search(rf'crate\s*=\s*"{re.escape(crate)}"', text):
            report(
                "network denylist",
                f"deny.toml's deny list does not name `{crate}`; "
                f"this script and the denylist have drifted apart",
            )


# --- main -------------------------------------------------------------------


def main() -> int:
    print("=== dhow security lint ===")
    print()

    check_no_secret_comparisons()
    check_derives_on_secret_types()
    check_no_raw_keys_in_header()
    check_every_entry_point_guards()
    check_network_denylist()

    if findings:
        for finding in findings:
            print(f"  FAIL  {finding}")
        print()
        print(f"{len(findings)} finding(s) across {checks_run} checks")
        return 1

    print(f"  PASS  {checks_run} checks, no findings")
    print()
    print("=== SECURITY LINT CLEAN ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
