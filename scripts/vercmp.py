#!/usr/bin/env python3
"""Version comparison and range matching across the ecosystems the graph covers.

One comparator serves npm semver, PEP 440, Maven, Go and RubyGems: split a version into a
numeric release tuple plus a prerelease tail, then apply semver's ordering rules. Exact
per-ecosystem semantics differ in corners nobody ships, and a shared comparator keeps the
matcher honest about what it can and cannot parse.
"""

import re

PRERELEASE_SPLIT = re.compile(r"[-+]|(?<=[0-9])(?=[A-Za-z])")
RELEASE_QUALIFIERS = {"release", "final", "ga"}


def parse_version(raw):
    """Return (release tuple, prerelease list), or None when the string is not a version."""
    if raw is None:
        return None
    v = str(raw).strip().strip("\"'")
    v = re.sub(r"^v", "", v, flags=re.I)
    v = re.sub(r"^\d+!", "", v)          # PEP 440 epoch
    v = v.split("+")[0]                   # build metadata never affects ordering
    if not v or not v[0].isdigit():
        return None
    parts = PRERELEASE_SPLIT.split(v, maxsplit=1)
    head = parts[0]
    tail = parts[1] if len(parts) > 1 else ""
    release = []
    for chunk in head.split("."):
        if chunk.isdigit():
            release.append(int(chunk))
        elif chunk:
            tail = chunk + ("." + tail if tail else "")
            break
    if not release:
        return None
    pre = []
    if tail:
        for chunk in re.split(r"[.\-_]", tail):
            if chunk:
                pre.append(int(chunk) if chunk.isdigit() else chunk.lower())
    # Maven/Spring dot-qualifiers mark a final release, not a prerelease.
    if pre and all(p in RELEASE_QUALIFIERS for p in pre):
        pre = []
    return tuple(release), pre


def cmp_version(a, b):
    ra, pa = a
    rb, pb = b
    width = max(len(ra), len(rb))
    pra = ra + (0,) * (width - len(ra))
    prb = rb + (0,) * (width - len(rb))
    if pra != prb:
        return -1 if pra < prb else 1
    # A release outranks any of its prereleases.
    if not pa and pb:
        return 1
    if pa and not pb:
        return -1
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        # Numeric identifiers sort below alphanumeric ones (semver rule 11).
        if isinstance(x, int):
            return -1
        if isinstance(y, int):
            return 1
        return -1 if x < y else 1
    if len(pa) != len(pb):
        return -1 if len(pa) < len(pb) else 1
    return 0


OPS = {
    "<=": lambda c: c <= 0,
    ">=": lambda c: c >= 0,
    "<": lambda c: c < 0,
    ">": lambda c: c > 0,
    "=": lambda c: c == 0,
    "==": lambda c: c == 0,
}


def in_range(version, spec):
    """GitHub advisory ranges are comma-separated comparators that must all hold."""
    target = parse_version(version)
    if target is None or not spec:
        return False
    for clause in str(spec).split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"^(<=|>=|==|<|>|=)?\s*(.+)$", clause)
        if not m:
            return False
        op = m.group(1) or "="
        bound = parse_version(m.group(2))
        if bound is None:
            return False
        # Advisories spell "affected since the beginning" as `>= 0`. Read literally that
        # would exclude prereleases and Go pseudo-versions, which are exactly the versions
        # untagged modules ship. Treat an all-zero lower bound as no lower bound.
        if op == ">=" and not bound[1] and not any(bound[0]):
            continue
        if not OPS[op](cmp_version(target, bound)):
            return False
    return True


def highest(versions):
    """The greatest parseable version in the list, or None."""
    best = None
    best_parsed = None
    for version in versions:
        parsed = parse_version(version)
        if parsed is None:
            continue
        if best_parsed is None or cmp_version(parsed, best_parsed) > 0:
            best, best_parsed = version, parsed
    return best


def lowest(versions):
    """The smallest parseable version in the list, or None."""
    best = best_parsed = None
    for version in versions:
        parsed = parse_version(version)
        if parsed is None:
            continue
        if best_parsed is None or cmp_version(parsed, best_parsed) < 0:
            best, best_parsed = version, parsed
    return best


RANGE_CASES = [
    ("1.2.3", ">= 1.0.0, < 2.0.0", True),
    ("2.0.0", ">= 1.0.0, < 2.0.0", False),
    ("1.0.0", ">= 1.0.0, < 2.0.0", True),
    ("0.9.9", ">= 1.0.0, < 2.0.0", False),
    ("5.131.0", ">= 2.0.0, < 5.131.1", True),
    ("5.131.1", ">= 2.0.0, < 5.131.1", False),
    ("16.2.12", ">= 16.0.0, <= 16.4.0", True),
    ("16.4.1", ">= 16.0.0, <= 16.4.0", False),
    ("7.9.3", "= 7.9.3", True),
    ("7.9.4", "= 7.9.3", False),
    ("1.4.0-beta.18", ">= 1.4.0-beta.18, < 1.7.7", True),
    ("1.4.0-beta.17", ">= 1.4.0-beta.18, < 1.7.7", False),
    ("1.7.7", ">= 1.4.0-beta.18, < 1.7.7", False),
    ("1.7.7-rc.1", ">= 1.4.0, < 1.7.7", True),
    ("3.17.0rc1", ">= 2.19.0, < 3.17.0", True),
    ("3.17.0", ">= 2.19.0, < 3.17.0", False),
    ("1.2", ">= 1.0, < 1.3", True),
    ("4.17.21", "<= 4.17.20", False),
    ("4.17.20", "<= 4.17.20", True),
    ("v1.2.3", ">= 1.0.0", True),
    ("2.0.0+build.5", "< 2.0.1", True),
    ("1.0.0.RELEASE", ">= 1.0.0", True),
    ("2.5.0.Final", ">= 2.0.0, < 2.6.0", True),
    ("1.2.3-SNAPSHOT", "< 1.2.3", True),
    ("main", ">= 1.0.0", False),
    ("latest", "< 9.9.9", False),
    ("", ">= 1.0.0", False),
    ("1.9.0", "> 1.8.0, < 1.10.0", True),
    ("1.10.0", "< 1.9.0", False),
    ("2.19.0", ">= 2.19.0, < 3.17.0", True),
    ("0.0.0-20210101000000-abcdef123456", ">= 0.0.0, < 1.0.0", True),
]

ORDER_CASES = [
    ("1.0.0-alpha", "1.0.0"),
    ("1.0.0", "1.0.1"),
    ("1.9.0", "1.10.0"),
    ("1.0.0-alpha.1", "1.0.0-alpha.2"),
    ("1.0.0-alpha.1", "1.0.0-beta"),
    ("2.0.0rc1", "2.0.0"),
    ("1.2.3", "1.2.3.1"),
    ("1.0.0-rc.1", "1.0.0-rc.2"),
]


NODE_LINE = re.compile(r"^\^?(\d+)\.x$")


def node_patched_lines(patched):
    """`^22.23.2 || ^24.18.1` -> {22: parsed 22.23.2, 24: parsed 24.18.1}.

    Node states each fix as one caret range per release line, so the caret's major names
    the line and its version is where that line stopped being affected.
    """
    lines = {}
    for part in str(patched or "").split("||"):
        parsed = parse_version(part.strip().lstrip("^~>=< "))
        if parsed and parsed[0]:
            lines[parsed[0][0]] = parsed
    return lines


def node_affected(version, vulnerable, patched):
    """Is this Node runtime inside a core advisory's affected range?

    The Node security database is almost entirely `22.x || 24.x` for the affected lines
    plus one caret range per line for the fix, so the fix decides: a line with a stated
    fix is affected below it, and a line named vulnerable with no fix has none yet. The
    handful of entries written as plain comparators fall through to in_range.
    """
    target = parse_version(version)
    if target is None or not target[0]:
        return False
    major = target[0][0]
    fixes = node_patched_lines(patched)
    if major in fixes:
        return cmp_version(target, fixes[major]) < 0
    for part in str(vulnerable or "").split("||"):
        part = part.strip()
        if not part:
            continue
        line = NODE_LINE.match(part)
        if line:
            if int(line.group(1)) == major:
                return True
            continue
        # `>=10.0.0 <10.19.0` is one range written with spaces, not two clauses.
        if in_range(version, re.sub(r"\s+(?=[<>=^~\d])", ", ", part)):
            return True
    return False


NODE_CASES = [
    # (installed, vulnerable, patched, expected)
    ("22.22.2", "22.x || 24.x || 26.x", "^22.23.2 || ^24.18.1 || ^26.5.1", True),
    ("22.23.2", "22.x || 24.x || 26.x", "^22.23.2 || ^24.18.1 || ^26.5.1", False),
    ("22.24.0", "22.x || 24.x || 26.x", "^22.23.2 || ^24.18.1 || ^26.5.1", False),
    ("24.18.0", "22.x || 24.x || 26.x", "^22.23.2 || ^24.18.1 || ^26.5.1", True),
    ("24.18.1", "22.x || 24.x || 26.x", "^22.23.2 || ^24.18.1 || ^26.5.1", False),
    # A release line the advisory never names is not affected.
    ("20.19.5", "22.x || 24.x", "^22.23.2 || ^24.18.1", False),
    # Named vulnerable with no fix for that line yet.
    ("18.4.0", "18.x || 22.x", "^22.23.2", True),
    # The rare comparator form.
    ("10.5.0", ">=10.0.0 <10.19.0", "^10.19.0", True),
    ("10.19.0", ">=10.0.0 <10.19.0", "^10.19.0", False),
    ("v22.22.2", "22.x", "^22.23.2", True),
    ("", "22.x", "^22.23.2", False),
    ("not-a-version", "22.x", "^22.23.2", False),
]


def selftest():
    failures = []
    for version, spec, expected in RANGE_CASES:
        actual = in_range(version, spec)
        if actual != expected:
            failures.append(f"  in_range({version!r}, {spec!r}) = {actual}, want {expected}")
    for lower, higher in ORDER_CASES:
        low, high = parse_version(lower), parse_version(higher)
        if low is None or high is None or cmp_version(low, high) >= 0:
            failures.append(f"  expected {lower} < {higher}")
    if highest(["1.2.3", "1.10.0", "main", "1.9.9"]) != "1.10.0":
        failures.append("  highest() picked the wrong version")
    for version, vulnerable, patched, expected in NODE_CASES:
        actual = node_affected(version, vulnerable, patched)
        if actual != expected:
            failures.append(f"  node_affected({version!r}, {vulnerable!r}, {patched!r}) "
                            f"= {actual}, want {expected}")
    if failures:
        print(f"vercmp selftest FAILED ({len(failures)})")
        print("\n".join(failures))
        return 1
    print(f"vercmp selftest ok: {len(RANGE_CASES)} range cases, "
          f"{len(ORDER_CASES)} ordering cases, {len(NODE_CASES)} node-runtime cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
