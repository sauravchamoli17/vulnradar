#!/usr/bin/env python3
"""Build a tech-stack + dependency graph of everything on this machine.

Read-only. Never installs, never runs a package script.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

PRUNE = {
    "node_modules", ".git", ".hg", ".svn", "Library", ".cache", ".npm", ".pnpm-store",
    ".bun", ".yarn", "venv", ".venv", "env", ".env.d", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "dist", "build", ".next", ".nuxt", ".svelte-kit",
    ".turbo", ".serverless", ".terraform", ".gradle", ".m2", ".rustup", ".cargo",
    "DerivedData", "Pods", "Carthage", ".Trash", "Trash", ".local", ".rbenv", ".nvm",
    ".pyenv", ".vscode", ".idea", "vendor", "site-packages", "coverage", ".gstack",
    "Applications", "Pictures", "Movies", "Music", ".docker", ".colima", ".orbstack",
}

# Lockfiles win over manifests: they carry resolved versions.
LOCKFILES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb",
    "npm-shrinkwrap.json", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock",
    "go.sum", "Gemfile.lock", "composer.lock", "pubspec.lock", "gradle.lockfile",
    "Package.resolved", "mix.lock",
}
MANIFESTS = {
    "package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "setup.py", "Pipfile", "go.mod", "Cargo.toml", "Gemfile", "composer.json",
    "pom.xml", "build.gradle", "build.gradle.kts", "pubspec.yaml", "mix.exs",
    "Dockerfile", ".nvmrc", ".node-version", ".python-version", ".ruby-version",
    ".tool-versions",
}
INTEREST = LOCKFILES | MANIFESTS
MAX_FILE = 24 * 1024 * 1024


def read(path, limit=MAX_FILE):
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def load_json(path):
    text = read(path)
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        # bun.lock and some tool output are JSONC: strip comments and trailing commas.
        stripped = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        stripped = re.sub(r"(^|\s)//[^\n]*", "", stripped)
        stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
        try:
            return json.loads(stripped)
        except ValueError:
            return None


def load_toml(path):
    if tomllib is None:
        return None
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, ValueError):
        return None


def clean_version(raw):
    if not raw:
        return None
    v = str(raw).strip().strip("\"'")
    v = re.sub(r"^(?:[\^~><=!]+|v)\s*", "", v)
    v = v.split(" ")[0].split(",")[0]
    v = re.sub(r"[()\[\]]", "", v)
    return v or None


def is_exact(raw):
    """True when a declared range pins one version, so matching can be trusted."""
    if raw is None:
        return False
    return bool(re.fullmatch(r"\s*=?\s*v?\d+(\.\d+)*(?:[-+][0-9A-Za-z.\-+]+)?\s*", str(raw)))


class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self._seen_edges = set()

    def node(self, nid, **attrs):
        existing = self.nodes.get(nid)
        if existing is None:
            self.nodes[nid] = dict(id=nid, **attrs)
        else:
            for key, value in attrs.items():
                if value is not None and existing.get(key) in (None, "", [], {}):
                    existing[key] = value
        return nid

    def edge(self, src, dst, rel, **attrs):
        key = (src, dst, rel)
        if key in self._seen_edges:
            return
        self._seen_edges.add(key)
        self.edges.append(dict(source=src, target=dst, rel=rel, **attrs))

    def pkg(self, ecosystem, name, version, *, resolved=True, declared=None):
        name = name.strip()
        version = clean_version(version)
        if not name or not version:
            return None
        nid = f"pkg:{ecosystem}:{name}@{version}"
        return self.node(
            nid, kind="package", ecosystem=ecosystem, name=name, version=version,
            resolved=resolved, declared=declared,
        )


def npm_name_from_path(path):
    """node_modules/a/node_modules/@scope/b -> @scope/b"""
    if "node_modules/" not in path:
        return None
    return path.rsplit("node_modules/", 1)[1] or None


def parse_package_lock(path, graph, proj):
    data = load_json(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    packages = data.get("packages")
    if isinstance(packages, dict):
        for loc, meta in packages.items():
            if not loc or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or npm_name_from_path(loc)
            if not name:
                continue
            nid = graph.pkg("npm", name, meta.get("version"))
            if nid:
                graph.edge(proj, nid, "dev" if meta.get("dev") else "depends_on",
                           direct=loc.count("node_modules/") == 1)
                count += 1
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        def walk(tree, dev):
            nonlocal count
            for name, meta in tree.items():
                if not isinstance(meta, dict):
                    continue
                nid = graph.pkg("npm", name, meta.get("version"))
                if nid:
                    graph.edge(proj, nid, "dev" if (dev or meta.get("dev")) else "depends_on")
                    count += 1
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"], dev or bool(meta.get("dev")))
        walk(deps, False)
    return count


PNPM_KEY = re.compile(r"^\s{2,4}'?(/?)((?:@[^/@\s']+/)?[^@\s'/][^@\s']*)@([0-9][^(\s':]*)'?:")


def parse_pnpm_lock(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    section = None
    for line in text.splitlines():
        if re.match(r"^[a-zA-Z]", line):
            section = line.split(":")[0]
            continue
        if section not in ("packages", "snapshots"):
            continue
        m = PNPM_KEY.match(line)
        if m:
            nid = graph.pkg("npm", m.group(2), m.group(3))
            if nid:
                graph.edge(proj, nid, "depends_on")
                count += 1
    return count


def parse_yarn_lock(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    headers = []
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            headers = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip("\"'")
                spec = re.sub(r"@(?:npm:|workspace:)?[^@]*$", "", spec) if spec.count("@") else spec
                if spec:
                    headers.append(spec)
            continue
        m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
        if m and headers:
            for name in headers:
                nid = graph.pkg("npm", name, m.group(1))
                if nid:
                    graph.edge(proj, nid, "depends_on")
                    count += 1
            headers = []
    return count


def parse_bun_lock(path, graph, proj):
    data = load_json(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    packages = data.get("packages")
    if isinstance(packages, dict):
        for name, meta in packages.items():
            spec = meta[0] if isinstance(meta, list) and meta else meta
            version = None
            if isinstance(spec, str) and "@" in spec:
                version = spec.rsplit("@", 1)[1]
            elif isinstance(spec, dict):
                version = spec.get("version")
            nid = graph.pkg("npm", name.rsplit("/", 1)[-1] if name.count("/") > 1 else name, version)
            if nid:
                graph.edge(proj, nid, "depends_on")
                count += 1
    return count


def parse_package_json(path, graph, proj, has_lock):
    data = load_json(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    for field, rel in (("dependencies", "depends_on"), ("devDependencies", "dev"),
                       ("optionalDependencies", "depends_on"), ("peerDependencies", "peer")):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str) or re.match(r"^(file:|link:|workspace:|git|https?:)", spec):
                continue
            # With a lockfile present the resolved versions are already in the graph;
            # only record declared ranges that the lockfile cannot supply.
            if has_lock and not is_exact(spec):
                continue
            nid = graph.pkg("npm", name, spec, resolved=is_exact(spec), declared=spec)
            if nid:
                graph.edge(proj, nid, rel, direct=True)
                count += 1
    engines = data.get("engines")
    if isinstance(engines, dict):
        for runtime, spec in engines.items():
            version = clean_version(spec)
            if version:
                nid = graph.node(f"rt:{runtime}@{version}", kind="runtime", name=runtime,
                                 version=version, ecosystem="runtime", source="engines")
                graph.edge(proj, nid, "runs_on")
    return count


def parse_requirements(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*==\s*([^\s;]+)", line)
        if not m:
            continue
        nid = graph.pkg("pip", m.group(1).split("[")[0], m.group(2))
        if nid:
            graph.edge(proj, nid, "depends_on", direct=True)
            count += 1
    return count


def parse_poetry_uv_lock(path, graph, proj):
    data = load_toml(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    for entry in data.get("package", []) or []:
        if not isinstance(entry, dict):
            continue
        nid = graph.pkg("pip", entry.get("name", ""), entry.get("version"))
        if nid:
            dev = str(entry.get("category", "")).lower() == "dev"
            graph.edge(proj, nid, "dev" if dev else "depends_on")
            count += 1
    return count


def parse_pipfile_lock(path, graph, proj):
    data = load_json(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    for section, rel in (("default", "depends_on"), ("develop", "dev")):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            version = meta.get("version") if isinstance(meta, dict) else None
            nid = graph.pkg("pip", name, version)
            if nid:
                graph.edge(proj, nid, rel)
                count += 1
    return count


def parse_cargo_lock(path, graph, proj):
    data = load_toml(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    for entry in data.get("package", []) or []:
        nid = graph.pkg("rust", entry.get("name", ""), entry.get("version"))
        if nid:
            graph.edge(proj, nid, "depends_on")
            count += 1
    return count


def parse_go_mod(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    in_block = False
    for line in text.splitlines():
        line = line.split("//")[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        spec = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        m = re.match(r"^([^\s]+)\s+(v[^\s]+)$", spec.strip())
        if m:
            nid = graph.pkg("go", m.group(1), m.group(2))
            if nid:
                graph.edge(proj, nid, "depends_on", direct=True)
                count += 1
    return count


def parse_gemfile_lock(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    in_specs = False
    for line in text.splitlines():
        if re.match(r"^\s{2}specs:", line):
            in_specs = True
            continue
        if line and not line[0].isspace():
            in_specs = False
            continue
        if not in_specs:
            continue
        m = re.match(r"^\s{4}([A-Za-z0-9._\-]+) \(([^)=<>~]+)\)$", line)
        if m:
            nid = graph.pkg("rubygems", m.group(1), m.group(2))
            if nid:
                graph.edge(proj, nid, "depends_on")
                count += 1
    return count


def parse_composer_lock(path, graph, proj):
    data = load_json(path)
    if not isinstance(data, dict):
        return 0
    count = 0
    for section, rel in (("packages", "depends_on"), ("packages-dev", "dev")):
        for entry in data.get(section, []) or []:
            if not isinstance(entry, dict):
                continue
            nid = graph.pkg("composer", entry.get("name", ""), entry.get("version"))
            if nid:
                graph.edge(proj, nid, rel)
                count += 1
    return count


def parse_pom(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return 0
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    props = {}
    for prop in root.findall("./m:properties/*", ns) + root.findall("./properties/*"):
        props[re.sub(r"\{.*\}", "", prop.tag)] = (prop.text or "").strip()
    count = 0
    for dep in root.iter():
        if re.sub(r"\{.*\}", "", dep.tag) != "dependency":
            continue
        fields = {re.sub(r"\{.*\}", "", c.tag): (c.text or "").strip() for c in dep}
        version = fields.get("version", "")
        m = re.fullmatch(r"\$\{([^}]+)\}", version)
        if m:
            version = props.get(m.group(1), "")
        name = f"{fields.get('groupId','')}:{fields.get('artifactId','')}"
        nid = graph.pkg("maven", name, version)
        if nid:
            rel = "dev" if fields.get("scope") in ("test", "provided") else "depends_on"
            graph.edge(proj, nid, rel, direct=True)
            count += 1
    return count


def parse_pubspec_lock(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    name = None
    for line in text.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'^\s+version:\s*"?([^"\s]+)"?', line)
        if m and name:
            nid = graph.pkg("pub", name, m.group(1))
            if nid:
                graph.edge(proj, nid, "depends_on")
                count += 1
            name = None
    return count


def parse_dockerfile(path, graph, proj):
    text = read(path)
    if not text:
        return 0
    count = 0
    for line in text.splitlines():
        m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", line, re.I)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("$") or ref.lower() == "scratch":
            continue
        image, _, tag = ref.partition(":")
        tag = (tag or "latest").split("@")[0]
        nid = graph.node(f"img:{image}:{tag}", kind="image", name=image, version=tag,
                         ecosystem="container")
        graph.edge(proj, nid, "runs_on")
        count += 1
    return count


def parse_workflows(project_dir, graph, proj):
    wf_dir = project_dir / ".github" / "workflows"
    if not wf_dir.is_dir():
        return 0
    count = 0
    for wf in list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")):
        text = read(wf)
        if not text:
            continue
        for m in re.finditer(r"uses:\s*[\"']?([A-Za-z0-9._\-]+/[A-Za-z0-9._\-/]+)@([^\s\"']+)", text):
            nid = graph.pkg("actions", m.group(1), m.group(2))
            if nid:
                graph.edge(proj, nid, "ci_uses")
                count += 1
    return count


def parse_runtime_pin(path, graph, proj):
    text = read(path, limit=4096)
    if not text:
        return 0
    name = {".nvmrc": "node", ".node-version": "node", ".python-version": "python",
            ".ruby-version": "ruby"}.get(path.name)
    if name:
        version = clean_version(text.splitlines()[0] if text.splitlines() else None)
        if version:
            nid = graph.node(f"rt:{name}@{version}", kind="runtime", name=name, version=version,
                             ecosystem="runtime", source=path.name)
            graph.edge(proj, nid, "runs_on")
        return 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            nid = graph.node(f"rt:{parts[0]}@{parts[1]}", kind="runtime", name=parts[0],
                             version=parts[1], ecosystem="runtime", source=".tool-versions")
            graph.edge(proj, nid, "runs_on")
    return 0


PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "bun.lock": parse_bun_lock,
    "requirements.txt": parse_requirements,
    "requirements-dev.txt": parse_requirements,
    "poetry.lock": parse_poetry_uv_lock,
    "uv.lock": parse_poetry_uv_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.lock": parse_composer_lock,
    "pom.xml": parse_pom,
    "pubspec.lock": parse_pubspec_lock,
    "Dockerfile": parse_dockerfile,
    ".nvmrc": parse_runtime_pin,
    ".node-version": parse_runtime_pin,
    ".python-version": parse_runtime_pin,
    ".ruby-version": parse_runtime_pin,
    ".tool-versions": parse_runtime_pin,
}


def discover(roots, max_depth, skip_hidden=True):
    """Group interesting files by the directory that owns them."""
    found = {}
    for root in roots:
        root = Path(root).expanduser().resolve()
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            here = Path(dirpath)
            depth = len(here.parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [
                d for d in dirnames
                if d not in PRUNE
                and not (skip_hidden and d.startswith(".") and d not in (".github",))
            ]
            hits = [f for f in filenames if f in INTEREST]
            if hits:
                found.setdefault(str(here), []).append(hits)
    return {d: sorted({f for group in groups for f in group}) for d, groups in found.items()}


def git_meta(directory):
    def run(args):
        try:
            out = subprocess.run(["git", "-C", directory] + args, capture_output=True,
                                 text=True, timeout=10)
            return out.stdout.strip() if out.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None
    if not run(["rev-parse", "--is-inside-work-tree"]):
        return {}
    return {
        "git_last_commit": run(["log", "-1", "--format=%cI"]),
        "git_branch": run(["rev-parse", "--abbrev-ref", "HEAD"]),
        "git_remote": run(["remote", "get-url", "origin"]),
    }


def days_since(iso):
    if not iso:
        return None
    try:
        stamp = time.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return int((time.time() - time.mktime(stamp)) / 86400)


def add_host_layer(graph, include_casks=True):
    host = graph.node("host", kind="host", name=os.uname().nodename, ecosystem="host")

    def sh(args, timeout=60):
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return out.stdout if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    product = sh(["sw_vers", "-productName"]).strip()
    version = sh(["sw_vers", "-productVersion"]).strip()
    if version:
        nid = graph.node(f"os:{product or 'macOS'}@{version}", kind="os",
                         name=product or "macOS", version=version, ecosystem="host")
        graph.edge(host, nid, "runs_on")

    for runtime, args, pattern in (
        ("node", ["node", "-v"], r"v?([0-9][^\s]*)"),
        ("python", ["python3", "-V"], r"([0-9][^\s]*)"),
        ("bun", ["bun", "-v"], r"([0-9][^\s]*)"),
        ("go", ["go", "version"], r"go([0-9][^\s]*)"),
        ("ruby", ["ruby", "-v"], r"ruby ([0-9][^\s]*)"),
        ("java", ["java", "-version"], r'"([0-9][^"]*)"'),
    ):
        m = re.search(pattern, sh(args) or "")
        if m:
            nid = graph.node(f"rt:{runtime}@{m.group(1)}", kind="runtime", name=runtime,
                             version=m.group(1), ecosystem="runtime", source="installed")
            graph.edge(host, nid, "runs_on")

    for flag, mgr in ((["--formula"], "brew"), (["--cask"], "brew-cask")):
        if mgr == "brew-cask" and not include_casks:
            continue
        for line in sh(["brew", "list"] + flag + ["--versions"]).splitlines():
            parts = line.split()
            if len(parts) >= 2:
                nid = graph.node(f"hostpkg:{mgr}:{parts[0]}@{parts[1]}", kind="host_package",
                                 name=parts[0], version=parts[1], ecosystem="host",
                                 manager=mgr)
                graph.edge(host, nid, "installed")

    images = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=30)
    for line in images.splitlines():
        if ":" not in line or line.startswith("<none>"):
            continue
        image, _, tag = line.partition(":")
        nid = graph.node(f"img:{image}:{tag}", kind="image", name=image, version=tag,
                         ecosystem="container", local=True)
        graph.edge(host, nid, "installed")
    return host


def main():
    ap = argparse.ArgumentParser(description="Build a machine dependency graph")
    ap.add_argument("--roots", nargs="*", default=[str(Path.home())])
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-host", action="store_true")
    ap.add_argument("--include-hidden", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    graph = Graph()
    host = None if args.no_host else add_host_layer(graph)
    if host is None:
        host = graph.node("host", kind="host", name=os.uname().nodename, ecosystem="host")

    discovered = discover(args.roots, args.depth, skip_hidden=not args.include_hidden)
    project_dirs = sorted(discovered)
    skipped_binary = []

    for directory in project_dirs:
        files = discovered[directory]
        path = Path(directory)
        locks = [f for f in files if f in LOCKFILES]
        if "bun.lockb" in locks:
            skipped_binary.append(str(path / "bun.lockb"))
        meta = git_meta(directory)
        proj = graph.node(
            f"proj:{directory}", kind="project", name=path.name, path=directory,
            ecosystem="project", manifests=files, has_lockfile=bool(locks),
            stale_days=days_since(meta.get("git_last_commit")), **meta,
        )
        graph.edge(host, proj, "contains")
        has_lock = any(f in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
                             "npm-shrinkwrap.json") for f in files)
        for fname in files:
            if fname == "package.json":
                parse_package_json(path / fname, graph, proj, has_lock)
                continue
            parser = PARSERS.get(fname)
            if parser:
                try:
                    parser(path / fname, graph, proj)
                except Exception as exc:  # a malformed lockfile must not abort the sweep
                    graph.nodes[proj].setdefault("parse_errors", []).append(f"{fname}: {exc}")
        parse_workflows(path, graph, proj)

    kinds = {}
    ecosystems = {}
    for node in graph.nodes.values():
        kinds[node["kind"]] = kinds.get(node["kind"], 0) + 1
        if node["kind"] == "package":
            ecosystems[node["ecosystem"]] = ecosystems.get(node["ecosystem"], 0) + 1

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roots": [str(Path(r).expanduser().resolve()) for r in args.roots],
        "depth": args.depth,
        "stats": {
            "nodes": len(graph.nodes), "edges": len(graph.edges),
            "projects": kinds.get("project", 0), "packages": kinds.get("package", 0),
            "by_kind": kinds, "by_ecosystem": ecosystems,
            "skipped_binary_lockfiles": skipped_binary,
        },
        "nodes": list(graph.nodes.values()),
        "edges": graph.edges,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload), encoding="utf-8")

    if not args.quiet:
        eco = ", ".join(f"{k}={v}" for k, v in sorted(ecosystems.items(), key=lambda x: -x[1]))
        print(f"graph: {len(graph.nodes)} nodes / {len(graph.edges)} edges")
        print(f"projects: {kinds.get('project', 0)}  packages: {kinds.get('package', 0)}")
        print(f"ecosystems: {eco or 'none'}")
        if skipped_binary:
            print(f"note: {len(skipped_binary)} binary bun.lockb file(s) unreadable "
                  f"(run `bun install --save-text-lockfile` to get a parseable lock)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
