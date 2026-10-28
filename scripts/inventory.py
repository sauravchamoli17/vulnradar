#!/usr/bin/env python3
"""Build a tech-stack + dependency graph of everything on this machine.

Read-only. Never installs, never runs a package script.
"""

import argparse
import fnmatch
import json
import os
import pathlib
import re
import shutil
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


# Patterns that are genuinely alarming inside a package lifecycle hook. Kept tight on
# purpose: a postinstall that runs `node scripts/build.js` is ordinary, and a scanner
# that cries wolf gets ignored.
RISKY_SCRIPT_PATTERNS = [
    (re.compile(r"(curl|wget)\b[^|;&]*\|\s*(ba)?sh", re.I),
     "downloads a script and pipes it straight into a shell"),
    (re.compile(r"\beval\s*\(\s*(atob|Buffer\.from|require\(['\"]zlib)", re.I),
     "evaluates decoded or decompressed data at runtime"),
    (re.compile(r"base64\s+(-d|--decode)", re.I),
     "decodes base64 inline during install"),
    (re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}", re.I),
     "contacts a bare IP address rather than a hostname"),
    (re.compile(r"\.onion\b", re.I), "contacts a Tor hidden service"),
    (re.compile(r">\s*/dev/tcp/", re.I), "opens a raw TCP socket from the shell"),
    (re.compile(r"\bnode\s+-e\b[^\n]*(child_process|exec)[^\n]*"
                r"(fetch|https?:|atob|Buffer\.from)", re.I),
     "inline one-liner that spawns a process and fetches or decodes data"),
    (re.compile(r"process\.env[^\n]{0,80}(fetch|https?\.request|curl)", re.I),
     "reads environment variables next to a network call"),
]
LIFECYCLE_HOOKS = {"preinstall", "install", "postinstall", "prepare", "prepublish",
                   "preprepare", "postprepare"}


NPM_FILES = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
             "bun.lock", "bun.lockb", "npm-shrinkwrap.json"}
# Only ecosystems that install into the project answer "is the code here?". Go, Maven,
# Cargo, RubyGems and a default pip resolve into shared caches, so a missing directory
# proves nothing and they stay unknown rather than being called clean.
INSTALL_DIRS = [
    (NPM_FILES, ("node_modules",)),
    ({"composer.json", "composer.lock"}, ("vendor",)),
    ({"Gemfile", "Gemfile.lock"}, ("vendor/bundle",)),
]


def install_state(directory, files):
    """Is the dependency tree materialised on this machine, or only pinned in a lockfile?"""
    path = Path(directory)
    known = False
    for markers, dirs in INSTALL_DIRS:
        if not markers & set(files):
            continue
        known = True
        for d in dirs:
            if (path / d).is_dir():
                return {"known": True, "present": True, "where": d}
    return {"known": known, "present": False}


def build_policy(directory, files):
    """Can a dependency execute code at install time here, and which ones?

    This matters more than a raw list: pnpm 10 blocks dependency build scripts unless
    they are allowlisted, and npm honours ignore-scripts, so a project can be immune
    to install-time payloads regardless of what its dependencies declare.
    """
    path = Path(directory)
    npmrc = read(path / ".npmrc", limit=64 * 1024) or ""
    if re.search(r"^\s*ignore-scripts\s*=\s*true", npmrc, re.M | re.I):
        return {"blocked": True, "manager": "npm",
                "why": "ignore-scripts=true in .npmrc"}

    manifest = load_json(path / "package.json") if "package.json" in files else None
    manifest = manifest if isinstance(manifest, dict) else {}

    if "pnpm-lock.yaml" in files:
        m = re.match(r"pnpm@(\d+)", str(manifest.get("packageManager") or ""))
        major = int(m.group(1)) if m else None
        allowed = ((manifest.get("pnpm") or {}).get("onlyBuiltDependencies")) or []
        if major and major >= 10:
            if allowed:
                return {"blocked": False, "manager": f"pnpm {major}",
                        "allowed": sorted(allowed),
                        "why": f"pnpm {major} runs install scripts only for the "
                               "allowlisted packages"}
            return {"blocked": True, "manager": f"pnpm {major}",
                    "why": f"pnpm {major} blocks dependency install scripts unless "
                           "allowlisted, and this project has no allowlist"}
        return {"blocked": False, "manager": f"pnpm {major or '<10'}",
                "why": "install scripts run; this lockfile format does not record "
                       "which packages have them"}

    if "package-lock.json" in files or "npm-shrinkwrap.json" in files:
        return {"blocked": False, "manager": "npm",
                "why": "npm runs dependency install scripts by default"}
    return None


def scan_scripts(manifest):
    """Lifecycle hooks are where supply-chain payloads fire; read them, judge narrowly."""
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return []
    found = []
    for hook, command in scripts.items():
        if hook not in LIFECYCLE_HOOKS or not isinstance(command, str):
            continue
        for pattern, reason in RISKY_SCRIPT_PATTERNS:
            if pattern.search(command):
                found.append({"hook": hook, "command": command[:300], "why": reason})
                break
    return found


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
                if meta.get("hasInstallScript"):
                    graph.nodes[proj].setdefault("install_script_packages", [])
                    entry = f"{name}@{clean_version(meta.get('version')) or '?'}"
                    if entry not in graph.nodes[proj]["install_script_packages"]:
                        graph.nodes[proj]["install_script_packages"].append(entry)
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
    current = None
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
                current = f"{m.group(2)}@{m.group(3)}"
                count += 1
            continue
        # pnpm < 9 recorded this; pnpm 9+ dropped it and gates builds by policy instead.
        if current and re.match(r"\s+requiresBuild:\s*true", line):
            graph.nodes[proj].setdefault("install_script_packages", [])
            if current not in graph.nodes[proj]["install_script_packages"]:
                graph.nodes[proj]["install_script_packages"].append(current)
            current = None
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
    risky = scan_scripts(data)
    if risky:
        graph.nodes[proj]["risky_scripts"] = risky
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


# A GUI app inherits launchd's PATH, not a login shell's, so anything a version manager
# installs is invisible to a scan started from the app — which is how most scans start.
# These are where the managers keep the version they would hand you.
RUNTIME_SHIMS = {
    "node": ["~/.volta/bin/node", "~/.asdf/shims/node",
             "~/Library/Application Support/fnm/aliases/default/bin/node",
             "~/.local/share/mise/shims/node"],
    "bun": ["~/.bun/bin/bun", "~/.asdf/shims/bun"],
    "python3": ["~/.pyenv/shims/python3", "~/.asdf/shims/python3",
                "~/.local/share/mise/shims/python3"],
    "ruby": ["~/.rbenv/shims/ruby", "~/.rvm/bin/ruby", "~/.asdf/shims/ruby"],
    "go": ["~/.asdf/shims/go", "/usr/local/go/bin/go"],
}


def nvm_default(home=None):
    """The node nvm would give you.

    `alias/default` can hold a full version, a release line like `22`, an alias that
    points at another alias, or `node`/`stable` for the newest. A line resolves to the
    highest installed version on it, which is what nvm itself does.
    """
    base = Path(home or Path.home()) / ".nvm"
    installed = []
    versions = base / "versions" / "node"
    if versions.is_dir():
        for child in versions.iterdir():
            parts = child.name.lstrip("v").split(".")
            if child.is_dir() and parts and all(p.isdigit() for p in parts):
                installed.append((tuple(int(p) for p in parts), child))
    if not installed:
        return None
    installed.sort()

    def binary(directory):
        path = directory / "bin" / "node"
        return str(path) if path.is_file() else None

    value = read(base / "alias" / "default", limit=256)
    seen = set()
    while value:
        value = value.strip()
        if not value or value in seen:
            return None
        seen.add(value)
        if value in ("node", "stable", "*", "latest"):
            return binary(installed[-1][1])
        wanted = value.lstrip("v")
        if wanted and all(p.isdigit() for p in wanted.split(".")):
            prefix = tuple(int(p) for p in wanted.split("."))
            on_line = [d for v, d in installed if v[:len(prefix)] == prefix]
            if on_line:
                return binary(on_line[-1])
        nxt = base / "alias" / value
        value = read(nxt, limit=256) if nxt.is_file() else None
    return None


def locate(binary):
    """The binary on PATH, or wherever a version manager is keeping it."""
    found = shutil.which(binary)
    if found:
        return found
    if binary == "node":
        found = nvm_default()
        if found:
            return found
    for candidate in RUNTIME_SHIMS.get(binary, []):
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def ignore_matcher(patterns):
    """Turn the user's ignore list into a predicate over directory paths.

    Three shapes, because people reach for all three: a bare name prunes a directory of
    that name wherever it turns up, anything containing a glob character is matched against
    the whole path, and a path prunes that subtree.
    """
    names, globs, trees = set(), [], []
    for raw in patterns or []:
        pattern = str(raw).strip()
        if not pattern:
            continue
        expanded = os.path.expanduser(pattern)
        if any(ch in pattern for ch in "*?["):
            globs.append(expanded)
        elif "/" in pattern:
            trees.append(Path(expanded).resolve())
        else:
            names.add(pattern)
    if not (names or globs or trees):
        return None

    def ignored(path):
        if path.name in names:
            return True
        if any(fnmatch.fnmatch(str(path), glob) for glob in globs):
            return True
        return any(path == tree or tree in path.parents for tree in trees)
    return ignored


def discover(roots, max_depth, skip_hidden=True, ignored=None):
    """Group interesting files by the directory that owns them."""
    found = {}
    for root in roots:
        root = Path(root).expanduser().resolve()
        if not root.is_dir() or (ignored and ignored(root)):
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
                and not (ignored and ignored(here / d))
            ]
            hits = [f for f in filenames if f in INTEREST]
            if hits:
                found.setdefault(str(here), []).append(hits)
    return {d: sorted({f for group in groups for f in group}) for d, groups in found.items()}


_SSH_HOSTS = {}


def resolve_ssh_host(alias):
    """Remotes often use an SSH alias (git@work:org/repo); ask ssh what it really is."""
    if alias in _SSH_HOSTS:
        return _SSH_HOSTS[alias]
    host = alias
    try:
        out = subprocess.run(["ssh", "-G", alias], capture_output=True, text=True, timeout=10)
        for line in out.stdout.splitlines():
            if line.startswith("hostname "):
                host = line.split(None, 1)[1].strip()
                break
    except (OSError, subprocess.SubprocessError):
        pass
    _SSH_HOSTS[alias] = host
    return host


def github_slug(remote):
    """owner/repo when the remote really points at GitHub, else None."""
    if not remote:
        return None
    m = re.match(r"^(?:ssh://)?(?:git@|[\w.-]+@)([\w.-]+)[:/](.+?)(?:\.git)?/?$", remote)
    if m:
        host, path = resolve_ssh_host(m.group(1)), m.group(2)
    else:
        m = re.match(r"^https?://(?:[^@/]+@)?([\w.-]+)/(.+?)(?:\.git)?/?$", remote)
        if not m:
            return None
        host, path = m.group(1), m.group(2)
    if host.lower() != "github.com":
        return None
    parts = [p for p in path.split("/") if p]
    return "/".join(parts[:2]) if len(parts) >= 2 else None


def dependabot_config(directory):
    """What .github/dependabot.yml says, without needing a YAML parser.

    Only two things change whether an advisory reaches the user: version updates
    turned off wholesale, and packages ignored by bare name (which also suppresses
    security PRs, unlike a semver-scoped ignore).
    """
    path = Path(directory) / ".github" / "dependabot.yml"
    if not path.is_file():
        path = Path(directory) / ".github" / "dependabot.yaml"
        if not path.is_file():
            return None
    text = read(path, limit=256 * 1024) or ""
    ignored, pending = [], None
    for raw in text.splitlines():
        line = raw.split("#")[0].rstrip()
        name = re.search(r"-?\s*dependency-name:\s*[\"']?([^\"'\s]+)", line)
        if name:
            if pending:
                ignored.append(pending)
            pending = name.group(1)
            continue
        if pending and re.search(r"update-types:", line):
            pending = None
    if pending:
        ignored.append(pending)
    return {
        "present": True,
        "version_updates_disabled": bool(
            re.search(r"open-pull-requests-limit:\s*0\b", text)),
        "ecosystems": sorted(set(re.findall(r"package-ecosystem:\s*[\"']?([\w-]+)", text))),
        "ignored_outright": sorted(set(ignored)),
    }


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
    remote = run(["remote", "get-url", "origin"])
    return {
        "git_last_commit": run(["log", "-1", "--format=%cI"]),
        "git_branch": run(["rev-parse", "--abbrev-ref", "HEAD"]),
        "git_remote": remote,
        "github": github_slug(remote),
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
        binary = locate(args[0])
        m = re.search(pattern, sh([binary] + args[1:]) or "") if binary else None
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


IGNORE_CASES = [
    (["~/code/Archive"], "~/code/Archive", True),
    (["~/code/Archive"], "~/code/Archive/old-app", True),
    (["~/code/Archive"], "~/code/Active", False),
    (["Archive"], "~/code/Archive", True),
    (["Archive"], "~/code/archive", False),
    (["*/Projects/*"], "~/Desktop/Projects/thing", True),
    (["*/Projects/*"], "~/Desktop/Steady/api", False),
    (["*-frontend"], "~/code/admin-frontend", True),
    ([""], "~/code/anything", False),
]


def _nvm_case(tmp, default, aliases=(), installed=()):
    """Build a throwaway ~/.nvm layout so the alias walk can be tested off the real one."""
    base = pathlib.Path(tmp) / ".nvm"
    (base / "alias").mkdir(parents=True, exist_ok=True)
    (base / "alias" / "default").write_text(default + "\n")
    for name, value in aliases:
        target = base / "alias" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value + "\n")
    for version in installed:
        binary = base / "versions" / "node" / version / "bin" / "node"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!/bin/sh\n")
    return tmp


def selftest():
    failures = []
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        home = _nvm_case(tmp, "22.22.2", installed=["v22.22.2"])
        got = nvm_default(home)
        if not got or not got.endswith("/.nvm/versions/node/v22.22.2/bin/node"):
            failures.append(f"  nvm_default did not resolve a plain version: {got}")
    with tempfile.TemporaryDirectory() as tmp:
        # nvm writes nested aliases like `lts/jod`, and default often points at one.
        home = _nvm_case(tmp, "lts/jod", aliases=[("lts/jod", "20.19.5")],
                         installed=["v20.19.5"])
        got = nvm_default(home)
        if not got or not got.endswith("/v20.19.5/bin/node"):
            failures.append(f"  nvm_default did not follow an alias chain: {got}")
    with tempfile.TemporaryDirectory() as tmp:
        # What nvm actually writes here most of the time: a release line, not a version.
        home = _nvm_case(tmp, "22", installed=["v22.9.0", "v22.22.2", "v24.19.0"])
        got = nvm_default(home)
        if not got or not got.endswith("/v22.22.2/bin/node"):
            failures.append(f"  nvm_default did not take the newest on line 22: {got}")
    with tempfile.TemporaryDirectory() as tmp:
        home = _nvm_case(tmp, "node", installed=["v22.22.2", "v24.19.0"])
        got = nvm_default(home)
        if not got or not got.endswith("/v24.19.0/bin/node"):
            failures.append(f"  nvm_default did not take the newest for `node`: {got}")
    with tempfile.TemporaryDirectory() as tmp:
        home = _nvm_case(tmp, "24.1.0", installed=[])
        if nvm_default(home) is not None:
            failures.append("  nvm_default returned a version that is not installed")
    with tempfile.TemporaryDirectory() as tmp:
        home = _nvm_case(tmp, "a", aliases=[("a", "b"), ("b", "a")])
        if nvm_default(home) is not None:
            failures.append("  nvm_default did not break an alias loop")
    if nvm_default(tempfile.gettempdir() + "/definitely-not-here") is not None:
        failures.append("  nvm_default invented a node with no .nvm present")
    for patterns, path, expected in IGNORE_CASES:
        matcher = ignore_matcher(patterns)
        actual = bool(matcher and matcher(Path(os.path.expanduser(path))))
        if actual != expected:
            failures.append(f"  ignore({patterns!r}, {path!r}) = {actual}, want {expected}")
    if ignore_matcher([]) is not None:
        failures.append("  an empty ignore list should produce no matcher")
    if failures:
        print(f"inventory selftest FAILED ({len(failures)})")
        print("\n".join(failures))
        return 1
    print(f"inventory selftest ok: {len(IGNORE_CASES)} ignore cases, "
          "7 nvm-resolution cases")
    return 0


def main():
    # Checked before the parser, which requires --out for a real run.
    if "--selftest" in sys.argv[1:]:
        return selftest()
    ap = argparse.ArgumentParser(description="Build a machine dependency graph")
    ap.add_argument("--roots", nargs="*", default=[str(Path.home())])
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--ignore", nargs="*", default=[],
                    help="skip these while walking: a folder path, a bare directory name "
                         "to prune anywhere, or a glob matched against the full path")
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-host", action="store_true")
    ap.add_argument("--include-hidden", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    graph = Graph()
    host = None if args.no_host else add_host_layer(graph)
    if host is None:
        host = graph.node("host", kind="host", name=os.uname().nodename, ecosystem="host")

    discovered = discover(args.roots, args.depth, skip_hidden=not args.include_hidden,
                          ignored=ignore_matcher(args.ignore))
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
            stale_days=days_since(meta.get("git_last_commit")),
            dependabot=dependabot_config(directory),
            build_policy=build_policy(directory, files),
            install_state=install_state(directory, files), **meta,
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
        "ignored": list(args.ignore),
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
