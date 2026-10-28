import Foundation

enum Band: String, CaseIterable, Comparable {
    case p0 = "P0", p1 = "P1", p2 = "P2", p3 = "P3"

    var rank: Int { Band.allCases.firstIndex(of: self) ?? 9 }
    var title: String {
        switch self {
        case .p0: return "Act now"
        case .p1: return "This week"
        case .p2: return "Schedule"
        case .p3: return "Monitor"
        }
    }
    static func < (a: Band, b: Band) -> Bool { a.rank < b.rank }
}

struct DependabotState: Decodable, Hashable {
    let state: String
    let repo: String?
    let number: Int?
    let url: String?

    /// One plain sentence about whether anything else will raise these.
    var note: String? {
        switch state {
        case "github":
            return repo.map {
                "Dependabot will flag and raise these itself if it is turned on for \($0)."
            }
        case "pr":
            return number.map { "Dependabot already has PR #\($0) open for this repo." }
        case "alert":
            return "Dependabot already has open alerts for this repo."
        case "not-github":
            return "Remote is not GitHub — Dependabot will not see these."
        case "no-repo":
            return "Not a git repo — nothing else is watching this."
        default:
            return nil
        }
    }

    var covered: Bool { state == "github" || state == "pr" || state == "alert" }
}

struct ProjectRef: Decodable, Hashable {
    let path: String
    let name: String
    let rel: String
    let direct: Bool?
    let staleDays: Int?
    let fix: String
    let dependabot: DependabotState?
    let band: String?
    let depsInstalled: InstallState?
}

struct InstallState: Decodable, Hashable {
    let known: Bool?
    let present: Bool?
}

struct Finding: Decodable, Hashable {
    let band: String
    let ecosystem: String
    let package: String
    let installed: String
    let fixedVersion: String?
    let severity: String?
    let cvss: Double?
    let advisory: String?
    let cve: String?
    let url: String?
    let summary: String?
    let kev: Bool?
    let malware: Bool?
    let new: Bool?
    let source: String?
    let installedOnDisk: Bool?
    let dormantDays: Int?
    let projects: [ProjectRef]

    /// Window findings were disclosed in the last N days; osv-scanner supplies the
    /// rest of the advisory history, which is backlog rather than news.
    var fromOSV: Bool { source == "osv-scanner" }

    var bandValue: Band { Band(rawValue: band) ?? .p3 }
}

/// A core advisory for the interpreter itself. These carry no package ecosystem, so the
/// dependency findings never include them and no package upgrade clears them.
struct RuntimeFinding: Decodable, Hashable {
    let band: String
    let advisory: String
    let cve: String?
    let severity: String?
    let summary: String?
    let url: String?
    let package: String
    let installed: String
    let fixedVersion: String?
    let running: Bool?
    let source: String?
    let fix: String?

    var bandValue: Band { Band(rawValue: band) ?? .p3 }
}

struct Lead: Decodable, Hashable {
    let cve: String
    let vendor: String?
    let product: String?
    let added: String?
    let url: String?
    let summary: String?
}

struct GraphStats: Decodable {
    let projects: Int?
    let packages: Int?
    let nodes: Int?
}

struct Intel: Decodable {
    let windowDays: Int?
    let publishedSince: String?
    let kevCatalog: String?
    let auth: String?
}

struct CodeAlert: Decodable, Hashable {
    let kind: String
    let project: String?
    let name: String?
    let hook: String?
    let command: String?
    let why: String?
}

struct Findings: Decodable {
    let generatedAt: String?
    let counts: [String: Int]?
    let findings: [Finding]
    let leads: [Lead]?
    let alerts: [CodeAlert]?
    let malware: [Finding]?
    let installScripts: [String: [String]]?
    let graphStats: GraphStats?
    let intel: Intel?
    let scope: ScanScope?
    let runtimes: [RuntimeFinding]?

    static func load(from url: URL) throws -> Findings {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(Findings.self, from: Data(contentsOf: url))
    }

    func count(_ band: Band) -> Int { counts?[band.rawValue] ?? 0 }
    var actionable: Int { count(.p0) + count(.p1) }
}

/// Where the scan that produced these results was pointed.
struct ScanScope: Decodable {
    let roots: [String]?
    let ignored: [String]?

    /// Older results predate this field, so there is nothing to compare and nothing to warn
    /// about — claiming staleness we cannot prove would be worse than staying quiet.
    func matches(roots wanted: [String], ignored skipping: [String]) -> Bool {
        guard let roots else { return true }
        let tidy = { (list: [String]) in
            Set(list.map { ($0 as NSString).expandingTildeInPath }
                    .map { $0.hasSuffix("/") ? String($0.dropLast()) : $0 })
        }
        return tidy(roots) == tidy(wanted) && tidy(ignored ?? []) == tidy(skipping)
    }
}

/// One package version to upgrade inside one project.
struct PackageItem: Identifiable, Hashable {
    let id = UUID()
    let band: Band
    let package: String
    let installed: String
    let target: String?
    let ecosystem: String
    let rel: String
    let direct: Bool
    let fix: String
    let kev: Bool
    let isNew: Bool
    /// Whether this project's repo is on GitHub, where Dependabot would raise it too.
    let dependabotCovered: Bool
    /// The lockfile pins a vulnerable version, but the tree is not installed in this checkout.
    let pinnedOnly: Bool
    let advisories: [Finding]

    var viaWindow: Bool { advisories.contains { !$0.fromOSV } }
    var viaOSV: Bool { advisories.contains { $0.fromOSV } }

    /// What to call this on the card: freshly disclosed, or long-standing backlog.
    var originLabel: String? {
        if viaWindow && viaOSV { return "RECENT + BACKLOG" }
        if viaWindow { return "RECENT" }
        if viaOSV { return "BACKLOG" }
        return nil
    }
}

struct ProjectGroup: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let name: String
    let staleDays: Int?
    let items: [PackageItem]
    let dependabot: DependabotState?

    var band: Band { items.map(\.band).min() ?? .p3 }
    var kev: Bool { items.contains { $0.kev } }
    var newCount: Int { items.filter(\.isNew).count }
    func count(_ band: Band) -> Int { items.filter { $0.band == band }.count }

    /// Everything to run inside this repo, deduplicated, in priority order.
    var fixScript: String {
        var seen = Set<String>()
        var lines = ["cd \(path.replacingOccurrences(of: " ", with: "\\ "))"]
        for item in items where !seen.contains(item.fix) {
            seen.insert(item.fix)
            lines.append(item.fix)
        }
        return lines.joined(separator: "\n")
    }

    /// A copy holding only the items matching an age filter, or nil when none do.
    func filtered(age: String) -> ProjectGroup? {
        guard age != "all" else { return self }
        let keep = items.filter { age == "recent" ? $0.viaWindow : $0.viaOSV }
        guard !keep.isEmpty else { return nil }
        return ProjectGroup(path: path, name: name, staleDays: staleDays,
                            items: keep, dependabot: dependabot)
    }

    static func build(from findings: [Finding]) -> [ProjectGroup] {
        var byPath: [String: (ref: ProjectRef, items: [PackageItem])] = [:]
        // Collapse the advisory-per-row feed into one row per package version per project.
        var merged: [String: (Finding, [Finding])] = [:]
        for finding in findings {
            let key = "\(finding.ecosystem)|\(finding.package)|\(finding.installed)"
            if var existing = merged[key] {
                existing.1.append(finding)
                merged[key] = existing
            } else {
                merged[key] = (finding, [finding])
            }
        }
        for (primary, group) in merged.values {
            let band = group.map(\.bandValue).min() ?? .p3
            let target = group.compactMap(\.fixedVersion).max { Version($0) < Version($1) }
            var refs: [String: ProjectRef] = [:]
            for finding in group {
                for ref in finding.projects {
                    if refs[ref.path] == nil || (ref.direct == true && refs[ref.path]?.direct != true) {
                        refs[ref.path] = ref
                    }
                }
            }
            for ref in refs.values {
                // The advisory's band is the worst case across every project it touches;
                // this project's own band accounts for whether the tree is installed here.
                let item = PackageItem(
                    band: ref.band.flatMap(Band.init(rawValue:)) ?? band,
                    package: primary.package, installed: primary.installed,
                    target: target, ecosystem: primary.ecosystem, rel: ref.rel,
                    direct: ref.direct ?? false, fix: ref.fix,
                    kev: group.contains { $0.kev == true },
                    isNew: group.contains { $0.new == true },
                    dependabotCovered: ref.dependabot?.covered == true,
                    pinnedOnly: ref.depsInstalled?.known == true
                        && ref.depsInstalled?.present != true,
                    advisories: group.sorted { ($0.cvss ?? 0) > ($1.cvss ?? 0) })
                byPath[ref.path, default: (ref, [])].items.append(item)
            }
        }
        return byPath.values.map { entry in
            ProjectGroup(path: entry.ref.path, name: entry.ref.name,
                         staleDays: entry.ref.staleDays,
                         items: entry.items.sorted {
                             $0.band == $1.band ? $0.package < $1.package : $0.band < $1.band
                         },
                         dependabot: entry.ref.dependabot)
        }.sorted {
            if $0.band != $1.band { return $0.band < $1.band }
            if $0.items.count != $1.items.count { return $0.items.count > $1.items.count }
            return $0.name < $1.name
        }
    }
}

/// Just enough version ordering to pick the highest fix target.
private struct Version: Comparable {
    let parts: [Int]
    init(_ raw: String) {
        parts = raw.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
    }
    static func < (a: Version, b: Version) -> Bool {
        for i in 0..<max(a.parts.count, b.parts.count) {
            let x = i < a.parts.count ? a.parts[i] : 0
            let y = i < b.parts.count ? b.parts[i] : 0
            if x != y { return x < y }
        }
        return false
    }
}

extension PackageItem {
    /// One finding, written out as evidence rather than a verdict.
    var briefing: String {
        var lines = ["### \(package) \(installed) → \(target ?? "no published fix") "
                     + "(\(ecosystem), \(direct ? "direct" : "transitive")"
                     + (rel == "dev" ? ", dev-only" : rel == "ci_uses" ? ", CI-only" : "")
                     + ")"]
        lines.append("Urgency: \(band.rawValue) — \(band.blurb)")
        if kev { lines.append("Known exploited in the wild (CISA KEV).") }
        for adv in advisories {
            var head = "- \(adv.advisory ?? adv.cve ?? "advisory")"
            var bits: [String] = []
            if let severity = adv.severity { bits.append(severity) }
            if let cvss = adv.cvss { bits.append(String(format: "CVSS %.1f", cvss)) }
            if let cve = adv.cve, cve != adv.advisory { bits.append(cve) }
            if !bits.isEmpty { head += " (" + bits.joined(separator: ", ") + ")" }
            lines.append(head)
            if let summary = adv.summary, !summary.isEmpty {
                lines.append("  \(summary)")
            }
            if let url = adv.url { lines.append("  \(url)") }
        }
        lines.append("Suggested command: \(fix)")
        return lines.joined(separator: "\n")
    }
}

extension ProjectGroup {
    /// A briefing for a coding agent: the evidence, then the judgement call, then the work.
    /// Deliberately does not assume the upgrade is warranted — that is what it asks.
    var aiPrompt: String {
        let actionable = items.filter { $0.band <= .p2 }
        let listed = actionable.isEmpty ? items : actionable
        var out = """
        A dependency scan flagged \(listed.count) package\(listed.count == 1 ? "" : "s") \
        in the repository at `\(path)`.

        For each one: work out whether this codebase is genuinely exposed, then apply the \
        upgrade only where it is warranted. Do not assume the scanner is right — it matches \
        installed versions against published advisory ranges and knows nothing about how \
        this code uses the package.

        ## Findings


        """
        out += listed.map(\.briefing).joined(separator: "\n\n")
        out += """


        ## How to work through it

        1. For each finding, find where the package is used in this repo. If it is pulled in \
        transitively, identify the direct dependency that owns it.
        2. Decide whether the vulnerable code path is reachable here. State the reasoning in \
        one or two sentences per package — a dev-only or build-time dependency with no \
        runtime exposure is usually not urgent, and say so rather than upgrading reflexively.
        3. Apply the upgrades you judged necessary, preferring the smallest version bump that \
        clears the advisory. For a transitive package, bump the parent or add an override \
        rather than pinning blindly.
        4. Check for breaking changes in each upgrade — read the changelog for major bumps \
        and adjust call sites.
        5. Run the project's install, lint, type-check, build and tests. Report what passed \
        and what did not; do not paper over a failure.
        6. Summarise: what you upgraded, what you deliberately left alone and why, and \
        anything that needs a human decision.

        Do not commit or push anything. Leave the changes in the working tree for review.
        """
        return out
    }
}

/// Projects rolled up by their parent directory, so a machine-wide scan reads as
/// "work has 24, side-projects has 6" instead of a flat list of a hundred repos.
struct FolderGroup: Identifiable, Hashable {
    var id: String { path }
    let path: String
    let projects: [ProjectGroup]

    var name: String {
        let home = NSHomeDirectory()
        let shown = path.hasPrefix(home) ? "~" + path.dropFirst(home.count) : path
        return shown.isEmpty ? "/" : String(shown)
    }
    var band: Band { projects.map(\.band).min() ?? .p3 }
    var findingCount: Int { projects.reduce(0) { $0 + $1.items.count } }
    func count(_ band: Band) -> Int { projects.filter { $0.band == band }.count }

    static func build(from projects: [ProjectGroup]) -> [FolderGroup] {
        var buckets: [String: [ProjectGroup]] = [:]
        for project in projects {
            let parent = (project.path as NSString).deletingLastPathComponent
            buckets[parent, default: []].append(project)
        }
        return buckets.map { parent, group in
            FolderGroup(path: parent,
                        projects: group.sorted {
                            $0.band == $1.band ? $0.name < $1.name : $0.band < $1.band
                        })
        }.sorted {
            if $0.band != $1.band { return $0.band < $1.band }
            if $0.projects.count != $1.projects.count {
                return $0.projects.count > $1.projects.count
            }
            return $0.name < $1.name
        }
    }
}
