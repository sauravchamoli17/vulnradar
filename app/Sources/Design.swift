import SwiftUI

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: alpha)
    }
}

/// Four surfaces, four text weights, one accent. Everything else is spacing.
enum Theme {
    static let bg = Color(hex: 0x0D0E11)
    static let sidebar = Color(hex: 0x111317)
    static let surface = Color(hex: 0x171A1F)
    static let raised = Color(hex: 0x1E2228)
    static let hairline = Color(hex: 0x23272E)

    static let text = Color(hex: 0xF0F1F3)
    static let secondary = Color(hex: 0x9BA2AC)
    static let tertiary = Color(hex: 0x646B75)

    static let accent = Color(hex: 0x6E8CFF)
    static let good = Color(hex: 0x3FBF72)
}

/// One scale, used everywhere. No more 10.5 / 11.5 / 12.5 drift.
enum TypeScale {
    static let micro = Font.system(size: 10, weight: .semibold)
    static let caption = Font.system(size: 11)
    static let small = Font.system(size: 12)
    static let body = Font.system(size: 13)
    static let strong = Font.system(size: 13, weight: .medium)
    static let title = Font.system(size: 15, weight: .semibold)
    static let heading = Font.system(size: 20, weight: .bold)
    static let stat = Font.system(size: 30, weight: .semibold, design: .rounded)

    static let mono = Font.system(size: 11.5, design: .monospaced)
    static let monoBody = Font.system(size: 12, design: .monospaced)
}

enum Space {
    static let xs: CGFloat = 4
    static let s: CGFloat = 8
    static let m: CGFloat = 12
    static let l: CGFloat = 16
    static let xl: CGFloat = 24
}

extension Band {
    var tint: Color {
        switch self {
        case .p0: return Color(hex: 0xFF5247)
        case .p1: return Color(hex: 0xFF9A2E)
        case .p2: return Color(hex: 0xDFBE33)
        case .p3: return Color(hex: 0x7B91A3)
        }
    }
    var blurb: String {
        switch self {
        case .p0: return "Exploited in the wild, or critical and reachable at runtime"
        case .p1: return "High impact on code you actually run"
        case .p2: return "Real but contained — dev-only, CI-only, or dormant"
        case .p3: return "Low exposure; no action unless context changes"
        }
    }
}

struct GlowDot: View {
    let color: Color
    var size: CGFloat = 7
    var glow = true

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .shadow(color: glow ? color.opacity(0.5) : .clear, radius: size * 0.6)
    }
}

struct BandPill: View {
    let band: Band

    var body: some View {
        Text(band.rawValue)
            .font(TypeScale.micro)
            .tracking(0.3)
            .foregroundStyle(band.tint)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(band.tint.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
    }
}

/// Proportional P0→P3 strip: the shape of the risk, not just the totals.
struct DistributionBar: View {
    let counts: [Band: Int]
    var height: CGFloat = 4

    private var total: Int { max(1, counts.values.reduce(0, +)) }

    var body: some View {
        GeometryReader { geo in
            HStack(spacing: 1.5) {
                ForEach(Band.allCases, id: \.self) { band in
                    let value = counts[band] ?? 0
                    if value > 0 {
                        Capsule().fill(band.tint)
                            .frame(width: max(2, geo.size.width * CGFloat(value)
                                              / CGFloat(total) - 1.5))
                    }
                }
            }
        }
        .frame(height: height)
    }
}

/// Flat panel: elevation by background, not by outline. Borders are the exception.
struct Panel<Content: View>: View {
    var padding: CGFloat = Space.m
    var fill: Color = Theme.surface
    var hoverable = false
    @ViewBuilder var content: Content
    @State private var hovering = false

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(hovering ? Theme.raised : fill)
            )
            .onHover { if hoverable { hovering = $0 } }
            .animation(.easeOut(duration: 0.1), value: hovering)
    }
}

/// The one emphasised control on screen.
struct PrimaryButton: View {
    let title: String
    let symbol: String
    var busy = false
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if busy {
                    ProgressView().controlSize(.small).scaleEffect(0.6)
                        .frame(width: 11, height: 11)
                } else {
                    Image(systemName: symbol).font(.system(size: 11, weight: .semibold))
                }
                Text(title).font(TypeScale.strong)
            }
            .foregroundStyle(.white)
            .fixedSize()
            .padding(.horizontal, Space.m)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Theme.accent.opacity(hovering ? 1 : 0.88))
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.1), value: hovering)
    }
}

/// Quiet icon control for everything that is not the primary action.
struct IconButton: View {
    let symbol: String
    var help: String = ""
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(hovering ? Theme.text : Theme.secondary)
                .frame(width: 26, height: 24)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(hovering ? Theme.raised : .clear)
                )
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(help)
    }
}

/// Segmented control used for the two or three view modes.
struct Segmented<T: Hashable>: View {
    let options: [(value: T, label: String, symbol: String?)]
    @Binding var selection: T

    var body: some View {
        HStack(spacing: 1) {
            ForEach(options, id: \.value) { option in
                Button { selection = option.value } label: {
                    HStack(spacing: 5) {
                        if let symbol = option.symbol {
                            Image(systemName: symbol).font(.system(size: 10, weight: .semibold))
                        }
                        Text(option.label).font(.system(size: 11.5, weight: .medium))
                    }
                    .foregroundStyle(selection == option.value ? Theme.text : Theme.secondary)
                    .padding(.horizontal, Space.s)
                    .padding(.vertical, 4)
                    .background(
                        RoundedRectangle(cornerRadius: 5)
                            .fill(selection == option.value ? Theme.raised : .clear)
                    )
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(2)
        .fixedSize()
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.surface))
    }
}

struct SectionLabel: View {
    let text: String
    var body: some View {
        Text(text.uppercased())
            .font(TypeScale.micro)
            .tracking(0.8)
            .foregroundStyle(Theme.tertiary)
    }
}

struct VersionJump: View {
    let from: String
    let to: String?

    var body: some View {
        HStack(spacing: 5) {
            Text(from).font(TypeScale.mono).foregroundStyle(Theme.secondary)
            Image(systemName: "arrow.right")
                .font(.system(size: 8, weight: .bold)).foregroundStyle(Theme.tertiary)
            Text(to ?? "no fix")
                .font(TypeScale.mono)
                .foregroundStyle(to == nil ? Theme.tertiary : Theme.good)
        }
    }
}
