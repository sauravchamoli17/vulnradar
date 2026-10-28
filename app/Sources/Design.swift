import AppKit
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

/// A real macOS material. Translucency is the strongest native signal there is —
/// a flat fill makes the same layout read as a web page in a window.
struct VisualEffect: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    var blending: NSVisualEffectView.BlendingMode = .behindWindow

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blending
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) {
        view.material = material
        view.blendingMode = blending
    }
}

enum Theme {
    /// Sits over the window material rather than replacing it.
    static let contentPanel = Color(hex: 0x1B1D23)
    static let raised = Color(hex: 0x23262E)
    static let sunken = Color.black.opacity(0.28)
    static let hairline = Color.white.opacity(0.065)

    static let text = Color(hex: 0xF6F7FA)
    static let secondary = Color(hex: 0xA7ADBA)
    static let tertiary = Color(hex: 0x8B92A2)

    /// One deliberate accent, reserved for action: Scan, links, the schedule.
    static let accent = Color(hex: 0x5A5FE0)
    static let good = Color(hex: 0x4FBF84)

    static let panelRadius: CGFloat = 10
    static let toolbarHeight: CGFloat = 52
}

enum TypeScale {
    /// Instrument Sans and JetBrains Mono ship in the bundle; if registration ever
    /// fails the system face stands in at the same size and weight.
    static func ui(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        let face: String
        switch weight {
        case .bold, .heavy, .black: face = "InstrumentSans-Bold"
        case .semibold: face = "InstrumentSans-SemiBold"
        case .medium: face = "InstrumentSans-Medium"
        default: face = "InstrumentSans-Regular"
        }
        return NSFont(name: face, size: size) == nil
            ? .system(size: size, weight: weight)
            : .custom(face, size: size)
    }

    static func code(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        let face = weight == .regular ? "JetBrainsMono-Regular" : "JetBrainsMono-Medium"
        return NSFont(name: face, size: size) == nil
            ? .system(size: size, design: .monospaced)
            : .custom(face, size: size)
    }

    static let heading = ui(25, .semibold)
    static let title = ui(15, .semibold)
    static let body = ui(13)
    static let strong = ui(13, .medium)
    static let caption = ui(11.5)
    static let micro = ui(10, .semibold)
    static let stat = ui(30, .semibold)

    static let mono = code(11.5)
}

enum Space {
    static let xs: CGFloat = 4
    static let s: CGFloat = 7
    static let m: CGFloat = 11
    static let l: CGFloat = 16
    static let xl: CGFloat = 24
}

extension Band {
    /// Desaturated, and separated by lightness as well as hue so they survive
    /// colour-blindness and a dimmed display.
    var tint: Color {
        switch self {
        case .p0: return Color(hex: 0xE2555F)
        case .p1: return Color(hex: 0xE0883C)
        case .p2: return Color(hex: 0xA89446)
        case .p3: return Color(hex: 0x6E7D8F)
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

/// Pointing hand over anything clickable. set/arrow rather than push/pop, which
/// unbalances when a hover-exit event is missed and leaves the cursor stuck.
struct PointerCursor: ViewModifier {
    func body(content: Content) -> some View {
        content.onHover { inside in
            if inside { NSCursor.pointingHand.set() } else { NSCursor.arrow.set() }
        }
    }
}

extension View {
    func pointerCursor() -> some View { modifier(PointerCursor()) }
}

struct GlowDot: View {
    let color: Color
    var size: CGFloat = 7
    var glow = true

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .shadow(color: glow ? color.opacity(0.5) : .clear, radius: size * 0.85)
    }
}

struct BandPill: View {
    let band: Band

    var body: some View {
        Text(band.rawValue)
            .font(TypeScale.ui(9.5, .bold))
            .tracking(0.4)
            .foregroundStyle(band.tint)
            .padding(.horizontal, 5)
            .padding(.vertical, 3)
            .background(band.tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 4))
    }
}

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

/// Inset card. Separation by elevation, never a 1px box.
struct Panel<Content: View>: View {
    var padding: CGFloat = Space.m
    var hoverable = false
    @ViewBuilder var content: Content
    @State private var hovering = false

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color.white.opacity(hovering ? 0.065 : 0.035))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.05), lineWidth: 0.5)
            )
            .onHover { if hoverable { hovering = $0 } }
            .animation(.easeOut(duration: 0.1), value: hovering)
    }
}

/// The single emphasised control, drawn like a macOS accent button.
struct PrimaryButton: View {
    let title: String
    let symbol: String
    var busy = false
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if busy {
                    ProgressView().controlSize(.small).scaleEffect(0.55)
                        .frame(width: 11, height: 11)
                } else {
                    Image(systemName: symbol).font(.system(size: 11, weight: .semibold))
                }
                Text(title).font(TypeScale.ui(12, .semibold))
            }
            .foregroundStyle(.white)
            .fixedSize()
            .padding(.horizontal, Space.m)
            .padding(.vertical, 5)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Theme.accent.opacity(hovering ? 1 : 0.9))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.22), lineWidth: 0.5)
                    .blendMode(.plusLighter)
            )
            .shadow(color: .black.opacity(0.3), radius: 1.5, y: 1)
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.1), value: hovering)
    }
}

struct IconButton: View {
    let symbol: String
    var help: String = ""
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .regular))
                .foregroundStyle(hovering ? Theme.text : Theme.secondary)
                .frame(width: 26, height: 26)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(hovering ? Color.white.opacity(0.08) : .clear)
                )
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .onHover { hovering = $0 }
        .help(help)
    }
}

/// Inset segmented control, the macOS pattern for a small set of modes.
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
                        Text(option.label).font(TypeScale.ui(11.5, .medium))
                    }
                    .foregroundStyle(selection == option.value ? Theme.text : Theme.tertiary)
                    .padding(.horizontal, Space.s + 2)
                    .padding(.vertical, 4)
                    .background(
                        RoundedRectangle(cornerRadius: 5)
                            .fill(selection == option.value
                                  ? Color.white.opacity(0.11) : .clear)
                    )
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .pointerCursor()
            }
        }
        .padding(2)
        .fixedSize()
        .background(RoundedRectangle(cornerRadius: 7).fill(Theme.sunken))
    }
}

struct SectionLabel: View {
    let text: String
    var tint: Color?
    var body: some View {
        Text(text.uppercased())
            .font(TypeScale.micro)
            .tracking(0.7)
            .foregroundStyle(tint ?? Theme.tertiary)
    }
}

struct VersionJump: View {
    let from: String
    let to: String?

    var body: some View {
        HStack(spacing: 5) {
            Text(from).font(TypeScale.mono).foregroundStyle(Theme.tertiary)
            Image(systemName: "arrow.right")
                .font(.system(size: 8, weight: .bold)).foregroundStyle(Theme.tertiary.opacity(0.7))
            Text(to ?? "no fix")
                .font(TypeScale.mono)
                .foregroundStyle(to == nil ? Theme.tertiary : Theme.good)
        }
    }
}

/// Time picker: you choose a scan time once, so pick it from a list rather than
/// stepping digits. The list expands in place — a macOS Menu strips a custom label,
/// and a popover inside the schedule popover nests badly.
struct TimeField: View {
    @Binding var hour: Int
    @Binding var minute: Int
    @State private var open = false

    private struct Slot: Identifiable {
        let hour: Int
        let minute: Int
        var id: Int { hour * 60 + minute }
    }

    private var uses12Hour: Bool {
        (DateFormatter.dateFormat(fromTemplate: "j", options: 0, locale: .current) ?? "")
            .contains("a")
    }

    private func label(_ h: Int, _ m: Int) -> String {
        guard uses12Hour else { return String(format: "%02d:%02d", h, m) }
        let twelve = h % 12 == 0 ? 12 : h % 12
        return String(format: "%d:%02d %@", twelve, m, h < 12 ? "AM" : "PM")
    }

    /// Half-hour slots, plus whatever is stored if it sits off the grid.
    private var slots: [Slot] {
        var out = (0..<24).flatMap { [Slot(hour: $0, minute: 0), Slot(hour: $0, minute: 30)] }
        if !out.contains(where: { $0.hour == hour && $0.minute == minute }) {
            out.append(Slot(hour: hour, minute: minute))
            out.sort { $0.id < $1.id }
        }
        return out
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                withAnimation(.easeOut(duration: 0.12)) { open.toggle() }
            } label: {
                HStack(spacing: 7) {
                    Image(systemName: "clock")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(Theme.tertiary)
                    Text(label(hour, minute))
                        .font(TypeScale.code(13, .medium))
                        .monospacedDigit()
                        .foregroundStyle(Theme.text)
                    Image(systemName: "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundStyle(Theme.tertiary)
                        .rotationEffect(.degrees(open ? 180 : 0))
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .frame(width: 136, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(Theme.sunken))
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .strokeBorder(open ? Theme.accent.opacity(0.5)
                                       : Color.white.opacity(0.09), lineWidth: 0.5))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .pointerCursor()

            if open {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 1) {
                            ForEach(slots) { row($0) }
                        }
                        .padding(3)
                    }
                    .frame(width: 136, height: 148)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(Theme.sunken))
                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.09), lineWidth: 0.5))
                    .onAppear { proxy.scrollTo(hour * 60 + minute, anchor: .center) }
                }
            }
        }
    }

    private func row(_ slot: Slot) -> some View {
        let current = slot.hour == hour && slot.minute == minute
        return Button {
            hour = slot.hour
            minute = slot.minute
            withAnimation(.easeOut(duration: 0.12)) { open = false }
        } label: {
            HStack(spacing: 4) {
                Text(label(slot.hour, slot.minute))
                    .font(TypeScale.code(12.5, .medium))
                    .monospacedDigit()
                Spacer(minLength: 0)
                if current {
                    Image(systemName: "checkmark").font(.system(size: 9, weight: .bold))
                }
            }
            .foregroundStyle(current ? Color.white : Theme.text)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(RoundedRectangle(cornerRadius: 5)
                .fill(current ? Theme.accent : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .id(slot.id)
    }
}
