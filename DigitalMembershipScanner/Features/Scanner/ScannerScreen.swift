import AVFoundation
import SwiftUI
import UIKit

struct ScannerScreen: View {
    @StateObject private var issuerStore = IssuerTrustStore()
    @State private var scanFeedback = ScanFeedbackPlayer()

    @State private var cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var result: MembershipVerificationResult?
    @State private var scannerError: String?
    @State private var scanID = UUID()
    @State private var isPresentingIssuerConfiguration = false

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                switch cameraStatus {
                case .authorized: scanner
                case .notDetermined: permissionRequest
                case .denied, .restricted: permissionDenied
                @unknown default: permissionDenied
                }
            }
            .navigationTitle("Membership Scanner")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarColorScheme(.dark, for: .navigationBar)
            .toolbarBackground(Color.black, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
            .toolbar {
                Button("Configure issuer", systemImage: "gearshape") {
                    isPresentingIssuerConfiguration = true
                }
                .accessibilityHint("Download a trusted issuer public key and name model")
            }
        }
        .sheet(item: $result) { result in
            ScanResultView(result: result, issuer: issuerStore.configuration?.issuer) { resetScanner() }
                .interactiveDismissDisabled()
        }
        .sheet(isPresented: $isPresentingIssuerConfiguration) {
            IssuerConfigurationView(store: issuerStore)
        }
        .alert("Scanner unavailable", isPresented: scannerErrorBinding) {
            Button("Try again") { scanID = UUID() }
        } message: {
            Text(scannerError ?? "An unknown camera error occurred.")
        }
    }

    private var scanner: some View {
        ZStack {
            QRScannerView(
                onCodeScanned: {
                    let verificationResult = issuerStore.validator().validate($0)
                    scanFeedback.play(for: verificationResult)
                    result = verificationResult
                },
                onFailure: { scannerError = $0 }
            )
            .id(scanID)
            .ignoresSafeArea()

            VStack(spacing: 18) {
                Spacer()
                RoundedRectangle(cornerRadius: 28)
                    .stroke(Color.white, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                    .frame(width: 270, height: 270)
                    .shadow(color: .black.opacity(0.7), radius: 10)
                    .accessibilityHidden(true)
                Spacer()
                Label("Align the membership QR code inside the frame", systemImage: "qrcode.viewfinder")
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.white)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 14)
                    .background(.black.opacity(0.82), in: Capsule())
                    .padding(.bottom, 36)
            }
            .padding()
        }
    }

    private var permissionRequest: some View {
        PermissionView(
            symbol: "camera.fill",
            title: "Camera access needed",
            message: "The scanner uses your camera to read membership QR codes. Codes stay on this device.",
            actionTitle: "Allow camera"
        ) {
            Task {
                _ = await AVCaptureDevice.requestAccess(for: .video)
                cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
            }
        }
    }

    private var permissionDenied: some View {
        PermissionView(
            symbol: "camera.badge.ellipsis",
            title: "Camera access is off",
            message: "Enable camera access in Settings to scan a membership card.",
            actionTitle: "Open Settings"
        ) {
            guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
            UIApplication.shared.open(url)
        }
    }

    private var scannerErrorBinding: Binding<Bool> {
        Binding(get: { scannerError != nil }, set: { if !$0 { scannerError = nil } })
    }

    private func resetScanner() {
        result = nil
        scanID = UUID()
    }
}

@MainActor
private final class ScanFeedbackPlayer {
    private struct Note {
        let frequency: Double
        let duration: Double
    }

    private let audioEngine = AVAudioEngine()
    private let audioPlayer = AVAudioPlayerNode()
    private let audioFormat = AVAudioFormat(standardFormatWithSampleRate: 44_100, channels: 1)!
    private var playbackID = UUID()

    init() {
        audioEngine.attach(audioPlayer)
        audioEngine.connect(audioPlayer, to: audioEngine.mainMixerNode, format: audioFormat)
    }

    func play(for result: MembershipVerificationResult) {
        switch result {
        case .verified:
            playSuccess()
        case .rejected, .trustedIssuerUnavailable:
            playWarning()
        }
    }

    private func playSuccess() {
        let haptic = UIImpactFeedbackGenerator(style: .soft)
        haptic.prepare()
        haptic.impactOccurred(intensity: 0.45)
        play(notes: [
            Note(frequency: 659.25, duration: 0.07),
            Note(frequency: 783.99, duration: 0.10),
        ], amplitude: 0.07)
    }

    private func playWarning() {
        let haptic = UIImpactFeedbackGenerator(style: .rigid)
        haptic.prepare()
        haptic.impactOccurred(intensity: 0.85)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.13) {
            haptic.impactOccurred(intensity: 0.95)
        }
        play(notes: [
            Note(frequency: 440.00, duration: 0.09),
            Note(frequency: 349.23, duration: 0.13),
        ], amplitude: 0.09)
    }

    private func play(notes: [Note], amplitude: Float) {
        let gapDuration = 0.025
        let totalDuration = notes.reduce(0) { $0 + $1.duration } + gapDuration * Double(notes.count - 1)
        let frameCapacity = AVAudioFrameCount(totalDuration * audioFormat.sampleRate)
        guard let buffer = AVAudioPCMBuffer(pcmFormat: audioFormat, frameCapacity: frameCapacity),
              let samples = buffer.floatChannelData?[0]
        else { return }

        buffer.frameLength = frameCapacity
        samples.initialize(repeating: 0, count: Int(frameCapacity))

        var startFrame = 0
        for note in notes {
            let noteFrames = Int(note.duration * audioFormat.sampleRate)
            let fadeFrames = max(1, min(Int(0.012 * audioFormat.sampleRate), noteFrames / 2))
            for frame in 0..<noteFrames {
                let attack = min(1, Float(frame) / Float(fadeFrames))
                let release = min(1, Float(noteFrames - frame - 1) / Float(fadeFrames))
                let envelope = min(attack, release)
                let phase = 2 * Double.pi * note.frequency * Double(frame) / audioFormat.sampleRate
                samples[startFrame + frame] = sin(Float(phase)) * amplitude * envelope
            }
            startFrame += noteFrames + Int(gapDuration * audioFormat.sampleRate)
        }

        do {
            try AVAudioSession.sharedInstance().setCategory(.ambient, mode: .default, options: [.mixWithOthers])
            try AVAudioSession.sharedInstance().setActive(true)
            if !audioEngine.isRunning { try audioEngine.start() }
            audioPlayer.stop()
            audioPlayer.scheduleBuffer(buffer, at: nil, options: .interrupts)
            audioPlayer.play()

            playbackID = UUID()
            let currentPlaybackID = playbackID
            DispatchQueue.main.asyncAfter(deadline: .now() + totalDuration + 0.1) { [weak self] in
                guard let self, playbackID == currentPlaybackID else { return }
                audioPlayer.stop()
                audioEngine.stop()
                try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
            }
        } catch {
            // Audio feedback is optional; haptics still provide scan feedback if audio is unavailable.
        }
    }
}

private struct IssuerConfigurationView: View {
    @ObservedObject var store: IssuerTrustStore
    @Environment(\.dismiss) private var dismiss
    @State private var setupURL = IssuerTrustStore.defaultSetupURL
    @State private var isLoadingIssuers = false
    @State private var installingIssuerID: String?
    @State private var isPresentingCustomSetupURL = false

    var body: some View {
        NavigationStack {
            Form {
                if let installedIssuer = store.configuration?.issuer {
                    Section("Current issuer") {
                        Label {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(installedIssuer.name)
                                    .foregroundStyle(.primary)
                                Text("Currently installed")
                                    .font(.caption)
                                    .foregroundStyle(.mint)
                            }
                        } icon: {
                            Image(systemName: "checkmark.shield.fill")
                                .foregroundStyle(.mint)
                        }
                    }
                }

                Section {
                    if isLoadingIssuers {
                        HStack {
                            Spacer()
                            ProgressView("Loading issuers…")
                            Spacer()
                        }
                    } else {
                        ForEach(availableIssuers) { issuer in
                            Button {
                                install(issuer)
                            } label: {
                                HStack {
                                    Text(issuer.name)
                                        .foregroundStyle(.primary)
                                    Spacer()
                                    if installingIssuerID == issuer.id {
                                        ProgressView()
                                    } else {
                                        Image(systemName: "chevron.right")
                                            .font(.caption.bold())
                                            .foregroundStyle(.tertiary)
                                    }
                                }
                            }
                            .disabled(installingIssuerID != nil)
                        }

                        if availableIssuers.isEmpty, store.setupError == nil {
                            Text(store.isConfigured ? "No other issuers are available." : "This setup service has no issuers configured.")
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Available issuers")
                } footer: {
                    Text("Choose the organisation whose membership cards this scanner should trust.")
                }

                if let error = store.setupError {
                    Section {
                        Text(error).foregroundStyle(.red)
                        Button("Try again") { loadIssuers() }
                    }
                }

                Section {
                    Button("Use a custom setup URL", systemImage: "link") {
                        isPresentingCustomSetupURL = true
                    }
                }

                if store.provisioningError != nil {
                    Section {
                        if let error = store.provisioningError {
                            Text(error).foregroundStyle(.red)
                        }
                    }
                }
            }
            .navigationTitle("Configure issuer")
            .navigationBarTitleDisplayMode(.inline)
            .task { await loadIssuersOnPresentation() }
            .sheet(isPresented: $isPresentingCustomSetupURL) {
                CustomSetupURLView(initialURL: setupURL) { customURL in
                    setupURL = customURL
                    loadIssuers()
                }
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: dismiss.callAsFunction)
                }
            }
        }
    }

    private var availableIssuers: [SetupIssuer] {
        guard let installedID = store.configuration?.issuer.id else { return store.availableIssuers }
        return store.availableIssuers.filter { $0.id != installedID }
    }

    private func loadIssuersOnPresentation() async {
        isLoadingIssuers = true
        await store.discoverIssuers(from: setupURL)
        isLoadingIssuers = false
    }

    private func loadIssuers() {
        isLoadingIssuers = true
        Task {
            await store.discoverIssuers(from: setupURL)
            isLoadingIssuers = false
        }
    }

    private func install(_ issuer: SetupIssuer) {
        installingIssuerID = issuer.id
        Task {
            await store.provision(issuer)
            installingIssuerID = nil
        }
    }
}

private struct CustomSetupURLView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var setupURL: String
    let load: (String) -> Void

    init(initialURL: String, load: @escaping (String) -> Void) {
        _setupURL = State(initialValue: initialURL)
        self.load = load
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("https://example.com/setup", text: $setupURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                } header: {
                    Text("Setup service")
                } footer: {
                    Text("Only use an address you trust. The selected issuer's public key and name model will be downloaded from this service.")
                }
            }
            .navigationTitle("Custom setup URL")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: dismiss.callAsFunction)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Load") {
                        let value = setupURL.trimmingCharacters(in: .whitespacesAndNewlines)
                        dismiss()
                        load(value)
                    }
                    .disabled(setupURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}

private struct PermissionView: View {
    let symbol: String
    let title: String
    let message: String
    let actionTitle: String
    let action: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: symbol).font(.system(size: 52)).foregroundStyle(.mint)
            Text(title).font(.title2.bold())
            Text(message).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button(actionTitle, action: action).buttonStyle(.borderedProminent).tint(.mint)
        }
        .padding(32)
    }
}

private struct ScanResultView: View {
    let result: MembershipVerificationResult
    let issuer: IssuerProfile?
    let scanAgain: () -> Void

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    if case let .verified(membership) = result {
                        verifiedContent(membership)
                    } else {
                        errorContent
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(24)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .safeAreaInset(edge: .bottom) {
                Button("Scan another card", action: scanAgain)
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .buttonStyle(.borderedProminent)
                    .tint(.mint)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background(.bar)
            }
            .toolbar(.hidden, for: .navigationBar)
        }
    }

    private func verifiedContent(_ membership: VerifiedMembership) -> some View {
        VStack(alignment: .leading, spacing: 24) {
            Label("Signature verified", systemImage: "checkmark.shield.fill")
                .font(.subheadline.bold())
                .textCase(.uppercase)
                .foregroundStyle(.mint)

            issuerCard(for: membership)

            Text(membership.name)
                .font(.largeTitle.bold())
                .frame(maxWidth: .infinity, alignment: .leading)

            memberIdentifier(for: membership)

            ForEach(membership.flags.sorted(), id: \.self) { flag in
                Text(issuer?.label(for: flag) ?? "Flag \(flag)")
                    .font(.title3.weight(.semibold))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
                    .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
            }
        }
    }

    @ViewBuilder private func memberIdentifier(for membership: VerifiedMembership) -> some View {
        switch membership.memberIdentifier {
        case .none:
            EmptyView()
        case let .number(identifier):
            LabeledContent("Member number", value: String(identifier))
                .foregroundStyle(.secondary)
        case let .text(identifier):
            LabeledContent("Member identifier", value: identifier)
                .foregroundStyle(.secondary)
        }
    }

    private func issuerCard(for membership: VerifiedMembership) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Issuer")
                .font(.caption.weight(.semibold))
                .textCase(.uppercase)
                .foregroundStyle(.secondary)
            Text(issuer?.name ?? "Configured issuer")
                .font(.title3.bold())
            if let description = issuer?.description, !description.isEmpty {
                Text(description)
                    .foregroundStyle(.secondary)
            }
            Divider()
            LabeledContent("Issued", value: issueDate(for: membership.issueDay))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(20)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 18))
    }

    private var errorContent: some View {
        VStack(spacing: 20) {
            switch result {
            case let .rejected(reason):
                Image(systemName: "xmark.shield.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.red)
                Text("Invalid card").font(.largeTitle.bold())
                Text(reason)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            case .trustedIssuerUnavailable:
                Image(systemName: "key.slash.fill")
                    .font(.system(size: 64))
                    .foregroundStyle(.orange)
                Text("Issuer unavailable").font(.largeTitle.bold())
                Text("The card is structurally valid, but no trusted issuer is configured. Its name and flags have not been displayed.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            case .verified:
                EmptyView()
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 32)
    }

    private func issueDate(for issueDay: UInt16) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let epoch = calendar.date(from: DateComponents(year: 2026, month: 1, day: 1))!
        let date = calendar.date(byAdding: .day, value: Int(issueDay), to: epoch)!
        let formatter = DateFormatter()
        formatter.dateStyle = .long
        formatter.timeStyle = .none
        formatter.timeZone = calendar.timeZone
        return formatter.string(from: date)
    }
}
