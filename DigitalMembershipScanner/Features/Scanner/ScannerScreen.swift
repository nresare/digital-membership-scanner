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
        .preferredColorScheme(.dark)
        .sheet(item: $result) { result in
            ScanResultView(result: result) { resetScanner() }
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
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 14)
                    .background(.black.opacity(0.72), in: Capsule())
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
        case .rejected, .trustedKeyUnavailable:
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
                Section {
                    if isLoadingIssuers {
                        HStack {
                            Spacer()
                            ProgressView("Loading issuers…")
                            Spacer()
                        }
                    } else {
                        ForEach(store.availableIssuers) { issuer in
                            Button {
                                install(issuer)
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(issuer.description)
                                            .foregroundStyle(.primary)
                                        Text(issuer.id)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
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

                        if store.availableIssuers.isEmpty, store.setupError == nil {
                            Text("This setup service has no issuers configured.")
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

                if store.isConfigured || store.provisioningError != nil {
                    Section {
                        if store.isConfigured {
                            Label("An issuer configuration is installed", systemImage: "checkmark.shield.fill")
                                .foregroundStyle(.green)
                        }
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
    let scanAgain: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                statusIcon.font(.system(size: 64))
                Text(title).font(.largeTitle.bold())
                Text(message).multilineTextAlignment(.center).foregroundStyle(.secondary)

                if case let .verified(membership) = result {
                    GroupBox("Membership") {
                        VStack(alignment: .leading, spacing: 10) {
                            LabeledContent("Name", value: membership.name)
                            LabeledContent("Key ID", value: String(membership.keyID))
                            LabeledContent("Flags", value: membership.flags.sorted().map(String.init).joined(separator: ", "))
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                Button("Scan another card", action: scanAgain)
                    .buttonStyle(.borderedProminent)
                    .tint(.mint)
            }
            .padding(24)
            .navigationTitle("Scan result")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    @ViewBuilder private var statusIcon: some View {
        switch result {
        case .verified: Image(systemName: "checkmark.shield.fill").foregroundStyle(.green)
        case .rejected: Image(systemName: "xmark.shield.fill").foregroundStyle(.red)
        case .trustedKeyUnavailable: Image(systemName: "key.slash.fill").foregroundStyle(.orange)
        }
    }

    private var title: String {
        switch result {
        case .verified: "Valid membership"
        case .rejected: "Invalid card"
        case .trustedKeyUnavailable: "Key unavailable"
        }
    }

    private var message: String {
        switch result {
        case .verified: "The membership signature is valid."
        case let .rejected(reason): reason
        case let .trustedKeyUnavailable(keyID):
            "The card is structurally valid, but no trusted BLS public key is configured for key ID \(keyID). Its name and flags have not been displayed."
        }
    }
}
