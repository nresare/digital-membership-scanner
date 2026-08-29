import AVFoundation
import SwiftUI
import UIKit

struct ScannerScreen: View {
    @StateObject private var issuerStore = IssuerTrustStore()

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
                onCodeScanned: { result = issuerStore.validator().validate($0) },
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

private struct IssuerConfigurationView: View {
    @ObservedObject var store: IssuerTrustStore
    @Environment(\.dismiss) private var dismiss
    @State private var provisioningURL = ""
    @State private var isLoading = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Trusted issuer") {
                    Text("Scanning never downloads a key. Import the issuer configuration yourself before scanning cards.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    TextField("Provisioning URL", text: $provisioningURL)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                }

                if store.isConfigured {
                    Section {
                        Label("An issuer configuration is installed", systemImage: "checkmark.shield.fill")
                            .foregroundStyle(.green)
                    }
                }

                if let error = store.provisioningError {
                    Section {
                        Text(error).foregroundStyle(.red)
                    }
                }

                Section {
                    Button {
                        isLoading = true
                        Task {
                            await store.provision(from: provisioningURL)
                            isLoading = false
                        }
                    } label: {
                        if isLoading {
                            HStack { Spacer(); ProgressView(); Spacer() }
                        } else {
                            Label("Download and trust issuer", systemImage: "arrow.down.circle")
                        }
                    }
                    .disabled(provisioningURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isLoading)
                } footer: {
                    Text("Only use an address you trust. An issuer configuration can validate every card that uses its key ID.")
                }
            }
            .navigationTitle("Configure issuer")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done", action: dismiss.callAsFunction)
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
