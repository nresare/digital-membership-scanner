import AVFoundation
import SwiftUI
import UIKit
import ZXingCpp

struct QRScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (Data) -> Void
    let onFailure: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onCodeScanned = onCodeScanned
        controller.onFailure = onFailure
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ uiViewController: ScannerViewController, coordinator: ()) {
        uiViewController.stopScanning()
    }
}

final class ScannerViewController: UIViewController, AVCaptureVideoDataOutputSampleBufferDelegate {
    var onCodeScanned: ((Data) -> Void)?
    var onFailure: ((String) -> Void)?

    private let captureSession = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "digital-membership.capture")
    private let barcodeReader = ZXIBarcodeReader()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasDeliveredCode = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureCaptureSession()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    func stopScanning() {
        sessionQueue.async { [captureSession] in
            if captureSession.isRunning { captureSession.stopRunning() }
        }
    }

    private func configureCaptureSession() {
        guard let camera = AVCaptureDevice.default(for: .video) else {
            onFailure?("This device does not have an available camera.")
            return
        }

        do {
            let input = try AVCaptureDeviceInput(device: camera)
            guard captureSession.canAddInput(input) else {
                onFailure?("The camera input could not be configured.")
                return
            }
            captureSession.addInput(input)

            let output = AVCaptureVideoDataOutput()
            output.alwaysDiscardsLateVideoFrames = true
            output.videoSettings = [
                kCVPixelBufferPixelFormatTypeKey as String:
                    kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
            ]
            output.setSampleBufferDelegate(self, queue: sessionQueue)
            guard captureSession.canAddOutput(output) else {
                onFailure?("QR code scanning could not be configured.")
                return
            }
            captureSession.addOutput(output)

            let layer = AVCaptureVideoPreviewLayer(session: captureSession)
            layer.videoGravity = .resizeAspectFill
            view.layer.addSublayer(layer)
            previewLayer = layer

            sessionQueue.async { [captureSession] in captureSession.startRunning() }
        } catch {
            onFailure?("Camera setup failed: \(error.localizedDescription)")
        }
    }

    func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        guard !hasDeliveredCode,
              let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer),
              let result = try? barcodeReader.read(pixelBuffer).first,
              result.format == .QR_CODE else { return }

        hasDeliveredCode = true
        let bytes = result.bytes
        DispatchQueue.main.async { [weak self] in
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            self?.onCodeScanned?(bytes)
            self?.stopScanning()
        }
    }
}
