# Digital Membership Scanner

A native iOS app for scanning QR-encoded digital membership cards.

The camera, raw-binary QR capture, and version 1 credential parser are implemented according to the [Digital Membership binary format](https://github.com/nresare/digital-membership/blob/main/specification.md).

## Requirements

- Xcode 26 or later
- iOS 17 or later
- A physical iPhone for camera testing

## Open and run

1. Open `DigitalMembershipScanner.xcodeproj` in Xcode.
2. Select the `DigitalMembershipScanner` scheme.
3. Choose your development team under Signing & Capabilities.
4. Run on an iPhone and grant camera permission.

The simulator build is useful for UI and unit tests, but scanning requires a camera-equipped device.

Core format tests can also run without the simulator:

```bash
swift test
```

This host-side route is useful on managed Macs that disallow ad-hoc-signed simulator test hosts.

## Architecture

- `Scanner/QRScannerView.swift` owns AVFoundation camera capture and uses ZXing-C++ to preserve raw QR bytes.
- `Membership/MembershipCredential.swift` parses the binary format and gates display behind `MembershipSignatureVerifying`.
- `Features/Scanner/ScannerScreen.swift` presents scanner state and results.

## Security status

QR contents are captured locally and are not transmitted. The app validates the complete version 1 binary structure. A trusted BLS public key and BLS12-381 verifier still need to be configured before a membership can be accepted. Until then, the app does not display the encoded name or flags.
