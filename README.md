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
- `Membership/MembershipCredential.swift` parses the binary format, verifies minimal-signature-size BLS12-381 signatures, and gates display behind `MembershipSignatureVerifying`.
- `Features/Scanner/ScannerScreen.swift` presents scanner state and results.

The BLS implementation is the audited upstream [`supranational/blst`](https://github.com/supranational/blst)
source, pinned and packaged locally under `Vendor/BlstPackage`. Verification rejects malformed,
non-canonical, identity, and wrong-subgroup G1 signatures and G2 public keys before pairing.

## Security status

QR contents are captured locally and are not transmitted. The app validates the version 1 binary
structure and implements BLS12-381 verification, but no issuer public key is provisioned by default.
Until a trusted key is supplied out of band, the app does not display the encoded name or flags.

The upstream format is now draft 0.4 and encodes names with `namecompress`. This checkout still
parses the earlier UTF-8 name field and therefore needs the issuer-specific name model integration
before it can read credentials produced by the current reference service.
