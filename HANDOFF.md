# Digital Membership Scanner — development handoff

Last updated: 2026-08-29

## Goal

Build a native iOS app that scans and verifies digital membership cards encoded according to:

- Repository: <https://github.com/nresare/digital-membership>
- Format specification: <https://github.com/nresare/digital-membership/blob/main/specification.md>

This directory was empty when work started. It is still **not a Git repository**; initialize Git on the personal computer if desired.

## Current state

There is a working Xcode project at `DigitalMembershipScanner.xcodeproj`, targeting iOS 17 or later.

Implemented:

- SwiftUI scanner interface and camera-permission states.
- AVFoundation camera preview and frame capture.
- Raw-binary QR decoding through ZXing-C++ 3.1.1, pinned with Swift Package Manager.
- Version 1 binary credential parser matching the current draft specification.
- Header version and key-ID extraction.
- Short and extended flag-length parsing.
- Little-endian flag bitset decoding.
- Minimum-length and bounds validation before slicing.
- Minimal flag encoding enforcement.
- UTF-8 name length, encoding, and control-character validation.
- A validation boundary (`MembershipSignatureVerifying`) that prevents the UI from displaying the name or flags until signature verification succeeds.
- SwiftUI results for verified, rejected, and missing-trusted-key states.
- Camera privacy description and a shared Xcode scheme.
- Xcode unit tests plus a host-side Swift package test suite.

The app currently compiles, scans raw QR bytes, and validates credential structure. It does **not yet perform BLS signature verification**, so it deliberately reports a structurally valid credential as “Key unavailable” and does not reveal its name or flags.

## Important files

- `DigitalMembershipScanner/App/DigitalMembershipScannerApp.swift` — app entry point.
- `DigitalMembershipScanner/Features/Scanner/ScannerScreen.swift` — scanner and result UI.
- `DigitalMembershipScanner/Scanner/QRScannerView.swift` — camera frames and ZXing-C++ raw-byte decoding.
- `DigitalMembershipScanner/Membership/MembershipCredential.swift` — parser, models, validator, and signature-verifier protocol.
- `DigitalMembershipScannerTests/MembershipCredentialTests.swift` — iOS/XCTest parser tests.
- `Package.swift` and `DigitalMembershipCoreTests/` — simulator-free host tests using the same production parser source.
- `README.md` — short usage and architecture notes.

## Verified status

The project file passes `plutil -lint`.

The iOS app compiled successfully with Xcode 26.6 using:

```bash
xcodebuild \
  -project DigitalMembershipScanner.xcodeproj \
  -scheme DigitalMembershipScanner \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

The host-side parser suite passes all 8 tests:

```bash
swift test
```

The tests cover the specification example, extended flag lengths, short credentials, unsupported versions, non-minimal lengths/flags, control characters, and suppression of the name when no trusted key exists.

## Managed-computer signing problem

Simulator XCTest execution could not start on the original managed Mac. The local unified log showed AMFI rejecting the simulator app because it was ad-hoc signed or signed by an unknown certificate chain. Santa itself was in Monitor mode and reported the binaries as allowed; Kandji was also scanning generated artifacts.

The keychain had zero valid code-signing identities. Moving DerivedData from `/tmp` into the home-directory workspace did not fix the simulator launch.

This should not be a problem on a normal personal Mac. If it occurs there:

1. In Xcode, open Settings → Accounts and sign in with an Apple ID.
2. Use Manage Certificates to create an Apple Development certificate.
3. Select the development team under the app target’s Signing & Capabilities.
4. Clean and rebuild.

Host-side `swift test` works without launching an iOS simulator and was used to verify parser behavior on the managed computer.

Do not copy `DerivedData/` or `.build/` to the new machine; both are generated and ignored.

## Highest-priority next work

### 1. Implement BLS12-381 verification

Implement `MembershipSignatureVerifying` using a well-maintained cryptographic library, likely the upstream `blst` library from Supranational after assessing the best iOS packaging approach.

Required rules from the specification:

- Ciphersuite: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`.
- Minimal-signature-size variant.
- Signature: canonical 48-byte compressed G1 point, non-identity and in the correct subgroup.
- Public key: canonical 96-byte compressed G2 point, non-identity and in the correct subgroup.
- Signed message: ASCII `digital-membership/v1\x00` followed by the complete unsigned credential.
- Key ID selects one of up to eight trusted public keys configured out of band.

`MembershipCredentialParser.domainPrefix` already contains the required prefix, and `ParsedMembershipCredential` exposes `unsignedCredential` and `signature` to a verifier. Only construct/display `VerifiedMembership` after cryptographic verification returns true.

### 2. Decide how trusted keys are provisioned

The reference issuer exposes `GET /public-key`, returning the algorithm, key ID, and an unpadded Base64URL-encoded 96-byte public key. The service currently generates a fresh key whenever it starts.

Choose a production trust model. Plausible first iteration:

- A settings/configuration screen imports issuer URL and public key while online.
- Validate the algorithm and exact decoded key length.
- Persist trusted public keys by key ID in the Keychain or an app configuration bundle.
- Perform card verification entirely offline after provisioning.

Do not silently fetch a key from an issuer in response to scanning a card; that would let an untrusted card choose its own trust root.

### 3. End-to-end fixtures and device test

- Add deterministic public key, signed credential, and invalid-signature fixtures to the specification/reference repository or this app.
- Test a valid card, altered header/name/flags, incorrect key ID, malformed points, identity points, and unknown flags.
- Generate a real QR with the Rust service and scan it on a physical iPhone.
- Confirm that ZXing-C++ `result.bytes` exactly matches the issuer’s credential bytes, including embedded zero and non-UTF-8 bytes.

### 4. Product polish

- Add an app icon and issuer branding.
- Define user-facing meanings for flags through an issuer profile; never grant access based on unknown flags.
- Add accessibility and camera lifecycle tests.
- Consider a torch control and scan-area optimization.
- Decide whether iPad support is desired; it is currently enabled.

## Security constraints from version 1

The current specification authenticates only the display name and flags. It does not provide expiry, revocation, a stable credential identifier, bearer identity verification, event restriction, confidentiality, or protection against copied screenshots. The UI and any authorization decisions should not claim those properties.

Never display the parsed name before signature verification. Parsing structural validity alone is not membership validity.

## Suggested opening prompt for the next Codex session

> Continue the iOS Digital Membership Scanner from `HANDOFF.md`. First inspect the existing project and rerun `swift test` plus an Xcode build. Then implement production-grade BLS12-381 minimal-signature-size verification behind `MembershipSignatureVerifying`, with deterministic interoperability fixtures from the reference Rust implementation. Preserve the rule that names and flags are never displayed before successful signature verification.

