# Android prototype client

The app uses NUS for LKP1 and Nordic McuMgr BLE 2.7.2 for MCUboot FOTA. The protocol code lives in `lkp1/`, separate from `ble/` and the Compose screen. Commands are enabled only after the three-flight handshake authenticates the lock certificate against the imported root and pinned serial.

## Prototype setup

1. Generate a phone leaf with the Python provisioning CLI on the provisioning PC. Import its JSON through **Import phone identity**. The Mode A private key stays in memory for the current app process. Never package a private key in the APK.
2. Enter the lock BLE address and its 16-byte serial from a trusted setup record (32 hex digits), then connect. Notifications are enabled before ClientHello. MTU 247 is requested; Android negotiates data length.
3. **Send demo command** emits APP_DATA plaintext `01 64 65 6d 6f` after the channel opens. The lock must authorize this phone device ID before acting on the command.
4. For FOTA, select a signed MCUboot image. The app ends the LKP1 session and waits for the NUS GATT disconnect callback before opening McuMgr SMP because firmware permits only one BLE connection. SMP requires an encrypted LE Secure Connections Just Works link; accept the system pairing prompt if shown. McuMgr SMP is separate from LKP1 NUS. MCUboot must enforce image signatures with its provisioned signing key.

The app takes a manually entered BLE address; it has no scanner or QR setup flow. Mode B Android Keystore provisioning can implement `KeyStoreProvider`, but CSR issuance and certificate storage are future product integration. Prototype JSON contains sensitive key material. FOTA currently has no progress view or app-side policy check.

## Tests

Run `./gradlew :app:testDebugUnitTest --no-configuration-cache` from `mobile/`.

The vector test uses the Python fixture to check certificate validation, X25519/HKDF keys, encrypted F2, and master/session derivation. BLE behavior requires device testing.
