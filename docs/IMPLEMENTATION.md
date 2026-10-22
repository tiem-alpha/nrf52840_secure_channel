# LKP1 implementation map

This document fixes the wire-level choices needed to integrate the three
implementations. `README.md` is authoritative if a conflict is found.

## Module boundaries

| Layer | Responsibility | No dependency on |
|---|---|---|
| BLE NUS transport | one connection, fragment delivery, notification and disconnect | certificate or command policy |
| LKP1 framing | bounded record encode/decode, 5 s inter-fragment timeout | BLE and crypto |
| LKP1 handshake | message ordering, transcript, authentication and key schedule | BLE and application commands |
| LKP1 record protection | AES-GCM, counters, session ID and replay checks | BLE and application commands |
| Identity store | leaf key/certificate, chain and two pinned roots | BLE |
| Command policy | ACL by authenticated `device_id`, authorization of commands | handshake internals |

Firmware uses PSA Crypto. Android uses JCA and a provider abstraction for the
long-term signing key. The Python implementation is the executable reference;
its machine-readable vector file is the integration fixture for C and Kotlin.

## Record layout and flight boundaries

- F1: one clear HANDSHAKE record holding M1.
- F2: one clear HANDSHAKE record holding M2, followed by one HANDSHAKE_ENC
  record whose plaintext is M3 || M4 || M5.
- F3: one HANDSHAKE_ENC record whose plaintext is M6 || M7 || M8.
- A handshake message includes its 3-byte header in the transcript. Each
  encrypted record has a 4-byte clear record header as AES-GCM AAD, with
  `body_len` equal to ciphertext length plus 16-byte tag.
- For APP_DATA, the 4-byte record header, 4-byte session ID, and 4-byte
  sequence number are AAD. The clear `body_len` includes these eight bytes,
  ciphertext, and tag. Both directional sequence numbers start at zero.

## Certificate and identity decisions

A transmitted chain contains the leaf first and at most one issuing CA. The
pinned root is not transmitted. A leaf issued directly by a root has a
one-certificate chain. The verifier checks each signature, issuer key ID,
role, usage and validity policy from `README.md`. The lock uses the validated
PHONE certificate's `subject_id` for a separate command ACL. The phone compares
the LOCK certificate's `subject_id` to the serial pinned at setup.

Factory material remains external to the firmware source tree. A production
build needs a provisioned signing key, certificate chain, and pinned roots;
the sample must fail closed if these are absent. No production secret may be
committed to the repository.

## Cross-language acceptance

The fixed vector covers M1 through M8, both encrypted handshake records,
master, directional application keys/IVs, session ID, and APP_DATA sequence
zero. The Python generator owns the fixture. C and Kotlin tests must compare
the same bytes, including record headers and tags. Negative tests cover all
cases in README section 13. The firmware build and BLE handshake timing need
an nRF52840 toolchain and device respectively; host tests alone cannot claim
those results.
