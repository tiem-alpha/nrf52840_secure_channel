# LKP1 Python reference

Requires Python 3 and `cryptography>=41`. From this directory run
`python3 -m unittest discover -s tests -v`.

Provisioning example: `PYTHONPATH=. python3 -m lkp1.provisioning root root.json`,
then `issuing-ca root.json ca.json --id <16-byte-hex>` and
`leaf ca.json lock.json --type lock --id <16-byte-hex>` (or `phone`).
Private artifacts are created with mode 0600 and must be kept offline.
For a lock leaf, `firmware-header lock.json
../nrf52840/include/factory_credentials.h --allow-phone phone.json` emits the
firmware identity header and an allowed phone ID. Repeat `--allow-phone` for
more phones. With no allowed phones, the generated count is zero and the
firmware must reject application commands.
The phone and lock JSON files are separate; never package the CA private key
or lock private key into the app. The generated firmware header contains the
lock private key and must be protected as a factory secret.

Wire flight F2 is one clear HANDSHAKE record M2 followed by one
HANDSHAKE_ENC record whose plaintext is M3||M4||M5. F3 is one
HANDSHAKE_ENC record containing M6||M7||M8. The AEAD AAD is the complete
four-byte record header with encrypted body length.
