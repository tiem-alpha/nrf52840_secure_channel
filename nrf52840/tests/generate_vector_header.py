"""Turn the checked-in Python fixture into C arrays for the host test."""
import json
import pathlib
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text())
output = pathlib.Path(sys.argv[2])
names = {
    "inputs": ["server_ephemeral_private", "server_nonce", "server_private", "server_chain", "roots", "client_id"],
    "messages": [f"M{i}" for i in range(1, 9)],
    "records": ["F1", "F2a", "F2b", "F3", "app0"],
    "secrets": ["c_hs_key", "c_hs_iv", "s_hs_key", "s_hs_iv", "c_fin_key", "s_fin_key", "c2s_key", "c2s_iv", "s2c_key", "s2c_iv", "session_id"],
}
lines = ["/* Generated from python/tests/vectors.json. Do not edit. */", "#include <stdint.h>"]
for group, keys in names.items():
    for key in keys:
        value = fixture[group][key]
        if isinstance(value, list):
            value = value[0]
        raw = bytes.fromhex(value)
        ident = f"v_{key}"
        lines.append(f"static const uint8_t {ident}[{len(raw)}] = {{")
        lines.append(",".join(f"0x{b:02x}" for b in raw) + "};")
for key in ["app0_plaintext"]:
    raw = bytes.fromhex(fixture[key])
    lines.append(f"static const uint8_t v_{key}[{len(raw)}] = {{")
    lines.append(",".join(f"0x{b:02x}" for b in raw) + "};")
output.write_text("\n".join(lines) + "\n")
