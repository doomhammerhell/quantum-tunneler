"""Independent laboratory ESP oracle. Requires Python cryptography (45.0.5 tested).
All inputs below are PUBLIC test material. Never use them in a tunnel.
Run from the repository root; overwrites only committed test fixtures.
"""
from pathlib import Path
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

info = (b"quantum-tunneler/experimental/esp/aes256gcm/v1"
        + (256).to_bytes(4, "big") + (257).to_bytes(4, "big")
        + (1).to_bytes(8, "big") + bytes([2]) * 32
        + b"/initiator-to-responder")
material = HKDF(algorithm=hashes.SHA256(), length=36,
                salt=bytes([1]) * 32, info=info).derive(bytes([7]) * 32)
header = (257).to_bytes(4, "big") + (1).to_bytes(4, "big")
iv = (1).to_bytes(8, "big")
nonce = material[32:] + iv
payload = b"independent ESP fixture"
pad = (-(len(payload) + 2)) % 4
body = payload + bytes(range(1, pad + 1)) + bytes([pad, 4])
fixtures = Path("quantum_ipsec/tests/fixtures")
for name, plaintext in [("esp", body), ("bad_padding", bytes([9, 2, 2, 4]))]:
    wire = header + iv + AESGCM(material[:32]).encrypt(nonce, plaintext, header)
    (fixtures / f"{name}.hex").write_text(wire.hex() + "\n")
# Same public key/nonce intentionally used for separate negative test fixtures,
# never live traffic. Each fixture is tested with an isolated inbound SA.
