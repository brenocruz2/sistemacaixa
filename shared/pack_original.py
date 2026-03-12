from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def pack_file(source: Path, output: Path, key_path: Path) -> None:
    key = key_path.read_bytes()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = source.read_bytes()
    ciphertext = aes.encrypt(nonce, plaintext, b"laserbox-protected-app")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(nonce + ciphertext)
    meta = {
        "source_name": source.name,
        "nonce_size": 12,
        "aad": "laserbox-protected-app",
        "encrypted_size": len(ciphertext),
    }
    output.with_suffix(output.suffix + ".json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Protegido: {source} -> {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Empacota o index.html em bundle criptografado.")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("key", type=Path)
    args = parser.parse_args()
    pack_file(args.source, args.output, args.key)
