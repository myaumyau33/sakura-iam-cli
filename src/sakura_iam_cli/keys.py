from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sakura_iam_cli import errors


def generate_key_pairs(output_dir: Path, num: int, bits: int = 2048) -> list[Path]:
    if num < 1:
        raise errors.CliError("--num must be at least 1")
    if bits not in (2048, 3072, 4096):
        raise errors.CliError("--bits must be 2048, 3072, or 4096")
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    width = max(3, len(str(num)))
    for index in range(1, num + 1):
        stem = f"sp-key-{index:0{width}d}"
        private_path = output_dir / f"{stem}.private.pem"
        public_path = output_dir / f"{stem}.public.pem"
        if private_path.exists() or public_path.exists():
            raise errors.CliError(f"refusing to overwrite an existing key: {stem}")
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        private_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_path.write_bytes(private_bytes)
        os.chmod(private_path, 0o600)
        public_path.write_bytes(public_bytes)
        os.chmod(public_path, 0o644)
        created.append(public_path)
    return created
