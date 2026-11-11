#!/usr/bin/env python3
"""Decrypt a packed GameAssembly.dll using a published version profile."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from decryptor.ga_static_decrypt import decode

MATERIALS = ("key", "sbox", "pass3", "records")


def load_profile(directory: Path, packed_hash: str) -> tuple[dict, dict[str, bytes]]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    expected_packed = manifest.get("packed_sha256")
    if expected_packed and expected_packed.lower() != packed_hash.lower():
        raise ValueError("packed GameAssembly.dll SHA-256 does not match profile manifest")
    payload = manifest.get("payload")
    if not isinstance(payload, int) or payload < 0:
        raise ValueError("invalid payload offset in profile manifest")

    materials: dict[str, bytes] = {}
    for name in MATERIALS:
        data = (directory / f"{name}.bin").read_bytes()
        meta = manifest.get(name)
        if isinstance(meta, dict) and meta.get("sha256"):
            if hashlib.sha256(data).hexdigest() != meta["sha256"].lower():
                raise ValueError(f"{name}.bin SHA-256 mismatch")
        materials[name] = data
    return manifest, materials


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packed", type=Path, help="Path to packed GameAssembly.dll")
    parser.add_argument("output", type=Path, help="Path to write decrypted GameAssembly.dll")
    parser.add_argument("--profile", type=Path, required=True, metavar="DIR", help="Profile directory")
    args = parser.parse_args()

    packed = args.packed.resolve(strict=True)
    output = args.output.resolve()
    profile = args.profile.resolve(strict=True)
    if output == packed or (output.exists() and os.path.samefile(packed, output)):
        raise ValueError("output path must differ from packed input path")

    packed_bytes = packed.read_bytes()
    packed_hash = hashlib.sha256(packed_bytes).hexdigest()
    manifest, materials = load_profile(profile, packed_hash)
    image, _ = decode(packed_bytes, materials, manifest["payload"])
    output_hash = hashlib.sha256(image).hexdigest()

    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".decrypt-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(image)
        os.replace(tmp_name, output)
    finally:
        Path(tmp_name).unlink(missing_ok=True)

    print(f"Decoded SHA-256: {output_hash}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[err] {exc}", file=sys.stderr)
        raise SystemExit(1)
