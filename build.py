from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import pbkdf2_hmac


ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / ".ignore" / "dist"
OUTPUT_DIR = ROOT / "dist"
PAYLOAD_PATH = OUTPUT_DIR / "site.enc.json"
ENCRYPTED_DIR = OUTPUT_DIR / "encrypted"
ITERATIONS = 600_000  # Bumped from 250k to meet OWASP recommendation for PBKDF2-SHA256


def load_dotenv_key(env_path: Path) -> str | None:
    if not env_path.exists():
        return None

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        name, value = line.split("=", 1)
        if name.strip() != "key":
            continue

        return value.strip().strip('"').strip("'")

    return None


def resolve_password(cli_password: str | None) -> str:
    password = cli_password or os.environ.get("NANOSITE_PASSWORD") or load_dotenv_key(ROOT / ".env")
    if not password:
        raise SystemExit("Missing password. Use --password, NANOSITE_PASSWORD, or .env key=...")
    return password


def collect_site_files(source_dir: Path) -> dict[str, dict[str, object]]:
    if not source_dir.exists():
        raise SystemExit(f"Source directory does not exist: {source_dir}")

    files: dict[str, dict[str, object]] = {}
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue

        rel_path = path.relative_to(source_dir).as_posix()
        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        files[rel_path] = {"mime": mime_type, "bytes": path.read_bytes()}

    if "index.html" not in files:
        raise SystemExit("Source site is missing .ignore/dist/index.html")

    return files


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a single AES-256 key from the password. Called once per build."""
    return pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32)


def build_payload(password: str, files: dict[str, dict[str, object]]) -> dict[str, object]:
    # Derive one key for all files — cracking one file gives nothing extra,
    # and an attacker still has to run the full PBKDF2 to verify any guess.
    salt = os.urandom(16)
    key = derive_key(password, salt)

    manifest_files: dict[str, dict[str, object]] = {}

    for rel_path, info in files.items():
        plaintext = info["bytes"]
        encrypted_rel_path = f"encrypted/{rel_path}.enc"
        encrypted_path = OUTPUT_DIR / encrypted_rel_path
        encrypted_path.parent.mkdir(parents=True, exist_ok=True)

        # Each file still gets its own random IV — required for GCM security.
        iv = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(iv, plaintext, None)
        encrypted_path.write_bytes(ciphertext)

        manifest_files[rel_path] = {
            "mime": info["mime"],
            "encrypted_path": encrypted_rel_path,
            "size": len(plaintext),
            "iv": base64.b64encode(iv).decode("ascii"),
        }

    return {
        # KDF parameters are now global — one salt, one key for all files.
        "kdf": "PBKDF2-SHA256",
        "iterations": ITERATIONS,
        "cipher": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("ascii"),
        "files": manifest_files,
    }


def prepare_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(exist_ok=True)
    for child in output_dir.iterdir():
        if child.name in {"index.html", "decrypt.js"}:
            continue
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def clean_output_dir(output_dir: Path) -> None:
    prepare_output_dir(output_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an encrypted nanosite payload.")
    parser.add_argument("--password", help="Override the password used to encrypt the site.")
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove generated encrypted artifacts from dist/ without rebuilding.",
    )
    args = parser.parse_args()

    if args.clean:
        clean_output_dir(OUTPUT_DIR)
        print(f"Removed generated encrypted artifacts from {OUTPUT_DIR}")
        return

    password = resolve_password(args.password)
    files = collect_site_files(SOURCE_DIR)

    prepare_output_dir(OUTPUT_DIR)
    payload = build_payload(password, files)
    PAYLOAD_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(
        f"Encrypted {len(files)} files from {SOURCE_DIR} into {PAYLOAD_PATH} "
        f"and {ENCRYPTED_DIR}"
    )


if __name__ == "__main__":
    main()
