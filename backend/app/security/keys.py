"""Key storage for the GCS (GAP-08, GAP-12).

* MAVLink 2 signing secrets (32-byte shared keys): generated, activated, retired,
  revoked and exported for vehicle provisioning. The secret never leaves this
  module through the API — only key IDs and fingerprints do. Provisioning export
  writes a file for the maintenance workstation; it is never sent over telemetry
  (SPIDERS is receive-only and does not send SETUP_SIGNING).
* Ed25519 keys used to sign evidence ("evidence") and approved baselines
  ("approval"). Their public keys are published so a third party can verify.

Storage is a directory (default data/keys) protected by OS permissions. That is
software-only protection: it does not resist an administrator of this machine.
Production deployments should put these keys in an OS secret store or HSM.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEYRING = "mavlink_keyring.json"
STATUSES = ("generated", "active", "retired", "revoked")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _restrict(p: Path) -> None:
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def fingerprint(secret: bytes) -> str:
    """Public identifier of a MAVLink secret: SHA-256 prefix. Safe to log and display."""
    return hashlib.sha256(b"spiders-mavlink-key-id" + secret).hexdigest()[:16]


def public_key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


class KeyStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.mav_dir = self.root / "mavlink"
        self.prov_dir = self.root / "provisioning"
        for d in (self.root, self.mav_dir, self.prov_dir):
            d.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    # ------------------------------------------------------------ MAVLink signing secrets
    def _ring(self) -> list[dict]:
        p = self.root / KEYRING
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []

    def _save_ring(self, ring: list[dict]) -> None:
        p = self.root / KEYRING
        p.write_bytes(json.dumps(ring, indent=2).encode("utf-8"))
        _restrict(p)

    def mavlink_keys(self) -> list[dict]:
        """Metadata only — never the secret."""
        return [{k: v for k, v in r.items() if k != "file"} for r in self._ring()]

    def generate_mavlink_key(self, actor: str, note: str = "") -> dict:
        secret = secrets.token_bytes(32)
        kid = fingerprint(secret)
        with self._lock:
            f = self.mav_dir / f"{kid}.key"
            f.write_bytes(secret)
            _restrict(f)
            ring = self._ring()
            rec = {"key_id": kid, "status": "generated", "created_at": _now(), "created_by": actor, "note": note[:200],
                   "file": f.name, "activated_at": None, "retired_at": None, "revoked_at": None, "revoked_reason": None,
                   "provisioning_exports": []}
            ring.append(rec)
            self._save_ring(ring)
        return {k: v for k, v in rec.items() if k != "file"}

    def _find(self, ring, kid) -> dict:
        rec = next((r for r in ring if r["key_id"] == kid), None)
        if rec is None:
            raise KeyError(kid)
        return rec

    def secret(self, kid: str) -> bytes:
        rec = self._find(self._ring(), kid)
        if rec["status"] == "revoked":
            raise ValueError("key is revoked")
        b = (self.mav_dir / rec["file"]).read_bytes()
        if len(b) != 32 or fingerprint(b) != kid:
            raise ValueError("key file does not match its key ID")
        return b

    def activate(self, kid: str, actor: str) -> dict:
        with self._lock:
            ring = self._ring()
            rec = self._find(ring, kid)
            if rec["status"] == "revoked":
                raise ValueError("a revoked key cannot be activated")
            self.secret(kid)  # integrity check before switching
            for r in ring:
                if r["status"] == "active" and r["key_id"] != kid:
                    r["status"], r["retired_at"] = "retired", _now()
            rec.update(status="active", activated_at=_now(), activated_by=actor)
            self._save_ring(ring)
        return {k: v for k, v in rec.items() if k != "file"}

    def revoke(self, kid: str, actor: str, reason: str) -> dict:
        if not reason.strip():
            raise ValueError("a revocation reason is required")
        with self._lock:
            ring = self._ring()
            rec = self._find(ring, kid)
            rec.update(status="revoked", revoked_at=_now(), revoked_by=actor, revoked_reason=reason[:300])
            f = self.mav_dir / rec["file"]
            if f.exists():  # destroy the secret: a revoked key must not be usable again
                f.write_bytes(secrets.token_bytes(32))
                f.unlink()
            self._save_ring(ring)
        return {k: v for k, v in rec.items() if k != "file"}

    def active_mavlink_secret(self) -> tuple[Optional[str], Optional[bytes]]:
        rec = next((r for r in self._ring() if r["status"] == "active"), None)
        if rec is None:
            return None, None
        return rec["key_id"], self.secret(rec["key_id"])

    def export_for_provisioning(self, kid: str, actor: str) -> Path:
        """Write the secret (hex) for loading onto the vehicle over a maintenance link."""
        b = self.secret(kid)
        out = self.prov_dir / f"{kid}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.key"
        out.write_bytes(b.hex().encode("ascii") + b"\n")
        _restrict(out)
        with self._lock:
            ring = self._ring()
            self._find(ring, kid)["provisioning_exports"].append({"at": _now(), "by": actor, "file": out.name})
            self._save_ring(ring)
        return out

    # ------------------------------------------------------------ Ed25519 signing keys
    def signing_key(self, purpose: str) -> Ed25519PrivateKey:
        if purpose not in ("evidence", "approval", "release"):
            raise ValueError("unknown key purpose")
        p = self.root / f"{purpose}_ed25519.pem"
        passphrase = os.environ.get(f"SPIDERS_{purpose.upper()}_KEY_PASSPHRASE")
        with self._lock:
            if not p.exists():
                key = Ed25519PrivateKey.generate()
                enc = (serialization.BestAvailableEncryption(passphrase.encode()) if passphrase
                       else serialization.NoEncryption())
                p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
                _restrict(p)
                pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                (self.root / f"{purpose}_ed25519.pub.pem").write_bytes(pub)
                return key
        return serialization.load_pem_private_key(p.read_bytes(), passphrase.encode() if passphrase else None)

    def public_key_pem(self, purpose: str) -> str:
        p = self.root / f"{purpose}_ed25519.pub.pem"
        if not p.exists():
            self.signing_key(purpose)
        return p.read_text(encoding="utf-8")

    def trusted_public_keys(self, purpose: str) -> dict[str, Ed25519PublicKey]:
        """This GCS's own key plus any third-party keys dropped in data/keys/trusted_<purpose>/*.pub.pem."""
        keys = {}
        own = serialization.load_pem_public_key(self.public_key_pem(purpose).encode())
        keys[public_key_id(own)] = own
        extra = self.root / f"trusted_{purpose}"
        if extra.is_dir():
            for f in sorted(extra.glob("*.pem")):
                try:
                    k = serialization.load_pem_public_key(f.read_bytes())
                    if isinstance(k, Ed25519PublicKey):
                        keys[public_key_id(k)] = k
                except ValueError:
                    continue
        return keys


def sign_json(key: Ed25519PrivateKey, body: dict) -> dict:
    """Detached Ed25519 signature over canonical JSON (sorted keys, no spaces)."""
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {"algorithm": "Ed25519", "key_id": public_key_id(key.public_key()),
            "signature": base64.b64encode(key.sign(canon)).decode("ascii")}


def verify_json(body: dict, sig: dict, trusted: dict[str, Ed25519PublicKey]) -> str:
    """VALID | UNTRUSTED_KEY | INVALID."""
    pub = trusted.get(sig.get("key_id", ""))
    if pub is None:
        return "UNTRUSTED_KEY"
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    try:
        pub.verify(base64.b64decode(sig.get("signature", "")), canon)
        return "VALID"
    except Exception:
        return "INVALID"
