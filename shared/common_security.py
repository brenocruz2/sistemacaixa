from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

APP_ID = "laserbox-pro-v10"
APP_VERSION = "1.0.0"
UTC = dt.timezone.utc


def utc_now() -> dt.datetime:
    return dt.datetime.now(UTC)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat()


def parse_iso_date(value: str) -> dt.datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def safe_digits(value: str) -> str:
    return re.sub(r"\D+", "", value or "")


def format_cep(value: str) -> str:
    digits = safe_digits(value)[:8]
    if len(digits) <= 5:
        return digits
    return f"{digits[:5]}-{digits[5:8]}"


def format_phone_br(value: str) -> str:
    digits = safe_digits(value)[:13]
    if not digits:
        return ""
    if digits.startswith("55") and len(digits) >= 12:
        digits = digits[2:]
    if len(digits) <= 2:
        return f"({digits}"
    if len(digits) <= 6:
        return f"({digits[:2]}) {digits[2:]}"
    if len(digits) <= 10:
        return f"({digits[:2]}) {digits[2:6]}-{digits[6:10]}"
    return f"({digits[:2]}) {digits[2:7]}-{digits[7:11]}"


def phone_to_wa_link(value: str) -> str:
    digits = safe_digits(value)
    if digits and not digits.startswith("55"):
        digits = "55" + digits
    return f"https://wa.me/{digits}" if digits else "https://wa.me/"


def format_cpf_cnpj(value: str) -> str:
    digits = safe_digits(value)[:14]
    if len(digits) <= 11:
        parts = [digits[:3], digits[3:6], digits[6:9], digits[9:11]]
        out = parts[0]
        if parts[1]:
            out += "." + parts[1]
        if parts[2]:
            out += "." + parts[2]
        if parts[3]:
            out += "-" + parts[3]
        return out
    parts = [digits[:2], digits[2:5], digits[5:8], digits[8:12], digits[12:14]]
    out = parts[0]
    if parts[1]:
        out += "." + parts[1]
    if parts[2]:
        out += "." + parts[2]
    if parts[3]:
        out += "/" + parts[3]
    if parts[4]:
        out += "-" + parts[4]
    return out


def machine_sources() -> List[Tuple[str, str]]:
    parts: List[Tuple[str, str]] = []
    parts.append(("hostname", socket.gethostname()))
    parts.append(("platform", platform.platform()))
    parts.append(("machine", platform.machine()))
    parts.append(("processor", platform.processor()))
    parts.append(("python", platform.python_version()))
    parts.append(("mac", hex(uuid.getnode())))

    system = platform.system().lower()
    if system == "windows":
        try:
            import winreg  # type: ignore

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography")
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            parts.append(("machine_guid", str(value)))
        except Exception:
            pass
        for cmd, label in [
            (["wmic", "csproduct", "get", "uuid"], "bios_uuid"),
            (["wmic", "bios", "get", "serialnumber"], "bios_serial"),
        ]:
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3)
                cleaned = " ".join(line.strip() for line in output.splitlines() if line.strip() and label.split("_")[0].upper() not in line.upper())
                if cleaned:
                    parts.append((label, cleaned))
            except Exception:
                pass
    elif system == "linux":
        for candidate, label in [
            ("/etc/machine-id", "machine_id"),
            ("/var/lib/dbus/machine-id", "dbus_machine_id"),
        ]:
            try:
                path = Path(candidate)
                if path.exists():
                    value = path.read_text(encoding="utf-8").strip()
                    if value:
                        parts.append((label, value))
            except Exception:
                pass
    elif system == "darwin":
        try:
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
            )
            for line in output.splitlines():
                if "IOPlatformUUID" in line:
                    parts.append(("platform_uuid", line.split("=")[-1].replace('"', '').strip()))
                    break
        except Exception:
            pass

    unique = []
    seen = set()
    for key, value in parts:
        value = (value or "").strip()
        if not value:
            continue
        if (key, value) in seen:
            continue
        seen.add((key, value))
        unique.append((key, value))
    return unique


def machine_fingerprint() -> str:
    raw = "|".join(f"{k}={v}" for k, v in machine_sources())
    return hashlib.sha256(raw.encode("utf-8")).hexdigest().upper()


def machine_summary() -> str:
    name = socket.gethostname()
    system = platform.system()
    release = platform.release()
    machine = platform.machine()
    return f"{name} | {system} {release} | {machine}".strip()


def build_installation_code(app_id: str = APP_ID) -> str:
    payload = {
        "app_id": app_id,
        "app_version": APP_VERSION,
        "device_code": machine_fingerprint(),
        "machine_summary": machine_summary(),
        "generated_at": iso_now(),
    }
    return "LBP-" + b64u_encode(canonical_json_bytes(payload))


def decode_installation_code(code: str) -> Dict[str, Any]:
    code = (code or "").strip()
    if not code.startswith("LBP-"):
        raise ValueError("Código de instalação inválido.")
    try:
        return json.loads(b64u_decode(code[4:]).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Não foi possível ler o código de instalação.") from exc


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def sign_license_payload(private_key_path: Path, payload: Dict[str, Any]) -> Dict[str, Any]:
    private_key = load_private_key(private_key_path)
    message = canonical_json_bytes(payload)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return {"payload": payload, "signature": b64u_encode(signature)}


def verify_license_document(public_key_path: Path, license_document: Dict[str, Any]) -> Dict[str, Any]:
    payload = license_document.get("payload")
    signature = license_document.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, str):
        raise ValueError("Licença inválida: estrutura incorreta.")
    public_key = load_public_key(public_key_path)
    message = canonical_json_bytes(payload)
    try:
        public_key.verify(b64u_decode(signature), message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("Assinatura da licença inválida.") from exc
    return payload


def license_status(payload: Dict[str, Any], expected_app_id: str = APP_ID, current_device_code: str | None = None) -> Tuple[bool, str]:
    if payload.get("app_id") != expected_app_id:
        return False, "Licença não pertence a este sistema."
    expires_at = payload.get("expires_at")
    if expires_at:
        try:
            expiry = parse_iso_date(expires_at)
            if utc_now() > expiry:
                return False, "Licença vencida."
        except Exception:
            return False, "Data de vencimento inválida na licença."
    device_code = payload.get("device_code")
    if current_device_code and device_code and current_device_code != device_code:
        return False, "Licença gerada para outro dispositivo."
    return True, "Licença válida."


def dump_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_json(path: Path, default: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not path.exists():
        return default or {}
    return json.loads(path.read_text(encoding="utf-8"))


def plan_days(plan_name: str) -> int | None:
    plan_name = (plan_name or "").strip().lower()
    mapping = {
        "mensal": 30,
        "trimestral": 90,
        "semestral": 180,
        "anual": 365,
        "permanente": None,
    }
    return mapping.get(plan_name)


def status_from_expiry(expires_at: str | None) -> str:
    if not expires_at:
        return "PERMANENTE"
    try:
        expiry = parse_iso_date(expires_at)
    except Exception:
        return "INVÁLIDA"
    now = utc_now()
    if now > expiry:
        return "VENCIDO"
    if expiry - now <= dt.timedelta(days=7):
        return "VENCE EM BREVE"
    return "ATIVO"
