from __future__ import annotations

import json
import secrets
import socket
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_DIR = BASE_DIR / "shared"
sys.path.insert(0, str(SHARED_DIR))

from common_security import (  # noqa: E402
    APP_ID,
    build_installation_code,
    canonical_json_bytes,
    load_json,
    machine_fingerprint,
    machine_summary,
    phone_to_wa_link,
    verify_license_document,
    license_status,
)

CLIENT_DIR = Path(__file__).resolve().parent
KEYS_DIR = CLIENT_DIR / "keys"
DATA_DIR = CLIENT_DIR / "data"
LICENSE_DIR = CLIENT_DIR / "license"
BUNDLE_PATH = DATA_DIR / "app.bundle"
LICENSE_PATH = LICENSE_DIR / "license.lic"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"
SUPPORT_CONFIG_PATH = CLIENT_DIR / "support_config.json"

_OBF_MASK = bytes.fromhex("df1468fb9bb26f3c4d796a5abcf6033f0d2a21f4904d5a2f3ce2f712b5a4dfc6")
_OBF_DATA = bytes.fromhex("99f6b61f0c70eb0a3e8f81cfe1d03dcef7f386f634be0ac78c4d81cc0219fb99")


def bundle_key() -> bytes:
    return bytes(a ^ b for a, b in zip(_OBF_MASK, _OBF_DATA))


def decrypt_bundle() -> bytes:
    raw = BUNDLE_PATH.read_bytes()
    nonce, ciphertext = raw[:12], raw[12:]
    aes = AESGCM(bundle_key())
    return aes.decrypt(nonce, ciphertext, b"laserbox-protected-app")


class SecureAppServer:
    def __init__(self, config: dict, app_html: bytes):
        self.config = config
        self.app_html = app_html
        self.session_token = secrets.token_urlsafe(24)
        self.port = self._find_port()
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    @staticmethod
    def _find_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def start(self):
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/app"):
                    token = self._token_from_path()
                    if token != server_ref.session_token:
                        self._send_text("Acesso negado.", status=HTTPStatus.FORBIDDEN)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(server_ref.app_html)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(server_ref.shell_html().encode("utf-8"))

            def log_message(self, format, *args):
                return

            def _token_from_path(self):
                if "?token=" in self.path:
                    return self.path.split("?token=", 1)[1].split("&", 1)[0]
                return ""

            def _send_text(self, text: str, status: int = 200):
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(text.encode("utf-8"))

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    def open_browser(self):
        webbrowser.open(self.url)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?token={self.session_token}"

    def shell_html(self) -> str:
        phone_display = self.config.get("support_phone_display", "Suporte")
        help_text = self.config.get("help_text", "Suporte comercial")
        wa = phone_to_wa_link(self.config.get("support_phone_e164", ""))
        app_name = self.config.get("app_name", "Sistema protegido")
        token = self.session_token
        return f"""<!DOCTYPE html>
<html lang=\"pt-br\">
<head>
<meta charset=\"utf-8\" />
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
<title>{app_name}</title>
<style>
:root{{--bg:#0f172a;--panel:#111827;--line:#1f2937;--accent:#84cc16;--text:#e5e7eb;--muted:#94a3b8;}}
*{{box-sizing:border-box}} html,body{{margin:0;height:100%;font-family:Arial,Helvetica,sans-serif;background:var(--bg);color:var(--text)}}
body{{display:flex;flex-direction:column}}
header{{height:60px;background:var(--panel);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 16px;gap:16px}}
.brand{{font-weight:800;letter-spacing:.4px}} .brand span{{color:var(--accent)}}
.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.actions a,.actions button{{border:1px solid #334155;background:#1e293b;color:#fff;padding:9px 12px;border-radius:8px;text-decoration:none;cursor:pointer;font-weight:700}}
.actions a.primary{{background:var(--accent);color:#111827;border-color:var(--accent)}}
.note{{font-size:12px;color:var(--muted)}}
main{{flex:1;min-height:0}}
iframe{{width:100%;height:100%;border:0;background:#fff}}
</style>
</head>
<body>
<header>
  <div>
    <div class=\"brand\">{app_name} <span>Protegido</span></div>
    <div class=\"note\">{help_text}</div>
  </div>
  <div class=\"actions\">
    <a href=\"{wa}\" target=\"_blank\" rel=\"noopener\">WhatsApp {phone_display}</a>
    <button onclick=\"alert('Ajuda / Renovação de licença: {phone_display}')\">Ajuda</button>
    <a class=\"primary\" href=\"/app?token={token}\" target=\"appframe\">Abrir sistema</a>
  </div>
</header>
<main>
  <iframe name=\"appframe\" src=\"/app?token={token}\"></iframe>
</main>
</body>
</html>"""


class LauncherUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = load_json(SUPPORT_CONFIG_PATH, default={
            "app_name": "LaserBox Pro V10",
            "support_phone_e164": "5599999999999",
            "support_phone_display": "(99) 99999-9999",
            "help_text": "Renovação e suporte via WhatsApp.",
        })
        self.current_device_code = machine_fingerprint()
        self.install_code = build_installation_code(APP_ID)
        self.server: SecureAppServer | None = None
        self.app_html = decrypt_bundle()
        self.root.title(self.config.get("app_name", "Sistema protegido"))
        self.root.geometry("820x620")

        self.status_var = tk.StringVar(value="Verificando licença...")
        self.info_var = tk.StringVar(value=machine_summary())
        self.license_text = None
        self.install_code_text = None

        self.build_ui()
        self.check_existing_license(show_success=False)

    def build_ui(self):
        frame = ttk.Frame(self.root, padding=14)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(frame, text=self.config.get("app_name", "Sistema protegido"), font=("Arial", 17, "bold"))
        title.pack(anchor="w")
        ttk.Label(frame, text="Ativação por licença vinculada ao dispositivo.").pack(anchor="w", pady=(2, 8))
        ttk.Label(frame, textvariable=self.info_var).pack(anchor="w", pady=(0, 8))

        top_buttons = ttk.Frame(frame)
        top_buttons.pack(fill="x", pady=(0, 8))
        ttk.Button(top_buttons, text="Abrir WhatsApp suporte", command=self.open_support).pack(side="left", padx=(0, 8))
        ttk.Button(top_buttons, text="Carregar licença do arquivo", command=self.load_license_file).pack(side="left", padx=(0, 8))
        ttk.Button(top_buttons, text="Validar licença colada", command=self.activate_from_text).pack(side="left", padx=(0, 8))
        ttk.Button(top_buttons, text="Abrir sistema", command=self.open_system).pack(side="left")

        ttk.Label(frame, text="Código de instalação para enviar ao administrador").pack(anchor="w")
        self.install_code_text = ScrolledText(frame, height=7, wrap="word")
        self.install_code_text.pack(fill="x", pady=(4, 10))
        self.install_code_text.insert("1.0", self.install_code)

        row = ttk.Frame(frame)
        row.pack(fill="x")
        ttk.Button(row, text="Copiar código", command=self.copy_install_code).pack(side="left", padx=(0, 8))
        ttk.Button(row, text="Revalidar licença salva", command=lambda: self.check_existing_license(show_success=True)).pack(side="left")

        ttk.Label(frame, text="Cole aqui a licença gerada no Builder").pack(anchor="w", pady=(12, 0))
        self.license_text = ScrolledText(frame, height=16, wrap="word")
        self.license_text.pack(fill="both", expand=True, pady=(4, 8))

        ttk.Label(frame, textvariable=self.status_var).pack(anchor="w")

    def copy_install_code(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.install_code)
        self.status_var.set("Código de instalação copiado.")

    def open_support(self):
        webbrowser.open(phone_to_wa_link(self.config.get("support_phone_e164", "")))

    def load_license_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Licença", "*.lic *.json"), ("Todos", "*.*")])
        if not filename:
            return
        text = Path(filename).read_text(encoding="utf-8")
        self.license_text.delete("1.0", "end")
        self.license_text.insert("1.0", text)
        self.activate_from_text()

    def activate_from_text(self):
        text = self.license_text.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Licença", "Cole a licença gerada pelo Builder.")
            return
        try:
            document = json.loads(text)
            payload = verify_license_document(PUBLIC_KEY_PATH, document)
            ok, msg = license_status(payload, expected_app_id=self.config.get("app_id", APP_ID), current_device_code=self.current_device_code)
            if not ok:
                raise ValueError(msg)
            LICENSE_DIR.mkdir(parents=True, exist_ok=True)
            LICENSE_PATH.write_text(text, encoding="utf-8")
            self.status_var.set("Licença ativada com sucesso.")
            messagebox.showinfo("Licença", "Licença validada e salva com sucesso.")
        except Exception as exc:
            self.status_var.set(f"Erro: {exc}")
            messagebox.showerror("Licença", str(exc))
            return
        self.open_system()

    def check_existing_license(self, show_success: bool = False) -> bool:
        if not LICENSE_PATH.exists():
            self.status_var.set("Nenhuma licença ativa encontrada. Gere a licença no Builder e cole aqui.")
            return False
        try:
            document = json.loads(LICENSE_PATH.read_text(encoding="utf-8"))
            payload = verify_license_document(PUBLIC_KEY_PATH, document)
            ok, msg = license_status(payload, expected_app_id=self.config.get("app_id", APP_ID), current_device_code=self.current_device_code)
            if not ok:
                raise ValueError(msg)
            expires_at = payload.get("expires_at") or "Permanente"
            self.status_var.set(f"Licença válida. Plano: {payload.get('plan_name')} | Vence: {expires_at}")
            if show_success:
                messagebox.showinfo("Licença", "Licença válida.")
            return True
        except Exception as exc:
            self.status_var.set(f"Licença inválida ou vencida: {exc}")
            return False

    def ensure_server(self):
        if self.server is None:
            self.server = SecureAppServer(self.config, self.app_html)
            self.server.start()

    def open_system(self):
        if not self.check_existing_license(show_success=False):
            messagebox.showerror("Sistema", "Ative uma licença válida antes de abrir o sistema.")
            return
        self.ensure_server()
        self.server.open_browser()
        self.status_var.set(f"Sistema liberado em {self.server.url}")


def preflight_or_exit():
    missing = []
    for path in [PUBLIC_KEY_PATH, BUNDLE_PATH, SUPPORT_CONFIG_PATH]:
        if not path.exists():
            missing.append(str(path))
    if missing:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Arquivos ausentes", "Estão faltando arquivos obrigatórios:\n\n" + "\n".join(missing))
        raise SystemExit(1)


if __name__ == "__main__":
    preflight_or_exit()
    root = tk.Tk()
    app = LauncherUI(root)
    root.mainloop()
