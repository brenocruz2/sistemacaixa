from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

BASE_DIR = Path(__file__).resolve().parent.parent
SHARED_DIR = BASE_DIR / "shared"
sys.path.insert(0, str(SHARED_DIR))

from common_security import (  # noqa: E402
    APP_ID,
    dump_json,
    format_cep,
    format_cpf_cnpj,
    format_phone_br,
    decode_installation_code,
    iso_now,
    load_json,
    phone_to_wa_link,
    plan_days,
    safe_digits,
    sign_license_payload,
    status_from_expiry,
)

ADMIN_DIR = Path(__file__).resolve().parent
DATA_DIR = ADMIN_DIR / "data"
KEYS_DIR = ADMIN_DIR / "keys"
OUTPUT_DIR = ADMIN_DIR / "output"
DB_PATH = DATA_DIR / "customers.db"
PRIVATE_KEY_PATH = KEYS_DIR / "private_key.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"

PLANS = ["Mensal", "Trimestral", "Semestral", "Anual", "Permanente"]


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                name TEXT NOT NULL,
                document TEXT,
                phone TEXT,
                cep TEXT,
                address TEXT,
                number TEXT,
                complement TEXT,
                district TEXT,
                city TEXT,
                state TEXT,
                notes TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                license_id TEXT NOT NULL,
                plan_name TEXT NOT NULL,
                expires_at TEXT,
                installation_code TEXT NOT NULL,
                device_code TEXT NOT NULL,
                license_path TEXT NOT NULL,
                FOREIGN KEY(customer_id) REFERENCES customers(id)
            )
            """
        )
        self.conn.commit()

    def save_customer(self, payload: dict, customer_id: int | None = None) -> int:
        now = iso_now()
        cur = self.conn.cursor()
        if customer_id:
            cur.execute(
                """
                UPDATE customers
                SET updated_at=?, name=?, document=?, phone=?, cep=?, address=?, number=?, complement=?, district=?, city=?, state=?, notes=?
                WHERE id=?
                """,
                (
                    now,
                    payload["name"],
                    payload["document"],
                    payload["phone"],
                    payload["cep"],
                    payload["address"],
                    payload["number"],
                    payload["complement"],
                    payload["district"],
                    payload["city"],
                    payload["state"],
                    payload["notes"],
                    customer_id,
                ),
            )
            self.conn.commit()
            return customer_id
        cur.execute(
            """
            INSERT INTO customers (created_at, updated_at, name, document, phone, cep, address, number, complement, district, city, state, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                now,
                payload["name"],
                payload["document"],
                payload["phone"],
                payload["cep"],
                payload["address"],
                payload["number"],
                payload["complement"],
                payload["district"],
                payload["city"],
                payload["state"],
                payload["notes"],
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_customers(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT c.*, l.plan_name, l.expires_at,
                   (SELECT COUNT(*) FROM licenses lx WHERE lx.customer_id = c.id) AS total_licenses
            FROM customers c
            LEFT JOIN licenses l ON l.id = (
                SELECT id FROM licenses WHERE customer_id = c.id ORDER BY id DESC LIMIT 1
            )
            ORDER BY c.name COLLATE NOCASE ASC
            """
        )
        return cur.fetchall()

    def get_customer(self, customer_id: int):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM customers WHERE id=?", (customer_id,))
        return cur.fetchone()

    def add_license(self, customer_id: int, payload: dict, license_path: Path, installation_code: str, device_code: str):
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO licenses (customer_id, created_at, license_id, plan_name, expires_at, installation_code, device_code, license_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                customer_id,
                iso_now(),
                payload["license_id"],
                payload["plan_name"],
                payload.get("expires_at"),
                installation_code,
                device_code,
                str(license_path),
            ),
        )
        self.conn.commit()


class AdminBuilderApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LaserBox Secure Builder")
        self.root.geometry("1180x760")
        self.db = Database(DB_PATH)
        self.selected_customer_id: int | None = None
        self.last_generated_license_text = ""
        self.last_generated_license_path: Path | None = None

        self.vars = {k: tk.StringVar() for k in [
            "name", "document", "phone", "cep", "address", "number", "complement", "district", "city", "state"
        ]}
        self.notes_var = tk.StringVar()
        self.customer_combo_var = tk.StringVar()
        self.plan_var = tk.StringVar(value="Mensal")
        self.installation_code_var = tk.StringVar()
        self.expiry_preview_var = tk.StringVar(value="Vencimento: --")
        self.status_var = tk.StringVar(value="Pronto.")

        self._build_ui()
        self._bind_masks()
        self.refresh_customer_table()
        self.refresh_customer_combo()

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container)
        header.pack(fill="x")
        ttk.Label(header, text="Builder / Cadastro / Licenciamento", font=("Arial", 16, "bold")).pack(side="left")
        ttk.Button(header, text="Abrir pasta de licenças", command=lambda: self.open_folder(OUTPUT_DIR)).pack(side="right", padx=4)
        ttk.Button(header, text="Abrir pasta de dados", command=lambda: self.open_folder(DATA_DIR)).pack(side="right", padx=4)

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True, pady=(10, 0))

        self.tab_cadastro = ttk.Frame(notebook, padding=12)
        self.tab_licenca = ttk.Frame(notebook, padding=12)
        self.tab_clientes = ttk.Frame(notebook, padding=12)
        notebook.add(self.tab_cadastro, text="Cadastro do cliente")
        notebook.add(self.tab_licenca, text="Gerar licença")
        notebook.add(self.tab_clientes, text="Clientes / Renovação")

        self.build_cadastro_tab()
        self.build_licenca_tab()
        self.build_clientes_tab()

        footer = ttk.Label(container, textvariable=self.status_var, anchor="w")
        footer.pack(fill="x", pady=(8, 0))

    def _bind_masks(self):
        self.vars["document"].trace_add("write", lambda *_: self._reformat_var("document", format_cpf_cnpj))
        self.vars["phone"].trace_add("write", lambda *_: self._reformat_var("phone", format_phone_br))
        self.vars["cep"].trace_add("write", lambda *_: self._reformat_var("cep", format_cep))
        self.plan_var.trace_add("write", lambda *_: self.update_expiry_preview())

    def _reformat_var(self, key, formatter):
        current = self.vars[key].get()
        formatted = formatter(current)
        if current != formatted:
            self.vars[key].set(formatted)

    def build_cadastro_tab(self):
        frame = self.tab_cadastro
        cols = [0, 1]
        for col in cols:
            frame.columnconfigure(col, weight=1)

        fields = [
            ("Nome / Razão social", "name"),
            ("CPF ou CNPJ", "document"),
            ("Telefone", "phone"),
            ("CEP", "cep"),
            ("Endereço", "address"),
            ("Número", "number"),
            ("Complemento", "complement"),
            ("Bairro", "district"),
            ("Cidade", "city"),
            ("UF", "state"),
        ]

        for idx, (label, key) in enumerate(fields):
            row = idx // 2
            col = (idx % 2) * 2
            ttk.Label(frame, text=label).grid(row=row, column=col, sticky="w", padx=(0, 8), pady=6)
            ttk.Entry(frame, textvariable=self.vars[key]).grid(row=row, column=col + 1, sticky="ew", pady=6)

        ttk.Label(frame, text="Observações").grid(row=5, column=0, sticky="nw", pady=6)
        self.notes_text = ScrolledText(frame, height=6, wrap="word")
        self.notes_text.grid(row=5, column=1, columnspan=3, sticky="nsew", pady=6)
        frame.rowconfigure(5, weight=1)

        actions = ttk.Frame(frame)
        actions.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(12, 0))
        for i in range(5):
            actions.columnconfigure(i, weight=1)
        ttk.Button(actions, text="Novo cadastro", command=self.clear_form).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(actions, text="Salvar cliente", command=self.save_customer).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(actions, text="Atualizar cliente", command=self.update_customer).grid(row=0, column=2, sticky="ew", padx=4)
        ttk.Button(actions, text="Carregar selecionado", command=self.load_selected_customer_from_table).grid(row=0, column=3, sticky="ew", padx=4)
        ttk.Button(actions, text="Ir para gerar licença", command=self.focus_license_tab).grid(row=0, column=4, sticky="ew", padx=4)

    def build_licenca_tab(self):
        frame = self.tab_licenca
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)

        ttk.Label(frame, text="Cliente cadastrado").grid(row=0, column=0, sticky="w", pady=6)
        self.customer_combo = ttk.Combobox(frame, textvariable=self.customer_combo_var, state="readonly")
        self.customer_combo.grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(frame, text="Plano").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Combobox(frame, textvariable=self.plan_var, values=PLANS, state="readonly").grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(frame, text="Código de instalação enviado pelo cliente").grid(row=2, column=0, sticky="w", pady=6)
        self.installation_entry = ttk.Entry(frame, textvariable=self.installation_code_var)
        self.installation_entry.grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Label(frame, textvariable=self.expiry_preview_var).grid(row=3, column=1, sticky="w", pady=6)

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 10))
        for i in range(4):
            buttons.columnconfigure(i, weight=1)
        ttk.Button(buttons, text="Ler código", command=self.inspect_install_code).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(buttons, text="Gerar licença", command=self.generate_license).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(buttons, text="Copiar licença", command=self.copy_generated_license).grid(row=0, column=2, sticky="ew", padx=4)
        ttk.Button(buttons, text="Salvar como", command=self.save_generated_license_as).grid(row=0, column=3, sticky="ew", padx=4)

        ttk.Label(frame, text="Licença gerada (JSON assinado)").grid(row=5, column=0, sticky="nw", pady=6)
        self.license_output = ScrolledText(frame, wrap="word")
        self.license_output.grid(row=5, column=1, sticky="nsew", pady=6)

    def build_clientes_tab(self):
        frame = self.tab_clientes
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        columns = ("id", "name", "document", "phone", "plan", "expires", "status")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        labels = {
            "id": "ID",
            "name": "Cliente",
            "document": "CPF/CNPJ",
            "phone": "Telefone",
            "plan": "Plano",
            "expires": "Vencimento",
            "status": "Status",
        }
        widths = {"id": 60, "name": 220, "document": 140, "phone": 140, "plan": 100, "expires": 160, "status": 120}
        for col in columns:
            self.tree.heading(col, text=labels[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.on_tree_select())

        buttons = ttk.Frame(frame)
        buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        for i in range(5):
            buttons.columnconfigure(i, weight=1)
        ttk.Button(buttons, text="Atualizar lista", command=self.refresh_customer_table).grid(row=0, column=0, sticky="ew", padx=4)
        ttk.Button(buttons, text="Carregar cadastro", command=self.load_selected_customer_from_table).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(buttons, text="Abrir WhatsApp 💬", command=self.open_whatsapp_for_selected).grid(row=0, column=2, sticky="ew", padx=4)
        ttk.Button(buttons, text="Gerar renovação", command=self.prepare_license_for_selected).grid(row=0, column=3, sticky="ew", padx=4)
        ttk.Button(buttons, text="Copiar telefone", command=self.copy_phone_for_selected).grid(row=0, column=4, sticky="ew", padx=4)

    def collect_form(self) -> dict:
        payload = {k: v.get().strip() for k, v in self.vars.items()}
        payload["notes"] = self.notes_text.get("1.0", "end").strip()
        return payload

    def validate_form(self, payload: dict) -> bool:
        if not payload["name"]:
            messagebox.showerror("Cadastro", "Informe o nome do cliente.")
            return False
        if payload["document"] and len(safe_digits(payload["document"])) not in (11, 14):
            messagebox.showerror("Cadastro", "CPF/CNPJ precisa ter 11 ou 14 dígitos.")
            return False
        if payload["cep"] and len(safe_digits(payload["cep"])) != 8:
            messagebox.showerror("Cadastro", "CEP deve ter 8 dígitos.")
            return False
        return True

    def clear_form(self):
        self.selected_customer_id = None
        for var in self.vars.values():
            var.set("")
        self.notes_text.delete("1.0", "end")
        self.status_var.set("Novo cadastro preparado.")

    def save_customer(self):
        payload = self.collect_form()
        if not self.validate_form(payload):
            return
        customer_id = self.db.save_customer(payload)
        self.selected_customer_id = customer_id
        self.refresh_customer_table()
        self.refresh_customer_combo(select_id=customer_id)
        self.status_var.set(f"Cliente salvo com ID {customer_id}.")
        messagebox.showinfo("Cadastro", f"Cliente salvo com sucesso. ID: {customer_id}")

    def update_customer(self):
        if not self.selected_customer_id:
            messagebox.showerror("Atualização", "Selecione um cliente primeiro.")
            return
        payload = self.collect_form()
        if not self.validate_form(payload):
            return
        self.db.save_customer(payload, customer_id=self.selected_customer_id)
        self.refresh_customer_table()
        self.refresh_customer_combo(select_id=self.selected_customer_id)
        self.status_var.set(f"Cliente {self.selected_customer_id} atualizado.")
        messagebox.showinfo("Atualização", "Cadastro atualizado com sucesso.")

    def populate_form(self, row):
        if not row:
            return
        self.selected_customer_id = int(row["id"])
        for key in self.vars:
            self.vars[key].set(row[key] or "")
        self.notes_text.delete("1.0", "end")
        self.notes_text.insert("1.0", row["notes"] or "")
        self.refresh_customer_combo(select_id=self.selected_customer_id)
        self.status_var.set(f"Cliente {self.selected_customer_id} carregado.")

    def refresh_customer_combo(self, select_id: int | None = None):
        customers = self.db.get_customers()
        values = [f"{row['id']} - {row['name']}" for row in customers]
        self.customer_combo["values"] = values
        if select_id:
            self.customer_combo_var.set(next((v for v in values if v.startswith(f"{select_id} - ")), ""))
        elif values and not self.customer_combo_var.get():
            self.customer_combo_var.set(values[0])

    def get_selected_customer_id_from_combo(self) -> int | None:
        value = self.customer_combo_var.get().strip()
        if not value or " - " not in value:
            return None
        return int(value.split(" - ", 1)[0])

    def inspect_install_code(self):
        try:
            data = decode_installation_code(self.installation_code_var.get())
        except Exception as exc:
            messagebox.showerror("Código", str(exc))
            return
        messagebox.showinfo(
            "Código de instalação",
            f"App: {data.get('app_id')}\nVersão: {data.get('app_version')}\n\nResumo da máquina:\n{data.get('machine_summary')}\n\nDevice code:\n{data.get('device_code')}",
        )

    def update_expiry_preview(self):
        days = plan_days(self.plan_var.get())
        if days is None:
            self.expiry_preview_var.set("Vencimento: permanente")
        else:
            from datetime import datetime, timedelta, timezone
            expiry = datetime.now(timezone.utc) + timedelta(days=days)
            self.expiry_preview_var.set(f"Vencimento: {expiry.strftime('%d/%m/%Y %H:%M UTC')}")

    def generate_license(self):
        customer_id = self.get_selected_customer_id_from_combo()
        if not customer_id:
            messagebox.showerror("Licença", "Selecione um cliente cadastrado.")
            return
        if not PRIVATE_KEY_PATH.exists():
            messagebox.showerror("Chaves", f"Private key não encontrada em:\n{PRIVATE_KEY_PATH}")
            return
        install_code = self.installation_code_var.get().strip()
        if not install_code:
            messagebox.showerror("Licença", "Cole o código de instalação enviado pelo cliente.")
            return
        try:
            install_data = decode_installation_code(install_code)
        except Exception as exc:
            messagebox.showerror("Licença", str(exc))
            return
        if install_data.get("app_id") != APP_ID:
            messagebox.showerror("Licença", "Esse código não pertence a este sistema.")
            return
        customer = self.db.get_customer(customer_id)
        if not customer:
            messagebox.showerror("Licença", "Cliente não encontrado.")
            return

        days = plan_days(self.plan_var.get())
        expires_at = None
        if days is not None:
            from datetime import timedelta
            expires_at = ( __import__('datetime').datetime.now(__import__('datetime').timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()

        payload = {
            "app_id": APP_ID,
            "license_id": str(uuid.uuid4()),
            "issued_at": iso_now(),
            "expires_at": expires_at,
            "plan_name": self.plan_var.get(),
            "max_devices": 1,
            "device_code": install_data["device_code"],
            "installation_code": install_code,
            "activation_mode": "single-device-single-license",
            "anti_piracy": {
                "deny_random_keys": True,
                "signature": "ECDSA-P256-SHA256",
                "device_lock": True,
            },
            "customer": {
                "id": int(customer["id"]),
                "name": customer["name"],
                "document": customer["document"],
                "phone": customer["phone"],
                "cep": customer["cep"],
                "address": customer["address"],
                "number": customer["number"],
                "complement": customer["complement"],
                "district": customer["district"],
                "city": customer["city"],
                "state": customer["state"],
            },
        }
        license_document = sign_license_payload(PRIVATE_KEY_PATH, payload)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = "".join(ch for ch in customer["name"] if ch.isalnum() or ch in ("_", "-", " ")).strip().replace(" ", "_")[:40] or f"cliente_{customer_id}"
        file_path = OUTPUT_DIR / f"{safe_name}_{self.plan_var.get().lower()}_{payload['license_id'][:8]}.lic"
        dump_json(file_path, license_document)
        self.db.add_license(customer_id, payload, file_path, install_code, install_data["device_code"])
        pretty = json.dumps(license_document, ensure_ascii=False, indent=2)
        self.license_output.delete("1.0", "end")
        self.license_output.insert("1.0", pretty)
        self.last_generated_license_text = pretty
        self.last_generated_license_path = file_path
        self.refresh_customer_table()
        self.status_var.set(f"Licença gerada e salva em {file_path.name}")
        messagebox.showinfo("Licença", f"Licença gerada com sucesso.\n\nArquivo:\n{file_path}")

    def copy_generated_license(self):
        text = self.license_output.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Licença", "Nenhuma licença gerada ainda.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Licença copiada para a área de transferência.")

    def save_generated_license_as(self):
        text = self.license_output.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Licença", "Nenhuma licença gerada ainda.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".lic", filetypes=[("Licença", "*.lic"), ("JSON", "*.json")])
        if not path:
            return
        Path(path).write_text(text, encoding="utf-8")
        self.status_var.set(f"Licença exportada para {path}")

    def refresh_customer_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for row in self.db.get_customers():
            status = status_from_expiry(row["expires_at"])
            expires = row["expires_at"] or "Permanente"
            self.tree.insert(
                "",
                "end",
                values=(row["id"], row["name"], row["document"], row["phone"], row["plan_name"] or "--", expires, status),
            )

    def on_tree_select(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = self.tree.item(selection[0])
        values = item.get("values") or []
        if not values:
            return
        self.status_var.set(f"Selecionado cliente ID {values[0]} - {values[1]}")

    def selected_customer_id_from_tree(self) -> int | None:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0]).get("values") or []
        return int(values[0]) if values else None

    def load_selected_customer_from_table(self):
        customer_id = self.selected_customer_id_from_tree()
        if not customer_id:
            messagebox.showerror("Clientes", "Selecione um cliente na tabela.")
            return
        row = self.db.get_customer(customer_id)
        self.populate_form(row)

    def prepare_license_for_selected(self):
        customer_id = self.selected_customer_id_from_tree()
        if not customer_id:
            messagebox.showerror("Clientes", "Selecione um cliente na tabela.")
            return
        self.refresh_customer_combo(select_id=customer_id)
        self.focus_license_tab()
        self.status_var.set("Cliente carregado para renovação/licenciamento.")

    def copy_phone_for_selected(self):
        customer_id = self.selected_customer_id_from_tree()
        if not customer_id:
            messagebox.showerror("Telefone", "Selecione um cliente.")
            return
        customer = self.db.get_customer(customer_id)
        phone = customer["phone"] if customer else ""
        if not phone:
            messagebox.showerror("Telefone", "Cliente sem telefone cadastrado.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(phone)
        self.status_var.set("Telefone copiado.")

    def open_whatsapp_for_selected(self):
        customer_id = self.selected_customer_id_from_tree()
        if not customer_id:
            messagebox.showerror("WhatsApp", "Selecione um cliente.")
            return
        customer = self.db.get_customer(customer_id)
        if not customer or not customer["phone"]:
            messagebox.showerror("WhatsApp", "Cliente sem telefone cadastrado.")
            return
        url = phone_to_wa_link(customer["phone"])
        webbrowser.open(url)
        self.status_var.set("WhatsApp do cliente aberto no navegador.")

    def focus_license_tab(self):
        self.tab_licenca.tkraise()
        for i in range(self.tab_licenca.master.index("end")):
            if self.tab_licenca.master.tab(i, "text") == "Gerar licença":
                self.tab_licenca.master.select(i)
                break

    @staticmethod
    def open_folder(path: Path):
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            messagebox.showinfo("Pasta", str(path))


def ensure_required_files():
    missing = []
    if not PRIVATE_KEY_PATH.exists():
        missing.append(str(PRIVATE_KEY_PATH))
    if not PUBLIC_KEY_PATH.exists():
        missing.append(str(PUBLIC_KEY_PATH))
    if missing:
        messagebox.showerror(
            "Chaves ausentes",
            "Arquivos de chave não encontrados. Verifique se as chaves foram geradas:\n\n" + "\n".join(missing),
        )
        raise SystemExit(1)


if __name__ == "__main__":
    root = tk.Tk()
    ensure_required_files()
    app = AdminBuilderApp(root)
    app.update_expiry_preview()
    root.mainloop()
