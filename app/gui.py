"""
SecureShare — CustomTkinter GUI.

Single-window application with Send / Receive modes,
progress bar, and status log.

v2: mandatory verification popup to detect MITM attacks.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import secrets
import socket
import string
import subprocess
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

from .config import (
    APP_NAME,
    APP_VERSION,
    SESSION_CODE_LENGTH,
    CONNECTION_TIMEOUT,
    TCP_CHUNK_SIZE,
)
from .crypto_utils import CryptoSession
from .network import (
    get_local_ips,
    stun_request,
    upnp_add_mapping,
    upnp_remove_mapping,
    upnp_get_external_ip,
    udp_hole_punch,
    tcp_listen,
    tcp_connect,
    tcp_connect_any,
)
from .signaling import SignalingClient
from .transfer import TCPSender, TCPReceiver, UDPSender, UDPReceiver
from .relay import MQTTRelaySender, MQTTRelayReceiver
from .relay_server import LocalRelayServer
from .cf_tunnel import CloudflareTunnel
from .ws_relay import WSRelaySender, WSRelayReceiver

log = logging.getLogger(__name__)

# ── Appearance ─────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def _generate_code() -> str:
    chars = string.ascii_lowercase + string.digits
    code = "".join(secrets.choice(chars) for _ in range(SESSION_CODE_LENGTH))
    return f"{code[:4]}-{code[4:]}"


def _human_size(b: int | float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} ПБ"


def _human_speed(bps: float) -> str:
    return f"{_human_size(bps)}/с"


def _human_eta(seconds: float) -> str:
    if seconds < 0 or seconds > 360000:
        return "—"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}г {m:02d}хв"
    if m:
        return f"{m}хв {s:02d}с"
    return f"{s}с"


# ════════════════════════════════════════════════════════════════════
#  Main application window
# ════════════════════════════════════════════════════════════════════

class App(ctk.CTk):
    WIDTH = 580
    HEIGHT = 640

    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(500, 580)
        self.resizable(True, True)

        # State
        self._worker_thread: Optional[threading.Thread] = None
        self._cancel_flag = False
        self._upnp_port: Optional[int] = None
        self._current_transfer = None  # TCPSender / TCPReceiver / etc.

        # Add Windows Firewall exception silently so the popup never appears
        threading.Thread(
            target=self._ensure_firewall_exception,
            daemon=True,
        ).start()

        self._build_ui()

    @staticmethod
    def _ensure_firewall_exception() -> None:
        """
        Register SecureShare.exe in Windows Firewall (inbound allow) so that
        Windows never shows the 'allow/block' popup when the local relay server
        binds a port.  Requires no elevation — netsh can add rules for the
        current user's program without admin rights on most Windows configs.
        """
        if os.name != "nt":
            return
        try:
            exe = sys.executable
            # When running as a PyInstaller bundle, sys.executable IS the .exe
            rule_name = "SecureShare"
            # Check whether the rule already exists
            check = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={rule_name}"],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if "No rules match" in check.stdout or check.returncode != 0:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}",
                     "dir=in", "action=allow",
                     f"program={exe}",
                     "enable=yes", "profile=any"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
        except Exception:
            pass   # silently ignore — transfer still works, just popup may appear

    # ── UI construction ────────────────────────────────────────────

    def _build_ui(self):
        # Title
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(18, 0))
        ctk.CTkLabel(
            title_frame,
            text=f"\U0001f512 {APP_NAME}",
            font=ctk.CTkFont(size=26, weight="bold"),
        ).pack(side="left")
        ctk.CTkLabel(
            title_frame,
            text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        ).pack(side="left", padx=(8, 0), pady=(8, 0))

        # Tab view
        self.tabs = ctk.CTkTabview(self, width=self.WIDTH - 40)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(10, 0))

        self._build_send_tab(self.tabs.add("\U0001f4e4  Надіслати"))
        self._build_recv_tab(self.tabs.add("\U0001f4e5  Отримати"))

        # Status / progress area (shared)
        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", padx=20, pady=(6, 12))

        self.progress_bar = ctk.CTkProgressBar(status_frame, height=18)
        self.progress_bar.pack(fill="x", padx=12, pady=(10, 4))
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            status_frame,
            text="",
            font=ctk.CTkFont(size=13),
        )
        self.progress_label.pack(padx=12, pady=(0, 2))

        self.status_box = ctk.CTkTextbox(
            status_frame,
            height=130,
            font=ctk.CTkFont(family="Consolas", size=12),
            state="disabled",
            wrap="word",
        )
        self.status_box.pack(fill="x", padx=12, pady=(4, 10))

        # Copyright footer
        ctk.CTkLabel(
            self,
            text="\u00a9 2026 Artem Marchenko. All rights reserved.",
            font=ctk.CTkFont(size=10),
            text_color="gray",
        ).pack(pady=(0, 4))

        # Cancel button
        self.cancel_btn = ctk.CTkButton(
            status_frame,
            text="\u23f9 Скасувати",
            fg_color="#c0392b",
            hover_color="#e74c3c",
            command=self._on_cancel,
            state="disabled",
        )
        self.cancel_btn.pack(pady=(0, 10))

    # ── Send tab ───────────────────────────────────────────────────

    def _build_send_tab(self, tab):
        ctk.CTkLabel(
            tab,
            text="Оберіть файл для надсилання:",
            font=ctk.CTkFont(size=14),
        ).pack(anchor="w", padx=10, pady=(10, 4))

        file_frame = ctk.CTkFrame(tab, fg_color="transparent")
        file_frame.pack(fill="x", padx=10, pady=4)

        self.file_entry = ctk.CTkEntry(
            file_frame,
            placeholder_text="Шлях до файлу...",
            state="readonly",
        )
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            file_frame,
            text="\U0001f4c1 Огляд",
            width=100,
            command=self._browse_file,
        ).pack(side="right")

        # Session code display
        code_frame = ctk.CTkFrame(tab)
        code_frame.pack(fill="x", padx=10, pady=(14, 4))

        ctk.CTkLabel(
            code_frame,
            text="Код сесії:",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=10, pady=(8, 0))

        self.send_code_label = ctk.CTkLabel(
            code_frame,
            text="— — — —",
            font=ctk.CTkFont(family="Consolas", size=28, weight="bold"),
            text_color="#3498db",
        )
        self.send_code_label.pack(padx=10, pady=(4, 4))

        ctk.CTkLabel(
            code_frame,
            text="Повідомте цей код отримувачу",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(padx=10, pady=(0, 8))

        self.send_btn = ctk.CTkButton(
            tab,
            text="\U0001f680 Надіслати",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=42,
            command=self._on_send,
        )
        self.send_btn.pack(fill="x", padx=10, pady=(12, 8))

    # ── Receive tab ────────────────────────────────────────────────

    def _build_recv_tab(self, tab):
        ctk.CTkLabel(
            tab,
            text="Введіть код сесії від відправника:",
            font=ctk.CTkFont(size=14),
        ).pack(anchor="w", padx=10, pady=(10, 4))

        self.recv_code_entry = ctk.CTkEntry(
            tab,
            placeholder_text="xxxx-xxxx",
            font=ctk.CTkFont(family="Consolas", size=22),
            height=44,
            justify="center",
        )
        self.recv_code_entry.pack(fill="x", padx=10, pady=4)

        # Save directory
        ctk.CTkLabel(
            tab,
            text="Зберегти в:",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=10, pady=(14, 4))

        dir_frame = ctk.CTkFrame(tab, fg_color="transparent")
        dir_frame.pack(fill="x", padx=10, pady=4)

        self.save_dir_entry = ctk.CTkEntry(dir_frame, state="readonly")
        self.save_dir_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        # Default save dir = Downloads
        downloads = Path.home() / "Downloads"
        if not downloads.exists():
            downloads = Path.home()
        self._save_dir = str(downloads)
        self.save_dir_entry.configure(state="normal")
        self.save_dir_entry.insert(0, self._save_dir)
        self.save_dir_entry.configure(state="readonly")

        ctk.CTkButton(
            dir_frame,
            text="\U0001f4c1 Огляд",
            width=100,
            command=self._browse_save_dir,
        ).pack(side="right")

        self.recv_btn = ctk.CTkButton(
            tab,
            text="\U0001f4e5 Отримати",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=42,
            command=self._on_receive,
        )
        self.recv_btn.pack(fill="x", padx=10, pady=(16, 8))

    # ── UI helpers ─────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Оберіть файл")
        if path:
            self.file_entry.configure(state="normal")
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self.file_entry.configure(state="readonly")

    def _browse_save_dir(self):
        path = filedialog.askdirectory(title="Оберіть папку для збереження")
        if path:
            self._save_dir = path
            self.save_dir_entry.configure(state="normal")
            self.save_dir_entry.delete(0, "end")
            self.save_dir_entry.insert(0, path)
            self.save_dir_entry.configure(state="readonly")

    def _log(self, text: str):
        """Append a line to the status textbox (thread-safe)."""
        def _do():
            self.status_box.configure(state="normal")
            self.status_box.insert("end", text + "\n")
            self.status_box.see("end")
            self.status_box.configure(state="disabled")
        self.after(0, _do)

    def _set_progress(self, done: int, total: int, speed: float):
        def _do():
            frac = done / total if total > 0 else 0
            self.progress_bar.set(frac)
            pct = frac * 100
            eta = (total - done) / speed if speed > 0 else 0
            self.progress_label.configure(
                text=(
                    f"{pct:.1f}%  \u00b7  {_human_size(done)} / {_human_size(total)}"
                    f"  \u00b7  \u26a1 {_human_speed(speed)}  \u00b7  \u23f1 {_human_eta(eta)}"
                )
            )
        self.after(0, _do)

    def _set_buttons(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        cancel_state = "disabled" if enabled else "normal"
        def _do():
            self.send_btn.configure(state=state)
            self.recv_btn.configure(state=state)
            self.cancel_btn.configure(state=cancel_state)
        self.after(0, _do)

    def _reset_ui(self):
        def _do():
            self.progress_bar.set(0)
            self.progress_label.configure(text="")
        self.after(0, _do)

    def _on_cancel(self):
        self._cancel_flag = True
        if self._current_transfer:
            self._current_transfer.cancel()
        self._log("\u23f9 Скасовано користувачем")

    # ── Verification dialog (mandatory MITM check) ────────────────

    def _verify_connection(self, code: str) -> bool:
        """Show a modal verification dialog.  Thread-safe (called from worker).

        Returns True if the user confirms the codes match,
        False if cancelled or timed out.
        """
        result: list[Optional[bool]] = [None]
        event = threading.Event()

        def _show():
            dialog = ctk.CTkToplevel(self)
            dialog.title("\U0001f510 Верифікація з'єднання")
            dialog.geometry("440x320")
            dialog.resizable(False, False)
            dialog.transient(self)
            dialog.grab_set()
            dialog.focus_force()

            # Center over parent
            dialog.update_idletasks()
            x = self.winfo_x() + (self.winfo_width() - 440) // 2
            y = self.winfo_y() + (self.winfo_height() - 320) // 2
            dialog.geometry(f"+{max(0,x)}+{max(0,y)}")

            ctk.CTkLabel(
                dialog,
                text="\U0001f510 Верифікація з'єднання",
                font=ctk.CTkFont(size=18, weight="bold"),
            ).pack(pady=(20, 8))

            ctk.CTkLabel(
                dialog,
                text="Переконайтесь, що обидва учасники\nбачать однаковий код:",
                font=ctk.CTkFont(size=13),
                justify="center",
            ).pack(pady=(0, 12))

            code_frame = ctk.CTkFrame(dialog)
            code_frame.pack(padx=40, pady=8, fill="x")
            ctk.CTkLabel(
                code_frame,
                text=code,
                font=ctk.CTkFont(family="Consolas", size=32, weight="bold"),
                text_color="#2ecc71",
            ).pack(pady=16)

            ctk.CTkLabel(
                dialog,
                text="\u26a0 Якщо коди різні \u2014 з'єднання може бути\nперехоплено зловмисником (MITM)!",
                font=ctk.CTkFont(size=12),
                text_color="#e74c3c",
                justify="center",
            ).pack(pady=(8, 14))

            btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
            btn_frame.pack(pady=(4, 16))

            def _confirm():
                result[0] = True
                dialog.grab_release()
                dialog.destroy()
                event.set()

            def _cancel():
                result[0] = False
                dialog.grab_release()
                dialog.destroy()
                event.set()

            ctk.CTkButton(
                btn_frame,
                text="\u2705 Коди збігаються",
                fg_color="#27ae60",
                hover_color="#2ecc71",
                command=_confirm,
                width=170,
            ).pack(side="left", padx=8)

            ctk.CTkButton(
                btn_frame,
                text="\u274c Скасувати",
                fg_color="#c0392b",
                hover_color="#e74c3c",
                command=_cancel,
                width=170,
            ).pack(side="right", padx=8)

            dialog.protocol("WM_DELETE_WINDOW", _cancel)

        self.after(0, _show)
        event.wait(timeout=120)
        return result[0] if result[0] is not None else False

    # ════════════════════════════════════════════════════════════════
    #  SEND workflow
    # ════════════════════════════════════════════════════════════════

    def _on_send(self):
        filepath = self.file_entry.get()
        if not filepath or not Path(filepath).is_file():
            messagebox.showwarning("Файл", "Будь ласка, оберіть файл для надсилання.")
            return

        code = _generate_code()
        self.send_code_label.configure(text=code)
        self._cancel_flag = False
        self._reset_ui()
        self._set_buttons(False)

        # Clear status
        self.status_box.configure(state="normal")
        self.status_box.delete("1.0", "end")
        self.status_box.configure(state="disabled")

        self._worker_thread = threading.Thread(
            target=self._send_worker,
            args=(filepath, code),
            daemon=True,
        )
        self._worker_thread.start()

    def _send_worker(self, filepath: str, code: str):
        """Sender = SERVER role.  We listen and wait for the receiver to connect."""
        signaling   = None
        conn_sock   = None
        udp_sock    = None
        srv         = None
        relay_srv   = None
        cf_tunnel   = None
        transfer_mode = None   # "tcp" | "udp" | "ws_relay" | "mqtt_relay"

        try:
            crypto = CryptoSession(code)

            # ── 1. Discover network ────────────────────────────────
            self._log("\U0001f50d Визначаю мережеві параметри...")
            local_ips = get_local_ips()
            self._log(f"  Локальні IP: {', '.join(local_ips)}")

            # Create TCP listener (sender = server)
            srv = tcp_listen(0)
            listen_port = srv.getsockname()[1]
            self._log(f"  TCP порт: {listen_port}")

            # Create UDP socket (for hole punching)
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                udp_sock.bind(("0.0.0.0", listen_port))
            except OSError:
                udp_sock.bind(("0.0.0.0", 0))
            udp_port = udp_sock.getsockname()[1]

            # STUN
            self._log("\U0001f310 STUN: визначаю публічну адресу...")
            pub_ip, pub_port, _ = stun_request(local_port=udp_port, existing_sock=udp_sock)
            if pub_ip:
                self._log(f"  Публічна адреса: {pub_ip}:{pub_port}")
            else:
                self._log("  STUN: не вдалося визначити \u26a0")

            # UPnP
            self._log("\U0001f50c UPnP: пробую відкрити порт...")
            upnp_ok = upnp_add_mapping(listen_port, listen_port, "TCP")
            if upnp_ok:
                self._upnp_port = listen_port
                ext_ip = upnp_get_external_ip()
                self._log(f"  UPnP: порт {listen_port} відкрито \u2713 ({ext_ip})")
            else:
                self._log("  UPnP: недоступний \u26a0")

            if self._cancel_flag:
                return

            # ── 2. Start local relay server + Cloudflare Tunnel ───
            relay_url: Optional[str] = None
            relay_srv = LocalRelayServer()
            if relay_srv.start():
                cf_tunnel = CloudflareTunnel()
                relay_url = cf_tunnel.start(
                    local_port=relay_srv.port,
                    on_status=self._log,
                )
                if not relay_url:
                    self._log("⚠ CF Tunnel недоступний — fallback на MQTT relay")
            else:
                self._log("⚠ Локальний relay сервер не запустився — fallback на MQTT relay")

            if self._cancel_flag:
                return

            # ── 3. MQTT signaling (TLS + encrypted) ──────────────
            self._log("\U0001f4e1 Підключаюсь до сигнального сервера (TLS)...")
            signaling = SignalingClient(code, "sender")
            if not signaling.connect():
                self._log(f"\u274c Помилка MQTT: {signaling.error}")
                return

            self._log("\U0001f4e1 Публікую зашифровану інформацію...")
            signaling.publish_info({
                "local_ips":   local_ips,
                "public_ip":   pub_ip,
                "public_port": pub_port,
                "listen_port": listen_port,
                "udp_port":    udp_port,
                "upnp":        upnp_ok,
                "public_key":  base64.b64encode(crypto.get_public_key_bytes()).decode(),
                "relay_url":   relay_url,   # None if CF tunnel not available
            })

            self._log("\u23f3 Чекаю отримувача...")
            peer = signaling.wait_for_peer(timeout=300)
            if self._cancel_flag:
                return
            if not peer:
                self._log("\u274c Таймаут: отримувач не з'єднався")
                return

            self._log("\u2705 Отримувач знайдено!")

            # ── 3. Derive encryption key ───────────────────────────
            peer_pub_key = base64.b64decode(peer["public_key"])
            crypto.derive_shared_key(peer_pub_key)

            verification_code = crypto.get_verification_code()
            self._log(f"\U0001f511 Код верифікації: {verification_code}")

            # ── 3b. Mandatory verification ─────────────────────────
            if not self._verify_connection(verification_code):
                self._log("\u274c Верифікацію відхилено \u2014 з'єднання закрито")
                return
            self._log("\u2705 Верифікацію підтверджено")

            peer_public_ip = peer.get("public_ip")
            peer_udp_port = peer.get("udp_port", 0)

            # ── 4. Establish connection ────────────────────────────
            # TCP accept in background + short UDP hole punch.
            # If all fail within ~10s → automatic relay fallback.

            accept_result: list = [None, None]  # [socket, addr]

            def _accept_worker():
                try:
                    srv.settimeout(15)
                    s, a = srv.accept()
                    accept_result[0] = s
                    accept_result[1] = a
                except Exception:
                    pass

            self._log("\u23f3 Пробую пряме з'єднання...")
            accept_thread = threading.Thread(target=_accept_worker, daemon=True)
            accept_thread.start()

            # Wait briefly for TCP (LAN / localhost case)
            accept_thread.join(timeout=5)
            if accept_result[0]:
                conn_sock = accept_result[0]
                self._log(f"  TCP з'єднання від {accept_result[1][0]}:{accept_result[1][1]} \u2713")
                transfer_mode = "tcp"

            # Quick UDP hole punch attempt
            if not conn_sock and pub_ip and peer_public_ip and peer_udp_port:
                self._log("\U0001f528 UDP hole punch (8с)...")
                if udp_hole_punch(
                    udp_sock, peer_public_ip, peer_udp_port,
                    timeout=8, on_status=self._log,
                ):
                    transfer_mode = "udp"

            # Last check for late TCP
            if not conn_sock and transfer_mode != "udp":
                accept_thread.join(timeout=2)
                if accept_result[0]:
                    conn_sock = accept_result[0]
                    self._log(f"  TCP з'єднання від {accept_result[1][0]}:{accept_result[1][1]} \u2713")
                    transfer_mode = "tcp"

            # ── Fallback: WS relay (CF Tunnel) or MQTT relay ──────
            if not conn_sock and transfer_mode != "udp":
                self._log("\u26a0 Пряме з'єднання не вдалося")
                if relay_url:
                    self._log("🌐 Переключаюсь на WS Relay (Cloudflare Tunnel)...")
                    transfer_mode = "ws_relay"
                else:
                    self._log("\U0001f4e1 Переключаюсь на MQTT relay...")
                    transfer_mode = "mqtt_relay"

            if self._cancel_flag:
                return

            # ── 5. Transfer file ───────────────────────────────────
            file_size = Path(filepath).stat().st_size
            self._log(f"\U0001f4e6 Надсилаю: {Path(filepath).name} ({_human_size(file_size)})")

            if transfer_mode == "tcp":
                conn_sock.settimeout(120)
                sender = TCPSender(
                    conn_sock, filepath, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = sender
                ok = sender.send()
            elif transfer_mode == "udp":
                sender = UDPSender(
                    udp_sock, (peer_public_ip, peer_udp_port),
                    filepath, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = sender
                ok = sender.send()
            elif transfer_mode == "ws_relay":
                # Sender connects locally (not through cloudflare)
                ws_sender = WSRelaySender(
                    f"ws://localhost:{relay_srv.port}",
                    code, filepath, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = ws_sender
                ok = ws_sender.send()
            else:
                # MQTT relay last-resort fallback
                relay_sender = MQTTRelaySender(
                    code, filepath, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = relay_sender
                ok = relay_sender.send()

            if ok:
                self._log("\U0001f389 Передачу завершено успішно!")
            elif self._cancel_flag:
                self._log("\u23f9 Передачу скасовано")
            else:
                self._log("\u274c Помилка передачі")

        except Exception as exc:
            self._log(f"\u274c Помилка: {exc}")
            log.exception("Send worker error")
        finally:
            self._current_transfer = None
            if signaling:
                signaling.disconnect()
            if conn_sock:
                try:
                    conn_sock.close()
                except Exception:
                    pass
            if self._upnp_port:
                upnp_remove_mapping(self._upnp_port, "TCP")
                self._upnp_port = None
            if srv:
                try:
                    srv.close()
                except Exception:
                    pass
            if cf_tunnel:
                cf_tunnel.stop()
            if relay_srv:
                relay_srv.stop()
            self._set_buttons(True)

    # ════════════════════════════════════════════════════════════════
    #  RECEIVE workflow
    # ════════════════════════════════════════════════════════════════

    def _on_receive(self):
        code = self.recv_code_entry.get().strip().lower()
        if not code or len(code.replace("-", "")) < SESSION_CODE_LENGTH:
            messagebox.showwarning("Код", "Введіть код сесії від відправника.")
            return

        save_dir = self._save_dir
        if not save_dir or not Path(save_dir).is_dir():
            messagebox.showwarning("Папка", "Оберіть папку для збереження.")
            return

        self._cancel_flag = False
        self._reset_ui()
        self._set_buttons(False)

        self.status_box.configure(state="normal")
        self.status_box.delete("1.0", "end")
        self.status_box.configure(state="disabled")

        self._worker_thread = threading.Thread(
            target=self._recv_worker,
            args=(code, save_dir),
            daemon=True,
        )
        self._worker_thread.start()

    def _recv_worker(self, code: str, save_dir: str):
        """Receiver = CLIENT role.  We connect TO the sender."""
        signaling     = None
        conn_sock     = None
        udp_sock      = None
        transfer_mode = None
        relay_url:    Optional[str] = None

        try:
            crypto = CryptoSession(code)

            # ── 1. Discover network ────────────────────────────────
            self._log("\U0001f50d Визначаю мережеві параметри...")
            local_ips = get_local_ips()
            self._log(f"  Локальні IP: {', '.join(local_ips)}")

            # UDP socket (for hole punching)
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp_sock.bind(("0.0.0.0", 0))
            udp_port = udp_sock.getsockname()[1]

            # STUN (to detect if same network as sender)
            self._log("\U0001f310 STUN: визначаю публічну адресу...")
            pub_ip, pub_port, _ = stun_request(local_port=udp_port, existing_sock=udp_sock)
            if pub_ip:
                self._log(f"  Публічна адреса: {pub_ip}:{pub_port}")
            else:
                self._log("  STUN: не вдалося визначити \u26a0")

            if self._cancel_flag:
                return

            # ── 2. MQTT signaling (TLS + encrypted) ──────────────
            self._log("\U0001f4e1 Підключаюсь до сигнального сервера (TLS)...")
            signaling = SignalingClient(code, "receiver")
            if not signaling.connect():
                self._log(f"\u274c Помилка MQTT: {signaling.error}")
                return

            self._log("\U0001f4e1 Публікую зашифровану інформацію...")
            signaling.publish_info({
                "local_ips": local_ips,
                "public_ip": pub_ip,
                "public_port": pub_port,
                "udp_port": udp_port,
                "public_key": base64.b64encode(crypto.get_public_key_bytes()).decode(),
            })

            self._log("\u23f3 Шукаю відправника...")
            peer = signaling.wait_for_peer(timeout=300)
            if self._cancel_flag:
                return
            if not peer:
                self._log("\u274c Таймаут: відправник не знайдено")
                return

            self._log("\u2705 Відправника знайдено!")

            # ── 3. Derive encryption key ───────────────────────────
            peer_pub_key = base64.b64decode(peer["public_key"])
            crypto.derive_shared_key(peer_pub_key)

            verification_code = crypto.get_verification_code()
            self._log(f"\U0001f511 Код верифікації: {verification_code}")

            # ── 3b. Mandatory verification ─────────────────────────
            if not self._verify_connection(verification_code):
                self._log("\u274c Верифікацію відхилено \u2014 з'єднання закрито")
                return
            self._log("\u2705 Верифікацію підтверджено")

            # ── 4. Connect to sender (receiver = client) ───────────
            peer_local_ips   = peer.get("local_ips", [])
            peer_public_ip   = peer.get("public_ip")
            peer_listen_port = peer.get("listen_port", 0)
            peer_udp_port    = peer.get("udp_port", 0)
            peer_upnp        = peer.get("upnp", False)
            relay_url        = peer.get("relay_url")   # Cloudflare Tunnel URL

            # Build candidate IP list for TCP connection
            tcp_candidates = list(peer_local_ips)

            # Detect same machine (overlapping local IPs) → try localhost
            my_ips_set = set(local_ips)
            peer_ips_set = set(peer_local_ips)
            same_machine = bool(my_ips_set & peer_ips_set)
            if same_machine:
                tcp_candidates = ["127.0.0.1"] + tcp_candidates
                self._log("\U0001f5a5\ufe0f Виявлено ту саму машину \u2014 пробую localhost...")

            # Strategy 1: LAN / same machine (parallel TCP, 3s)
            if pub_ip and peer_public_ip and pub_ip == peer_public_ip and peer_listen_port:
                self._log("\U0001f3e0 LAN \u2014 з'єднуюсь (3с)...")
                conn_sock = tcp_connect_any(
                    tcp_candidates, peer_listen_port,
                    timeout=3, on_status=self._log,
                )
                if conn_sock:
                    transfer_mode = "tcp"

            # Strategy 2: TCP to sender's public IP (3s)
            if not conn_sock and peer_public_ip and peer_listen_port:
                self._log(f"\U0001f310 TCP до {peer_public_ip}:{peer_listen_port} (3с)...")
                conn_sock = tcp_connect(peer_public_ip, peer_listen_port, timeout=3)
                if conn_sock:
                    self._log("  TCP \u2713")
                    transfer_mode = "tcp"

            # Strategy 3: Quick UDP hole punch (8s)
            if not conn_sock and pub_ip and peer_public_ip and peer_udp_port:
                self._log("\U0001f528 UDP hole punch (8с)...")
                if udp_hole_punch(
                    udp_sock, peer_public_ip, peer_udp_port,
                    timeout=8, on_status=self._log,
                ):
                    transfer_mode = "udp"

            # ── Fallback: WS relay (CF Tunnel) or MQTT relay ──────
            if not conn_sock and transfer_mode != "udp":
                self._log("\u26a0 Пряме з'єднання не вдалося")
                if relay_url:
                    self._log("🌐 Переключаюсь на WS Relay (Cloudflare Tunnel)...")
                    transfer_mode = "ws_relay"
                else:
                    self._log("\U0001f4e1 Переключаюсь на MQTT relay...")
                    transfer_mode = "mqtt_relay"

            if self._cancel_flag:
                return

            # ── 5. Receive file ────────────────────────────────────
            self._log("\U0001f4e5 Починаю отримання...")

            if transfer_mode == "tcp":
                conn_sock.settimeout(120)
                receiver = TCPReceiver(
                    conn_sock, save_dir, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = receiver
                result = receiver.receive()
            elif transfer_mode == "udp":
                receiver = UDPReceiver(
                    udp_sock, (peer_public_ip, peer_udp_port),
                    save_dir, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = receiver
                result = receiver.receive()
            elif transfer_mode == "ws_relay":
                ws_receiver = WSRelayReceiver(
                    relay_url, code, save_dir, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = ws_receiver
                result = ws_receiver.receive()
            else:
                # MQTT relay last-resort fallback
                relay_receiver = MQTTRelayReceiver(
                    code, save_dir, crypto,
                    on_progress=self._set_progress,
                    on_status=self._log,
                )
                self._current_transfer = relay_receiver
                result = relay_receiver.receive()

            if result:
                self._log(f"\U0001f389 Файл отримано: {result}")
            elif self._cancel_flag:
                self._log("\u23f9 Отримання скасовано")
            else:
                self._log("\u274c Помилка отримання")

        except Exception as exc:
            self._log(f"\u274c Помилка: {exc}")
            log.exception("Receive worker error")
        finally:
            self._current_transfer = None
            if signaling:
                signaling.disconnect()
            if conn_sock:
                try:
                    conn_sock.close()
                except Exception:
                    pass
            self._set_buttons(True)
