"""
SecureShare — CustomTkinter GUI.

Single-window application with Send / Receive modes,
progress bar, status log, and verification popup.

v3: VPS-only relay, simplified architecture, improved UX.
"""

from __future__ import annotations

import datetime
import logging
import random
import secrets
import socket
import ssl
import string
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional
from urllib.parse import urlparse

import customtkinter as ctk

import webbrowser

from .config import (
    APP_NAME,
    APP_VERSION,
    DONATE_URL,
    GITHUB_URL,
    SESSION_CODE_LENGTH,
    VPS_MAX_FILE_SIZE,
    VPS_RELAY_URL,
)
from .ws_relay import VPSRelaySender, VPSRelayReceiver
from .updater import (
    check_for_update, skip_version, clear_skipped, ReleaseInfo,
    can_auto_update, download_and_verify, install_and_restart,
)
from .telemetry import report_crash, report_session

log = logging.getLogger(__name__)

# ── Appearance ─────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Startup tips (shown randomly on launch) ───────────────────────
_STARTUP_TIPS = [
    "❤️  SecureShare — безкоштовний open-source проєкт. Підтримайте розробку: {donate_url}",
    "🔒  Ваші файли захищені AES-256-GCM шифруванням. Сервер ніколи не бачить ваших даних.",
    "🔄  При втраті з’єднання передача автоматично відновиться з місця зупинки.",
    "⭐  Подобається SecureShare? Поставте зірку на GitHub: {github_url}",
    "🚀  Порада: для кількох файлів спакуйте їх в один архів (ZIP/RAR).",
    "🛡️  Завжди перевіряйте код верифікації — це захист від атак посередника (MITM).",
    "☕  Розробка та сервер коштують гроші. Пригостіть автора кавою: {donate_url}",
]


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


def _timestamp() -> str:
    """Current time as [HH:MM:SS] prefix for log lines."""
    return datetime.datetime.now().strftime("[%H:%M:%S]")


# ════════════════════════════════════════════════════════════════════
#  Main application window
# ════════════════════════════════════════════════════════════════════

class App(ctk.CTk):
    WIDTH = 580
    HEIGHT = 700

    # Connection states
    STATE_IDLE = "idle"
    STATE_CONNECTING = "connecting"
    STATE_WAITING = "waiting"
    STATE_KEY_EXCHANGE = "key_exchange"
    STATE_VERIFYING = "verifying"
    STATE_TRANSFERRING = "transferring"
    STATE_DONE = "done"
    STATE_ERROR = "error"

    _STATE_LABELS = {
        STATE_IDLE:         ("⚪  Готовий", "gray"),
        STATE_CONNECTING:   ("🟡  Підключення...", "#f39c12"),
        STATE_WAITING:      ("🟡  Очікування партнера...", "#f39c12"),
        STATE_KEY_EXCHANGE: ("🟡  Обмін ключами...", "#f39c12"),
        STATE_VERIFYING:    ("🟠  Верифікація...", "#e67e22"),
        STATE_TRANSFERRING: ("🟢  Передача...", "#2ecc71"),
        STATE_DONE:         ("🟢  Завершено ✓", "#27ae60"),
        STATE_ERROR:        ("🔴  Помилка", "#e74c3c"),
    }

    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(500, 660)
        self.resizable(True, True)

        # ── Window icon ─────────────────────────────────────────────
        self._set_window_icon()

        # State
        self._worker_thread: Optional[threading.Thread] = None
        self._cancel_flag = False
        self._current_transfer = None   # VPSRelaySender / VPSRelayReceiver

        self._build_ui()

        # ── Auto-check for updates (silent, background) ─────────
        self.after(2000, self._check_updates_startup)

        # ── Show a random startup tip ────────────────────────
        self.after(500, self._show_startup_tip)

    # ── Window icon ──────────────────────────────────────────────

    def _set_window_icon(self):
        """Set the window/taskbar icon from bundled assets."""
        try:
            # PyInstaller bundled path
            if getattr(sys, 'frozen', False):
                base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
            else:
                base = Path(__file__).resolve().parent.parent

            ico_path = base / "assets" / "SecureShare.ico"
            png_path = base / "assets" / "icon_32.png"

            if ico_path.exists():
                self.iconbitmap(str(ico_path))
            if png_path.exists():
                from tkinter import PhotoImage
                self._icon_photo = PhotoImage(file=str(png_path))
                self.iconphoto(True, self._icon_photo)
        except Exception as exc:
            log.debug("Could not set window icon: %s", exc)

    # ── UI construction ────────────────────────────────────────────

    def _build_ui(self):
        # ── Title bar ─────────────────────────────────────────────
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(14, 0))

        ctk.CTkLabel(
            title_frame,
            text=f"🔒 {APP_NAME}",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(side="left")

        ctk.CTkLabel(
            title_frame,
            text=f"v{APP_VERSION}",
            font=ctk.CTkFont(size=10),
            text_color="#777777",
        ).pack(side="left", padx=(6, 0), pady=(5, 0))

        # ── Toolbar ───────────────────────────────────────────────
        toolbar = ctk.CTkFrame(self, fg_color="#1e1e1e", corner_radius=8, height=36)
        toolbar.pack(fill="x", padx=20, pady=(8, 0))
        toolbar.pack_propagate(False)

        _tb_font = ctk.CTkFont(size=12)
        _tb_kw = dict(
            height=28,
            font=_tb_font,
            fg_color="transparent",
            hover_color="#333333",
            border_width=0,
            corner_radius=6,
        )

        ctk.CTkButton(
            toolbar, text="🔄 Оновити", width=100,
            command=self._check_updates_manual, **_tb_kw,
        ).pack(side="left", padx=(6, 2), pady=4)

        ctk.CTkButton(
            toolbar, text="❤️ Підтримати", width=110,
            command=self._open_donate,
            height=28, font=_tb_font,
            fg_color="#5c1a2a", hover_color="#7a2840",
            border_width=0, corner_radius=6,
        ).pack(side="left", padx=2, pady=4)

        ctk.CTkButton(
            toolbar, text="🔍 Діагностика", width=116,
            command=self._run_diagnostics, **_tb_kw,
        ).pack(side="left", padx=2, pady=4)

        ctk.CTkButton(
            toolbar, text="❓ Довідка", width=100,
            command=self._show_help, **_tb_kw,
        ).pack(side="left", padx=2, pady=4)

        # Tab view
        self.tabs = ctk.CTkTabview(self, width=self.WIDTH - 40)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(6, 0))

        self._build_send_tab(self.tabs.add("📤  Надіслати"))
        self._build_recv_tab(self.tabs.add("📥  Отримати"))

        # ── Status / progress area (shared) ───────────────────────
        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", padx=20, pady=(4, 6))

        # Connection status indicator
        self.status_indicator = ctk.CTkLabel(
            status_frame,
            text="⚪  Готовий",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="gray",
        )
        self.status_indicator.pack(padx=12, pady=(6, 0))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(status_frame, height=16)
        self.progress_bar.pack(fill="x", padx=12, pady=(4, 2))
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            status_frame,
            text="",
            font=ctk.CTkFont(size=12),
        )
        self.progress_label.pack(padx=12, pady=(0, 2))

        # Status log textbox
        self.status_box = ctk.CTkTextbox(
            status_frame,
            height=110,
            font=ctk.CTkFont(family="Consolas", size=11),
            state="disabled",
            wrap="word",
        )
        self.status_box.pack(fill="x", padx=12, pady=(2, 4))

        # Bottom buttons row: log actions + cancel
        btn_row = ctk.CTkFrame(status_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=(0, 8))

        ctk.CTkButton(
            btn_row,
            text="📋 Копіювати лог",
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            border_width=1,
            border_color="#555555",
            command=self._copy_log,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_row,
            text="💾 Зберегти лог",
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            border_width=1,
            border_color="#555555",
            command=self._save_log,
        ).pack(side="left")

        # Cancel button — right-aligned in the same row
        self.cancel_btn = ctk.CTkButton(
            btn_row,
            text="⏹ Скасувати",
            width=130,
            height=28,
            fg_color="#c0392b",
            hover_color="#e74c3c",
            command=self._on_cancel,
            state="disabled",
        )
        self.cancel_btn.pack(side="right")

        # Copyright footer
        ctk.CTkLabel(
            self,
            text="© 2026 Artem Marchenko. MIT License",
            font=ctk.CTkFont(size=10),
            text_color="gray",
        ).pack(pady=(0, 4))

    # ── Send tab ───────────────────────────────────────────────────

    def _build_send_tab(self, tab):
        ctk.CTkLabel(
            tab,
            text="Оберіть файл для надсилання:",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=10, pady=(6, 2))

        file_frame = ctk.CTkFrame(tab, fg_color="transparent")
        file_frame.pack(fill="x", padx=10, pady=2)

        self.file_entry = ctk.CTkEntry(
            file_frame,
            placeholder_text="Шлях до файлу...",
            state="readonly",
        )
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            file_frame,
            text="📁 Огляд",
            width=100,
            command=self._browse_file,
        ).pack(side="right")

        # File info label (size + warning)
        self.file_info_label = ctk.CTkLabel(
            tab,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="gray",
        )
        self.file_info_label.pack(anchor="w", padx=14, pady=(2, 0))

        # 5 GB warning (hidden by default)
        self.size_warning_label = ctk.CTkLabel(
            tab,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#e74c3c",
        )
        self.size_warning_label.pack(anchor="w", padx=14, pady=(0, 0))

        # Session code display
        code_frame = ctk.CTkFrame(tab)
        code_frame.pack(fill="x", padx=10, pady=(6, 2))

        ctk.CTkLabel(
            code_frame,
            text="Код сесії:",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=10, pady=(8, 0))

        code_inner = ctk.CTkFrame(code_frame, fg_color="transparent")
        code_inner.pack(fill="x", padx=10, pady=(4, 4))

        self.send_code_label = ctk.CTkLabel(
            code_inner,
            text="— — — —",
            font=ctk.CTkFont(family="Consolas", size=24, weight="bold"),
            text_color="#3498db",
        )
        self.send_code_label.pack(side="left", padx=(0, 10))

        self.copy_code_btn = ctk.CTkButton(
            code_inner,
            text="📋",
            width=36,
            height=36,
            font=ctk.CTkFont(size=16),
            fg_color="#555555",
            hover_color="#666666",
            command=self._copy_session_code,
            state="disabled",
        )
        self.copy_code_btn.pack(side="left")

        ctk.CTkLabel(
            code_frame,
            text="Повідомте цей код отримувачу",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(padx=10, pady=(0, 8))

        self.send_btn = ctk.CTkButton(
            tab,
            text="🚀 Надіслати",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=38,
            command=self._on_send,
        )
        self.send_btn.pack(fill="x", padx=10, pady=(8, 6))

    # ── Receive tab ────────────────────────────────────────────────

    def _build_recv_tab(self, tab):
        ctk.CTkLabel(
            tab,
            text="Введіть код сесії від відправника:",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=10, pady=(6, 2))

        self.recv_code_entry = ctk.CTkEntry(
            tab,
            placeholder_text="xxxx-xxxx",
            font=ctk.CTkFont(family="Consolas", size=20),
            height=40,
            justify="center",
        )
        self.recv_code_entry.pack(fill="x", padx=10, pady=2)

        # Paste button next to entry for convenience
        paste_frame = ctk.CTkFrame(tab, fg_color="transparent")
        paste_frame.pack(fill="x", padx=10, pady=(2, 0))
        ctk.CTkButton(
            paste_frame,
            text="📋 Вставити код",
            width=120,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            border_width=1,
            border_color="#555555",
            command=self._paste_session_code,
        ).pack(side="left")

        # Save directory
        ctk.CTkLabel(
            tab,
            text="Зберегти в:",
            font=ctk.CTkFont(size=13),
        ).pack(anchor="w", padx=10, pady=(8, 2))

        dir_frame = ctk.CTkFrame(tab, fg_color="transparent")
        dir_frame.pack(fill="x", padx=10, pady=2)

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
            text="📁 Огляд",
            width=100,
            command=self._browse_save_dir,
        ).pack(side="right")

        self.recv_btn = ctk.CTkButton(
            tab,
            text="📥 Отримати",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=38,
            command=self._on_receive,
        )
        self.recv_btn.pack(fill="x", padx=10, pady=(10, 6))

    # ── UI helpers ─────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Оберіть файл")
        if path:
            self.file_entry.configure(state="normal")
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self.file_entry.configure(state="readonly")
            self._update_file_info(path)

    def _update_file_info(self, path: str):
        """Show file size and 5GB warning after file selection."""
        try:
            size = Path(path).stat().st_size
            name = Path(path).name
            self.file_info_label.configure(
                text=f"📄 {name} — {_human_size(size)}"
            )
            if size > VPS_MAX_FILE_SIZE:
                self.size_warning_label.configure(
                    text=(
                        f"⚠️ Файл перевищує ліміт {_human_size(VPS_MAX_FILE_SIZE)}. "
                        "Передача може бути перервана сервером."
                    )
                )
            else:
                self.size_warning_label.configure(text="")
        except Exception:
            self.file_info_label.configure(text="")
            self.size_warning_label.configure(text="")

    def _browse_save_dir(self):
        path = filedialog.askdirectory(title="Оберіть папку для збереження")
        if path:
            self._save_dir = path
            self.save_dir_entry.configure(state="normal")
            self.save_dir_entry.delete(0, "end")
            self.save_dir_entry.insert(0, path)
            self.save_dir_entry.configure(state="readonly")

    def _copy_session_code(self):
        """Copy session code to clipboard."""
        code = self.send_code_label.cget("text")
        if code and code != "— — — —":
            self.clipboard_clear()
            self.clipboard_append(code)
            # Brief visual feedback
            old_text = self.copy_code_btn.cget("text")
            self.copy_code_btn.configure(text="✓")
            self.after(1500, lambda: self.copy_code_btn.configure(text=old_text))

    def _paste_session_code(self):
        """Paste session code from clipboard into the receive code entry."""
        try:
            text = self.clipboard_get().strip()
        except Exception:
            return
        if text:
            self.recv_code_entry.delete(0, "end")
            self.recv_code_entry.insert(0, text)

    def _copy_log(self):
        """Copy the entire status log to clipboard."""
        self.status_box.configure(state="normal")
        text = self.status_box.get("1.0", "end").strip()
        self.status_box.configure(state="disabled")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._log("📋 Лог скопійовано в буфер обміну")

    def _save_log(self):
        """Save the status log to a text file."""
        self.status_box.configure(state="normal")
        text = self.status_box.get("1.0", "end").strip()
        self.status_box.configure(state="disabled")
        if not text:
            return

        path = filedialog.asksaveasfilename(
            title="Зберегти лог",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"secureshare_log_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt",
        )
        if path:
            try:
                header = (
                    f"SecureShare v{APP_VERSION} — Log Export\n"
                    f"Date: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
                    f"{'=' * 50}\n\n"
                )
                with open(path, "w", encoding="utf-8") as f:
                    f.write(header + text + "\n")
                self._log(f"💾 Лог збережено: {Path(path).name}")
            except Exception as exc:
                self._log(f"❌ Помилка збереження логу: {exc}")

    # ── Diagnostics ──────────────────────────────────────────────────

    def _run_diagnostics(self):
        """Run connectivity diagnostics in a background thread and show results."""
        # Prevent multiple diagnostic windows
        if hasattr(self, "_diag_win") and self._diag_win is not None:
            try:
                self._diag_win.focus()
                return
            except Exception:
                pass

        win = ctk.CTkToplevel(self)
        win.title(f"{APP_NAME} — Діагностика")
        win.geometry("480x420")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()
        self._diag_win = win

        def _on_close():
            self._diag_win = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_close)

        # Header
        header = ctk.CTkFrame(win, fg_color="#1a3a5c", corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(
            header,
            text="🔍  Діагностика системи",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color="white",
        ).pack(padx=20, pady=12)

        # Results area
        results_frame = ctk.CTkFrame(win, fg_color="transparent")
        results_frame.pack(fill="both", expand=True, padx=20, pady=(12, 6))

        checks = [
            ("internet",  "🌐  Інтернет-з'єднання"),
            ("dns",       "🔗  DNS relay-сервера"),
            ("tls",       "🔒  TLS/SSL сертифікат"),
            ("websocket", "⚡  WebSocket з'єднання"),
            ("latency",   "📊  Латентність (пінг)"),
        ]

        # Create result rows
        row_widgets = {}
        for i, (key, label_text) in enumerate(checks):
            row = ctk.CTkFrame(results_frame, fg_color="#2a2a2a", corner_radius=8)
            row.pack(fill="x", pady=3)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                row, text=label_text,
                font=ctk.CTkFont(size=13),
                anchor="w",
            ).grid(row=0, column=0, padx=12, pady=10, sticky="w")

            status_label = ctk.CTkLabel(
                row, text="⏳ Перевіряю...",
                font=ctk.CTkFont(size=12),
                text_color="#f39c12",
                anchor="e",
            )
            status_label.grid(row=0, column=1, padx=12, pady=10, sticky="e")
            row_widgets[key] = (row, status_label)

        # Summary label (below checks)
        summary_label = ctk.CTkLabel(
            win, text="",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        summary_label.pack(pady=(4, 2))

        # Close button
        close_btn = ctk.CTkButton(
            win, text="Закрити", width=140, height=32,
            fg_color="#1a3a5c", hover_color="#2471a3",
            command=_on_close,
        )
        close_btn.pack(pady=(2, 12))

        def _update_row(key: str, ok: bool, detail: str,
                        color: str | None = None):
            """Thread-safe row update."""
            row_frame, lbl = row_widgets[key]
            if ok:
                txt = f"✅  {detail}"
                clr = color or "#2ecc71"
                bg = "#1a2e1a"
            else:
                txt = f"❌  {detail}"
                clr = color or "#e74c3c"
                bg = "#2e1a1a"

            def _do():
                lbl.configure(text=txt, text_color=clr)
                row_frame.configure(fg_color=bg)
            win.after(0, _do)

        def _run_checks():
            parsed = urlparse(VPS_RELAY_URL)
            host = parsed.hostname or "secureshare-relay.duckdns.org"
            port = parsed.port or 443
            passed = 0
            total = len(checks)

            # 1. Internet connectivity
            try:
                socket.setdefaulttimeout(5)
                socket.create_connection(("8.8.8.8", 53), timeout=5).close()
                _update_row("internet", True, "Підключено")
                passed += 1
            except Exception:
                _update_row("internet", False, "Немає з'єднання")
                # If no internet, mark all remaining as failed
                for key in ["dns", "tls", "websocket", "latency"]:
                    _update_row(key, False, "Пропущено (немає інтернету)",
                                "#888888")
                win.after(0, lambda: summary_label.configure(
                    text=f"Результат: {passed}/{total} перевірок пройдено",
                    text_color="#e74c3c",
                ))
                return

            # 2. DNS resolution
            try:
                t0 = time.perf_counter()
                ip = socket.gethostbyname(host)
                dns_ms = (time.perf_counter() - t0) * 1000
                _update_row("dns", True, f"{ip}  ({dns_ms:.0f} мс)")
                passed += 1
            except Exception:
                _update_row("dns", False, f"Не вдалося резолвити {host}")
                for key in ["tls", "websocket", "latency"]:
                    _update_row(key, False, "Пропущено (DNS помилка)",
                                "#888888")
                win.after(0, lambda: summary_label.configure(
                    text=f"Результат: {passed}/{total} перевірок пройдено",
                    text_color="#e74c3c",
                ))
                return

            # 3. TLS/SSL certificate
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        issuer_parts = dict(
                            x[0] for x in cert.get("issuer", [])
                        )
                        issuer = issuer_parts.get(
                            "organizationName", "Unknown"
                        )
                        not_after = cert.get("notAfter", "?")
                        _update_row("tls", True,
                                    f"{issuer} (до {not_after})")
                        passed += 1
            except ssl.SSLCertVerificationError:
                _update_row("tls", False, "Невалідний сертифікат")
            except Exception as exc:
                _update_row("tls", False, f"Помилка: {type(exc).__name__}")

            # 4. WebSocket connection
            try:
                import websockets.sync.client as wsc
                t0 = time.perf_counter()
                ws = wsc.connect(
                    f"{VPS_RELAY_URL}/health",
                    open_timeout=5,
                    close_timeout=3,
                )
                ws_ms = (time.perf_counter() - t0) * 1000
                ws.close()
                _update_row("websocket", True, f"OK  ({ws_ms:.0f} мс)")
                passed += 1
            except Exception:
                # Try plain HTTPS health check as fallback
                try:
                    import urllib.request
                    health_url = VPS_RELAY_URL.replace(
                        "wss://", "https://"
                    ) + "/health"
                    t0 = time.perf_counter()
                    resp = urllib.request.urlopen(health_url, timeout=5)
                    ws_ms = (time.perf_counter() - t0) * 1000
                    if resp.status == 200:
                        _update_row("websocket", True,
                                    f"OK (HTTP, {ws_ms:.0f} мс)")
                        passed += 1
                    else:
                        _update_row("websocket", False,
                                    f"HTTP {resp.status}")
                except Exception:
                    _update_row("websocket", False,
                                "Не вдалося підключитися")

            # 5. Latency (3 TCP pings, take median)
            try:
                pings = []
                for _ in range(3):
                    t0 = time.perf_counter()
                    s = socket.create_connection((host, port), timeout=5)
                    elapsed = (time.perf_counter() - t0) * 1000
                    s.close()
                    pings.append(elapsed)
                    time.sleep(0.1)
                pings.sort()
                median = pings[len(pings) // 2]
                if median < 100:
                    quality = "Відмінно"
                    clr = "#2ecc71"
                elif median < 250:
                    quality = "Добре"
                    clr = "#f1c40f"
                else:
                    quality = "Повільно"
                    clr = "#e67e22"
                _update_row("latency", True,
                            f"{median:.0f} мс ({quality})", clr)
                passed += 1
            except Exception:
                _update_row("latency", False, "Не вдалося виміряти")

            # Summary
            if passed == total:
                s_text = f"✅  Все працює! ({passed}/{total})"
                s_color = "#2ecc71"
            elif passed >= 3:
                s_text = f"⚠️  Частково ({passed}/{total})"
                s_color = "#f39c12"
            else:
                s_text = f"❌  Проблеми ({passed}/{total})"
                s_color = "#e74c3c"

            win.after(0, lambda: summary_label.configure(
                text=s_text, text_color=s_color,
            ))

        # Run checks in background thread
        threading.Thread(target=_run_checks, daemon=True).start()

    # ── Help popup ───────────────────────────────────────────────────

    def _show_help(self):
        """Open a modal help window with step-by-step instructions."""
        # Prevent multiple help windows
        if hasattr(self, "_help_win") and self._help_win is not None:
            try:
                self._help_win.focus()
                return
            except Exception:
                pass

        win = ctk.CTkToplevel(self)
        win.title(f"{APP_NAME} — Інструкція")
        win.geometry("520x560")
        win.resizable(True, True)
        win.transient(self)
        win.grab_set()
        self._help_win = win

        def _on_close():
            self._help_win = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_close)

        # Header with accent background
        header_frame = ctk.CTkFrame(win, fg_color="#1a5276", corner_radius=0)
        header_frame.pack(fill="x")
        ctk.CTkLabel(
            header_frame,
            text="📖  Як користуватися SecureShare",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="white",
        ).pack(padx=20, pady=14)

        # Scrollable content
        scroll = ctk.CTkScrollableFrame(win, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=12, pady=(8, 6))

        # Section color scheme: (title, body, card_color, title_color, accent_bar)
        help_sections = [
            (
                "📤  Надсилання файлу",
                "1.  Відкрийте вкладку «Надіслати»\n"
                "2.  Натисніть «Огляд» та оберіть файл\n"
                "3.  Натисніть «Надіслати» — програма згенерує код сесії\n"
                "4.  Передайте цей код отримувачу (кнопка 📋)\n"
                "5.  Дочекайтесь підключення отримувача\n"
                "6.  Підтвердіть код верифікації\n"
                "7.  Передача розпочнеться автоматично",
                "#1a3a2a",  # card bg
                "#2ecc71",  # title color (green)
            ),
            (
                "📥  Отримання файлу",
                "1.  Відкрийте вкладку «Отримати»\n"
                "2.  Введіть код сесії від відправника\n"
                "3.  Оберіть папку збереження\n"
                "4.  Натисніть «Отримати»\n"
                "5.  Підтвердіть код верифікації\n"
                "6.  Файл збережеться у вказану папку",
                "#1a2a3a",  # card bg
                "#3498db",  # title color (blue)
            ),
            (
                "🔑  Код верифікації",
                "Після підключення обидва пристрої покажуть\n"
                "однаковий 8-символьний код (XXXX-XXXX).\n\n"
                "✅ Коди збігаються → натисніть «Так»\n"
                "❌ Коди різні → натисніть «Ні» і спробуйте ще раз\n\n"
                "Це захищає від атак посередника (MITM).",
                "#2a2a1a",  # card bg
                "#f1c40f",  # title color (yellow)
            ),
            (
                "🔒  Безпека",
                "•  Шифрування: AES-256-GCM (наскрізне)\n"
                "•  Обмін ключами: X25519 (Diffie-Hellman)\n"
                "•  Сервер НЕ бачить ваших даних\n"
                "•  Код сесії одноразовий",
                "#1a1a2a",  # card bg
                "#9b59b6",  # title color (purple)
            ),
            (
                "⚠️  Обмеження",
                f"•  Максимальний розмір: {VPS_MAX_FILE_SIZE // (1024**3)} ГБ на сесію\n"
                "•  Один файл за сесію (для кількох → архів)\n"
                "•  Потрібен інтернет на обох пристроях\n"
                "•  Для великих файлів — розбийте архіватором",
                "#2a1a1a",  # card bg
                "#e74c3c",  # title color (red)
            ),
            (
                "🔄  Авто-реконнект і відновлення",
                "При втраті з'єднання під час передачі\n"
                "програма автоматично перепідключається\n"
                "(до 5 спроб: 5с, 10с, 20с, 40с, 60с) і продовжує з місця зупинки.\n\n"
                "Верифікація при реконнекті пропускається —\n"
                "програма пам'ятає сесію через токен.\n\n"
                "Якщо реконнект не вдався:\n"
                "1.  Відправник обирає ТОЙ САМИЙ файл\n"
                "2.  Натискає «Надіслати» (новий код)\n"
                "3.  Отримувач вводить новий код\n"
                "4.  Передача продовжиться (resume)\n\n"
                "⏱ Прогрес зберігається 7 днів.",
                "#1a2a3a",  # card bg
                "#e67e22",  # title color (orange)
            ),
            (
                "🛠  Вирішення проблем",
                "•  Немає з'єднання → перевірте інтернет\n"
                "•  Передача перервалась → відновіть (див. вище)\n"
                "•  Діагностика → «Копіювати лог» / «Зберегти лог»\n"
                "•  Зупинити передачу → кнопка «Скасувати»",
                "#1a2a2a",  # card bg
                "#1abc9c",  # title color (teal)
            ),
            (
                "🔄  Авто-оновлення",
                "Програма автоматично перевіряє оновлення\n"
                "при кожному запуску. Якщо є нова версія —\n"
                "з'явиться діалог з описом змін.\n\n"
                "•  🔄 Оновити зараз — завантажити та встановити\n"
                "•  ⏩ Пропустити — ігнорувати цю версію\n"
                "•  Пізніше — нагадати наступного разу\n\n"
                "Оновлення перевіряється через SHA-256.\n"
                "Кнопка 🔄 у шапці — перевірка вручну.",
                "#1a2a2a",  # card bg
                "#3498db",  # title color (blue)
            ),
            (
                "❤️  Підтримка проєкту",
                "SecureShare — безкоштовний open-source проєкт.\n"
                "Розробка та сервер коштують грошей.\n\n"
                "Кнопка ❤️ у шапці відкриває сторінку\n"
                "підтримки на Ko-fi.\n\n"
                "Навіть маленький донат допомагає тримати\n"
                "relay-сервер онлайн та розвивати проєкт.",
                "#2a1a2a",  # card bg
                "#e91e63",  # title color (pink)
            ),
        ]

        for title, body, card_bg, title_color in help_sections:
            # Card container
            card = ctk.CTkFrame(scroll, fg_color=card_bg, corner_radius=8)
            card.pack(fill="x", padx=4, pady=4)

            # Colored title
            ctk.CTkLabel(
                card,
                text=title,
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color=title_color,
                anchor="w",
            ).pack(fill="x", padx=12, pady=(10, 4))

            # Body text
            ctk.CTkLabel(
                card,
                text=body,
                font=ctk.CTkFont(size=12),
                text_color="#cccccc",
                anchor="w",
                justify="left",
                wraplength=430,
            ).pack(fill="x", padx=20, pady=(0, 10))

        # Close button
        ctk.CTkButton(
            win,
            text="Закрити",
            width=140,
            height=32,
            fg_color="#1a5276",
            hover_color="#2471a3",
            command=_on_close,
        ).pack(pady=(6, 12))

    # ── Update checker ────────────────────────────────────────────

    def _show_startup_tip(self):
        """Show a random helpful tip in the status log on app launch."""
        tip_raw = random.choice(_STARTUP_TIPS)
        # If tip contains a URL placeholder, use clickable log
        if "{donate_url}" in tip_raw:
            parts = tip_raw.split("{donate_url}")
            self._log_donate(parts[0].rstrip(), DONATE_URL)
        elif "{github_url}" in tip_raw:
            parts = tip_raw.split("{github_url}")
            self._log_donate(parts[0].rstrip(), GITHUB_URL)
        else:
            self._log(tip_raw)

    def _open_donate(self):
        """Open the donation page in the default browser."""
        webbrowser.open(DONATE_URL)
        self._log("❤️  Дякую за підтримку!")

    def _check_updates_startup(self):
        """Run a silent background update check on startup (respects cooldown)."""
        def _worker():
            try:
                release = check_for_update(force=False)
                if release:
                    self.after(0, lambda: self._show_update_dialog(release))
            except Exception as exc:
                log.debug("Startup update check failed: %s", exc)

        threading.Thread(target=_worker, daemon=True).start()

    def _check_updates_manual(self):
        """Manual update check triggered by the user."""
        clear_skipped()

        # Create a small "checking" indicator
        self._log("🔍 Перевіряю оновлення...")

        def _worker():
            try:
                release = check_for_update(force=True)
                if release:
                    self.after(0, lambda: self._show_update_dialog(release))
                else:
                    self.after(0, lambda: self._log(
                        f"✅ У вас актуальна версія (v{APP_VERSION})"
                    ))
            except Exception as exc:
                _err = str(exc)
                self.after(0, lambda _e=_err: self._log(
                    f"⚠️ Не вдалось перевірити оновлення: {_e}"
                ))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_update_dialog(self, release: ReleaseInfo):
        """Show a modal dialog informing the user about a new version."""
        if hasattr(self, "_update_win") and self._update_win is not None:
            try:
                self._update_win.focus()
                return
            except Exception:
                pass

        win = ctk.CTkToplevel(self)
        win.title(f"{APP_NAME} — Оновлення")
        win.geometry("540x580")
        win.resizable(True, True)
        win.transient(self)
        win.grab_set()
        win.focus_force()
        self._update_win = win

        def _on_close():
            self._update_win = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_close)

        # Center over parent
        win.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - 540) // 2
        y = self.winfo_y() + (self.winfo_height() - 580) // 2
        win.geometry(f"+{max(0, x)}+{max(0, y)}")

        # ── Header ────────────────────────────────────────────────
        header = ctk.CTkFrame(win, fg_color="#1a5276", corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(
            header,
            text="🆕  Доступне оновлення!",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="white",
        ).pack(padx=20, pady=14)

        # ── Version info ──────────────────────────────────────────
        info_frame = ctk.CTkFrame(win, fg_color="#2a2a2a", corner_radius=8)
        info_frame.pack(fill="x", padx=20, pady=(12, 6))

        ver_row = ctk.CTkFrame(info_frame, fg_color="transparent")
        ver_row.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            ver_row,
            text=f"Поточна:  v{APP_VERSION}",
            font=ctk.CTkFont(size=13),
            text_color="#aaaaaa",
        ).pack(side="left")

        ctk.CTkLabel(
            ver_row,
            text="  →  ",
            font=ctk.CTkFont(size=13),
            text_color="#888888",
        ).pack(side="left")

        ctk.CTkLabel(
            ver_row,
            text=f"Нова:  v{release.version}",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#2ecc71",
        ).pack(side="left")

        if release.published:
            pub_date = release.published[:10]  # YYYY-MM-DD
            ctk.CTkLabel(
                info_frame,
                text=f"Дата випуску: {pub_date}",
                font=ctk.CTkFont(size=11),
                text_color="#888888",
            ).pack(padx=16, pady=(0, 10))

        # ── Release notes ─────────────────────────────────────────
        ctk.CTkLabel(
            win,
            text="Що нового:",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        ).pack(fill="x", padx=24, pady=(8, 2))

        notes_box = ctk.CTkTextbox(
            win,
            height=140,
            font=ctk.CTkFont(size=12),
            wrap="word",
            fg_color="#1e1e1e",
        )
        notes_box.pack(fill="x", padx=20, pady=(2, 8))

        # Format release notes — extract Changes, strip commit hashes
        body = release.body.strip() if release.body else ""
        if body:
            import re as _re
            _m = _re.search(
                r"###\s*Changes\s*\n(.*?)(?=\n###|\Z)",
                body, _re.DOTALL,
            )
            if _m:
                _lines = _m.group(1).strip().splitlines()
                _clean = []
                for _ln in _lines:
                    _ln = _re.sub(
                        r"^-\s+[0-9a-f]{7,}\s+", "\u2022 ", _ln.strip()
                    )
                    if _ln:
                        _clean.append(_ln)
                if _clean:
                    body = "\n".join(_clean)
        if not body:
            body = "Немає опису."
        notes_box.insert("1.0", body)
        notes_box.configure(state="disabled")

        # ── Download progress (hidden by default) ──────────────────
        progress_frame = ctk.CTkFrame(win, fg_color="transparent")
        progress_frame.pack(fill="x", padx=20, pady=(0, 4))

        update_progress_bar = ctk.CTkProgressBar(
            progress_frame, height=12,
        )
        update_progress_bar.set(0)
        # Hidden initially

        update_status_label = ctk.CTkLabel(
            progress_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#aaaaaa",
        )
        # Hidden initially

        # ── Action buttons ────────────────────────────────────────
        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(4, 16))

        # Auto-install button (only for frozen .exe builds)
        auto_update_btn = None
        if can_auto_update():
            def _auto_update():
                """Download, verify, and install the update automatically."""
                # Disable all buttons
                if auto_update_btn:
                    auto_update_btn.configure(state="disabled", text="⏳ Оновлюю...")
                for child in btn_frame.winfo_children():
                    try:
                        child.configure(state="disabled")
                    except Exception:
                        pass

                # Show progress bar
                update_progress_bar.pack(fill="x", padx=4, pady=(4, 2))
                update_status_label.pack(padx=4, pady=(0, 4))

                def _progress(downloaded: int, total: int):
                    frac = downloaded / total if total > 0 else 0
                    pct = frac * 100
                    mb_done = downloaded / (1024 * 1024)
                    mb_total = total / (1024 * 1024)
                    win.after(0, lambda: update_progress_bar.set(frac))
                    win.after(0, lambda: update_status_label.configure(
                        text=f"{pct:.0f}%  ·  {mb_done:.1f} / {mb_total:.1f} МБ"
                    ))

                def _status(msg: str):
                    win.after(0, lambda: update_status_label.configure(text=msg))

                def _worker():
                    try:
                        binary, err = download_and_verify(
                            release,
                            progress_cb=_progress,
                            status_cb=_status,
                        )
                        if binary is None:
                            win.after(0, lambda: update_status_label.configure(
                                text=f"❌ {err}", text_color="#e74c3c",
                            ))
                            win.after(0, lambda: _enable_buttons())
                            return

                        _status("Встановлюю оновлення...")
                        ok, err = install_and_restart(
                            binary, status_cb=_status,
                        )
                        if not ok:
                            win.after(0, lambda: update_status_label.configure(
                                text=f"❌ {err}", text_color="#e74c3c",
                            ))
                            win.after(0, lambda: _enable_buttons())
                    except SystemExit:
                        raise
                    except Exception as exc:
                        _err = str(exc)
                        win.after(0, lambda _e=_err: update_status_label.configure(
                            text=f"❌ Помилка: {_e}", text_color="#e74c3c",
                        ))
                        win.after(0, lambda: _enable_buttons())

                def _enable_buttons():
                    if auto_update_btn:
                        auto_update_btn.configure(
                            state="normal", text="🔄 Оновити зараз"
                        )
                    for child in btn_frame.winfo_children():
                        try:
                            child.configure(state="normal")
                        except Exception:
                            pass

                threading.Thread(target=_worker, daemon=True).start()

            auto_update_btn = ctk.CTkButton(
                btn_frame,
                text="🔄 Оновити зараз",
                font=ctk.CTkFont(size=14, weight="bold"),
                fg_color="#2471a3",
                hover_color="#2e86c1",
                height=36,
                command=_auto_update,
            )
            auto_update_btn.pack(side="left", padx=(0, 6), fill="x", expand=True)

        def _download():
            """Open the release page in the default browser."""
            import webbrowser
            webbrowser.open(release.html_url)
            _on_close()

        ctk.CTkButton(
            btn_frame,
            text="🌐 GitHub",
            font=ctk.CTkFont(size=12),
            fg_color="#27ae60",
            hover_color="#2ecc71",
            height=36,
            width=90,
            command=_download,
        ).pack(side="left", padx=(0, 6))

        def _skip():
            """Skip this specific version."""
            skip_version(release.version)
            self._log(f"⏩ Версію v{release.version} пропущено")
            _on_close()

        ctk.CTkButton(
            btn_frame,
            text="⏩ Пропустити",
            font=ctk.CTkFont(size=12),
            fg_color="#555555",
            hover_color="#666666",
            height=36,
            width=110,
            command=_skip,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            btn_frame,
            text="Пізніше",
            font=ctk.CTkFont(size=12),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            height=36,
            width=80,
            command=_on_close,
        ).pack(side="right")

    def _set_state(self, state: str):
        """Update the connection status indicator."""
        label_text, color = self._STATE_LABELS.get(
            state, ("⚪  Готовий", "gray")
        )

        def _do():
            self.status_indicator.configure(text=label_text, text_color=color)
        self.after(0, _do)

    def _log(self, text: str):
        """Append a timestamped line to the status textbox (thread-safe)
        and duplicate to Python logger (console + file)."""
        ts = _timestamp()
        line = f"{ts} {text}\n"
        # Duplicate to Python logger so it goes to console + log file
        log.info("[GUI] %s", text)

        def _do():
            self.status_box.configure(state="normal")
            self.status_box.insert("end", line)
            self.status_box.see("end")
            self.status_box.configure(state="disabled")
        self.after(0, _do)

    def _log_donate(self, text: str, url: str):
        """Log a message with a clickable donation link (thread-safe)."""
        ts = _timestamp()
        log.info("[GUI] %s %s", text, url)

        def _do():
            tb = self.status_box
            tb.configure(state="normal")
            tb.insert("end", f"{ts} {text} ")

            # Create unique tag for this link
            tag = f"link_{id(url)}_{time.time_ns()}"
            tb.insert("end", url, tag)

            # Style: underline + orange color
            inner = tb._textbox  # access underlying tk.Text widget
            inner.tag_configure(tag, foreground="#f59e0b", underline=True)
            inner.tag_bind(
                tag, "<Button-1>",
                lambda e, u=url: webbrowser.open(u),
            )
            inner.tag_bind(
                tag, "<Enter>",
                lambda e: inner.configure(cursor="hand2"),
            )
            inner.tag_bind(
                tag, "<Leave>",
                lambda e: inner.configure(cursor=""),
            )

            tb.insert("end", "\n")
            tb.see("end")
            tb.configure(state="disabled")
        self.after(0, _do)

    def _set_progress(self, done: int, total: int, speed: float):
        def _do():
            frac = done / total if total > 0 else 0
            self.progress_bar.set(frac)
            pct = frac * 100
            eta = (total - done) / speed if speed > 0 else 0
            self.progress_label.configure(
                text=(
                    f"{pct:.1f}%  ·  {_human_size(done)} / {_human_size(total)}"
                    f"  ·  ⚡ {_human_speed(speed)}  ·  ⏱ {_human_eta(eta)}"
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
            self.copy_code_btn.configure(
                state="normal" if not enabled else "disabled"
            )
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
        self._log("⏹ Скасовано користувачем")

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
            dialog.title("🔐 Верифікація з'єднання")
            dialog.geometry("440x320")
            dialog.resizable(False, False)
            dialog.transient(self)
            dialog.grab_set()
            dialog.focus_force()

            # Center over parent
            dialog.update_idletasks()
            x = self.winfo_x() + (self.winfo_width() - 440) // 2
            y = self.winfo_y() + (self.winfo_height() - 320) // 2
            dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

            ctk.CTkLabel(
                dialog,
                text="🔐 Верифікація з'єднання",
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
                text="⚠ Якщо коди різні — з'єднання може бути\nперехоплено зловмисником (MITM)!",
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
                text="✅ Коди збігаються",
                fg_color="#27ae60",
                hover_color="#2ecc71",
                command=_confirm,
                width=170,
            ).pack(side="left", padx=8)

            ctk.CTkButton(
                btn_frame,
                text="❌ Скасувати",
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
    #  Status callback adapter for ws_relay → GUI state indicator
    # ════════════════════════════════════════════════════════════════

    def _make_status_cb(self):
        """Return a status callback that updates both the log and the state indicator."""
        def _on_status(msg: str):
            self._log(msg)
            # Auto-detect state from relay status messages
            lower = msg.lower()
            if "підключаюсь" in lower:
                self._set_state(self.STATE_CONNECTING)
            elif "чекаю" in lower and ("отримувач" in lower or "відправник" in lower):
                self._set_state(self.STATE_WAITING)
            elif "обмін ключами" in lower:
                self._set_state(self.STATE_KEY_EXCHANGE)
            elif "верифікац" in lower and ("підтверджен" in lower or "код" in lower):
                self._set_state(self.STATE_VERIFYING)
            elif "надсилаю" in lower or "отримую" in lower:
                self._set_state(self.STATE_TRANSFERRING)
            elif "передано" in lower or "збережено" in lower:
                self._set_state(self.STATE_DONE)
            elif "помилка" in lower or "❌" in msg:
                self._set_state(self.STATE_ERROR)
        return _on_status

    # ════════════════════════════════════════════════════════════════
    #  SEND workflow
    # ════════════════════════════════════════════════════════════════

    def _on_send(self):
        filepath = self.file_entry.get()
        if not filepath or not Path(filepath).is_file():
            messagebox.showwarning("Файл", "Будь ласка, оберіть файл для надсилання.")
            return

        # Check file size > 5 GB — warn but allow
        file_size = Path(filepath).stat().st_size
        if file_size > VPS_MAX_FILE_SIZE:
            proceed = messagebox.askyesno(
                "Великий файл",
                f"Файл ({_human_size(file_size)}) перевищує ліміт сервера "
                f"({_human_size(VPS_MAX_FILE_SIZE)}).\n\n"
                "Передача може бути перервана.\nПродовжити?",
            )
            if not proceed:
                return

        code = _generate_code()
        self.send_code_label.configure(text=code)
        self._cancel_flag = False
        self._reset_ui()
        self._set_buttons(False)
        self._set_state(self.STATE_IDLE)

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
        """Send a file through the VPS relay server."""
        t_start = time.monotonic()
        file_size = Path(filepath).stat().st_size
        outcome = "error"
        error_type = ""
        try:
            sender = VPSRelaySender(
                session_code=code,
                filepath=filepath,
                on_progress=self._set_progress,
                on_status=self._make_status_cb(),
                on_verify=self._verify_connection,
            )
            self._current_transfer = sender

            ok = sender.send()

            if ok:
                outcome = "success"
                self._set_state(self.STATE_DONE)
                self._log("🎉 Передачу завершено успішно!")
                self._log_donate(
                    "☕ Подобається SecureShare? "
                    "Пригостіть автора кавою —",
                    DONATE_URL,
                )
            elif self._cancel_flag:
                outcome = "cancelled"
                self._set_state(self.STATE_IDLE)
                self._log("⏹ Передачу скасовано")
            else:
                outcome = "error"
                self._set_state(self.STATE_ERROR)
                self._log("❌ Помилка передачі")

        except Exception as exc:
            outcome = "error"
            error_type = type(exc).__name__
            self._set_state(self.STATE_ERROR)
            self._log(f"❌ Помилка: {exc}")
            log.exception("Send worker error")
            report_crash(exc, state="send_worker")
        finally:
            self._current_transfer = None
            self._set_buttons(True)
            # Anonymous session telemetry
            report_session(
                role="sender",
                outcome=outcome,
                file_size=file_size,
                duration_s=time.monotonic() - t_start,
                error_type=error_type,
            )

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
        self._set_state(self.STATE_IDLE)

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
        """Receive a file through the VPS relay server."""
        t_start = time.monotonic()
        outcome = "error"
        error_type = ""
        file_size = 0
        try:
            receiver = VPSRelayReceiver(
                session_code=code,
                save_dir=save_dir,
                on_progress=self._set_progress,
                on_status=self._make_status_cb(),
                on_verify=self._verify_connection,
            )
            self._current_transfer = receiver

            result = receiver.receive()

            if result:
                outcome = "success"
                try:
                    file_size = Path(result).stat().st_size
                except Exception:
                    pass
                self._set_state(self.STATE_DONE)
                self._log(f"🎉 Файл отримано: {result}")
                self._log_donate(
                    "☕ SecureShare — безкоштовний сервіс. "
                    "Підтримайте розробку:",
                    DONATE_URL,
                )
            elif self._cancel_flag:
                outcome = "cancelled"
                self._set_state(self.STATE_IDLE)
                self._log("⏹ Отримання скасовано")
            else:
                outcome = "error"
                self._set_state(self.STATE_ERROR)
                self._log("❌ Помилка отримання")

        except Exception as exc:
            outcome = "error"
            error_type = type(exc).__name__
            self._set_state(self.STATE_ERROR)
            self._log(f"❌ Помилка: {exc}")
            log.exception("Receive worker error")
            report_crash(exc, state="recv_worker")
        finally:
            self._current_transfer = None
            self._set_buttons(True)
            # Anonymous session telemetry
            report_session(
                role="receiver",
                outcome=outcome,
                file_size=file_size,
                duration_s=time.monotonic() - t_start,
                error_type=error_type,
            )
