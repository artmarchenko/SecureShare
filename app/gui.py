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
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

import webbrowser

from .config import (
    APP_NAME,
    APP_VERSION,
    DONATE_URL,
    GITHUB_URL,
    SESSION_CODE_LENGTH,
    VPS_MAX_FILE_SIZE,
)
from .crypto_utils import new_session_code
from .format import human_eta, human_size, human_speed
from .ws_relay import TransferState, VPSRelaySender, VPSRelayReceiver
from .updater import check_for_update, clear_skipped, ReleaseInfo
from .telemetry import report_crash, report_session
from .i18n import t, init as i18n_init, set_language, get_language, available_languages
from .ui.diagnostics_window import open_diagnostics
from .ui.help_window import open_help
from .ui.update_dialog import open_update_dialog
from .ui.verify_dialog import ask_verification

log = logging.getLogger(__name__)

# ── Appearance ─────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ── Startup tips (shown randomly on launch) ───────────────────────
def _startup_tips() -> list[str]:
    return [
        t("startup_tip_donate", donate_url=DONATE_URL),
        t("startup_tip_encryption"),
        t("startup_tip_reconnect"),
        t("startup_tip_github", github_url=GITHUB_URL),
        t("startup_tip_archive"),
        t("startup_tip_verify"),
        t("startup_tip_coffee", donate_url=DONATE_URL),
    ]


def _generate_code() -> str:
    return new_session_code(SESSION_CODE_LENGTH)


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

    @staticmethod
    def _get_state_labels():
        return {
            App.STATE_IDLE:         (t("state_idle"), "gray"),
            App.STATE_CONNECTING:   (t("state_connecting"), "#f39c12"),
            App.STATE_WAITING:      (t("state_waiting"), "#f39c12"),
            App.STATE_KEY_EXCHANGE: (t("state_key_exchange"), "#f39c12"),
            App.STATE_VERIFYING:    (t("state_verifying"), "#e67e22"),
            App.STATE_TRANSFERRING: (t("state_transferring"), "#2ecc71"),
            App.STATE_DONE:         (t("state_done"), "#27ae60"),
            App.STATE_ERROR:        (t("state_error"), "#e74c3c"),
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

        i18n_init()
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

        self._tb_update_btn = ctk.CTkButton(
            toolbar, text=t("toolbar_update"), width=100,
            command=self._check_updates_manual, **_tb_kw,
        )
        self._tb_update_btn.pack(side="left", padx=(6, 2), pady=4)

        self._tb_donate_btn = ctk.CTkButton(
            toolbar, text=t("toolbar_donate"), width=110,
            command=self._open_donate,
            height=28, font=_tb_font,
            fg_color="#5c1a2a", hover_color="#7a2840",
            border_width=0, corner_radius=6,
        )
        self._tb_donate_btn.pack(side="left", padx=2, pady=4)

        self._tb_diag_btn = ctk.CTkButton(
            toolbar, text=t("toolbar_diagnostics"), width=116,
            command=self._run_diagnostics, **_tb_kw,
        )
        self._tb_diag_btn.pack(side="left", padx=2, pady=4)

        self._tb_help_btn = ctk.CTkButton(
            toolbar, text=t("toolbar_help"), width=100,
            command=self._show_help, **_tb_kw,
        )
        self._tb_help_btn.pack(side="left", padx=2, pady=4)

        # Language selector
        _lang_map = {"uk": "UA", "en": "EN", "de": "DE"}
        _lang_codes = available_languages()
        _lang_labels = [_lang_map.get(c, c.upper()) for c in _lang_codes]
        _cur_label = _lang_map.get(get_language(), "UA")

        self._lang_menu = ctk.CTkOptionMenu(
            toolbar,
            values=_lang_labels,
            width=56,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#333333",
            button_color="#444444",
            button_hover_color="#555555",
            dropdown_fg_color="#2a2a2a",
            command=self._on_language_change,
        )
        self._lang_menu.set(_cur_label)
        self._lang_menu.pack(side="right", padx=(2, 6), pady=4)
        self._lang_codes = _lang_codes
        self._lang_labels = _lang_labels

        # Tab view
        self.tabs = ctk.CTkTabview(self, width=self.WIDTH - 40)
        # The tabs keep their natural height; spare (or missing) vertical space
        # goes to the status log below, which scrolls anyway (U1).
        self.tabs.pack(fill="x", padx=20, pady=(6, 0))

        self._tab_send_name = t("tab_send")
        self._tab_recv_name = t("tab_receive")
        self._build_send_tab(self.tabs.add(self._tab_send_name))
        self._build_recv_tab(self.tabs.add(self._tab_recv_name))

        # ── Status / progress area (shared) ───────────────────────
        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="both", expand=True, padx=20, pady=(4, 6))

        # Connection status indicator
        self.status_indicator = ctk.CTkLabel(
            status_frame,
            text=t("state_idle"),
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
        self.status_box.pack(fill="both", expand=True, padx=12, pady=(2, 4))

        # Bottom buttons row: log actions + cancel
        btn_row = ctk.CTkFrame(status_frame, fg_color="transparent")
        # Packed at the bottom *before* the log box: if space runs out, the
        # log box shrinks, never the buttons.
        btn_row.pack(side="bottom", fill="x", padx=12, pady=(0, 8), before=self.status_box)

        self._copy_log_btn = ctk.CTkButton(
            btn_row,
            text=t("btn_copy_log"),
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            border_width=1,
            border_color="#555555",
            command=self._copy_log,
        )
        self._copy_log_btn.pack(side="left", padx=(0, 6))

        self._save_log_btn = ctk.CTkButton(
            btn_row,
            text=t("btn_save_log"),
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            border_width=1,
            border_color="#555555",
            command=self._save_log,
        )
        self._save_log_btn.pack(side="left")

        # Cancel button — right-aligned in the same row
        self.cancel_btn = ctk.CTkButton(
            btn_row,
            text=t("btn_cancel"),
            width=130,
            height=28,
            fg_color="#c0392b",
            hover_color="#e74c3c",
            command=self._on_cancel,
            state="disabled",
        )
        self.cancel_btn.pack(side="right")

        # Copyright footer
        self._copyright_lbl = ctk.CTkLabel(
            self,
            text=t("copyright"),
            font=ctk.CTkFont(size=10),
            text_color="gray",
        )
        # Bottom-anchored and allocated before the tabs/status area, so it is
        # never the widget that gets clipped.
        self._copyright_lbl.pack(side="bottom", pady=(0, 4), before=self.tabs)

    def _on_language_change(self, label: str):
        """Handle language selection from the toolbar dropdown."""
        idx = self._lang_labels.index(label) if label in self._lang_labels else 0
        code = self._lang_codes[idx]
        if code != get_language():
            set_language(code)
            self._refresh_ui_texts()

    def _refresh_ui_texts(self):
        """Refresh all UI texts after language change (live switch)."""
        # Toolbar buttons
        self._tb_update_btn.configure(text=t("toolbar_update"))
        self._tb_donate_btn.configure(text=t("toolbar_donate"))
        self._tb_diag_btn.configure(text=t("toolbar_diagnostics"))
        self._tb_help_btn.configure(text=t("toolbar_help"))

        # Tab names — update the segmented button text
        try:
            seg = self.tabs._segmented_button
            for val, btn in seg._buttons_dict.items():
                if val == self._tab_send_name:
                    btn.configure(text=t("tab_send"))
                elif val == self._tab_recv_name:
                    btn.configure(text=t("tab_receive"))
        except Exception:
            pass  # CTkTabview internals changed — tabs will update on restart

        # Status indicator — refresh only if idle
        # Only refresh if we're in idle state (don't overwrite active status)
        if not hasattr(self, "_current_state") or self._current_state == self.STATE_IDLE:
            self.status_indicator.configure(text=t("state_idle"))

        # Bottom buttons
        self._copy_log_btn.configure(text=t("btn_copy_log"))
        self._save_log_btn.configure(text=t("btn_save_log"))
        self.cancel_btn.configure(text=t("btn_cancel"))

        # Copyright
        self._copyright_lbl.configure(text=t("copyright"))

        # Send tab
        self._send_choose_lbl.configure(text=t("send_choose_file"))
        self.file_entry.configure(placeholder_text=t("send_file_placeholder"))
        self._send_browse_btn.configure(text=t("btn_browse"))
        self._send_session_lbl.configure(text=t("send_session_code"))
        self._send_hint_lbl.configure(text=t("send_code_hint"))
        self.send_btn.configure(text=t("btn_send"))

        # Receive tab
        self._recv_enter_lbl.configure(text=t("recv_enter_code"))
        self._recv_paste_btn.configure(text=t("btn_paste_code"))
        self._recv_save_lbl.configure(text=t("recv_save_to"))
        self._recv_browse_btn.configure(text=t("btn_browse"))
        self.recv_btn.configure(text=t("btn_receive"))

    # ── Send tab ───────────────────────────────────────────────────

    def _build_send_tab(self, tab):
        self._send_choose_lbl = ctk.CTkLabel(
            tab,
            text=t("send_choose_file"),
            font=ctk.CTkFont(size=13),
        )
        self._send_choose_lbl.pack(anchor="w", padx=10, pady=(6, 2))

        file_frame = ctk.CTkFrame(tab, fg_color="transparent")
        file_frame.pack(fill="x", padx=10, pady=2)

        self.file_entry = ctk.CTkEntry(
            file_frame,
            placeholder_text=t("send_file_placeholder"),
            state="readonly",
        )
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        self._send_browse_btn = ctk.CTkButton(
            file_frame,
            text=t("btn_browse"),
            width=100,
            command=self._browse_file,
        )
        self._send_browse_btn.pack(side="right")

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

        self._send_session_lbl = ctk.CTkLabel(
            code_frame,
            text=t("send_session_code"),
            font=ctk.CTkFont(size=13),
        )
        self._send_session_lbl.pack(anchor="w", padx=10, pady=(8, 0))

        code_inner = ctk.CTkFrame(code_frame, fg_color="transparent")
        code_inner.pack(fill="x", padx=10, pady=(4, 4))

        self.send_code_label = ctk.CTkLabel(
            code_inner,
            text=t("send_code_placeholder"),
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

        self._send_hint_lbl = ctk.CTkLabel(
            code_frame,
            text=t("send_code_hint"),
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        self._send_hint_lbl.pack(padx=10, pady=(0, 8))

        self.send_btn = ctk.CTkButton(
            tab,
            text=t("btn_send"),
            font=ctk.CTkFont(size=14, weight="bold"),
            height=38,
            command=self._on_send,
        )
        self.send_btn.pack(fill="x", padx=10, pady=(8, 6))

    # ── Receive tab ────────────────────────────────────────────────

    def _build_recv_tab(self, tab):
        self._recv_enter_lbl = ctk.CTkLabel(
            tab,
            text=t("recv_enter_code"),
            font=ctk.CTkFont(size=13),
        )
        self._recv_enter_lbl.pack(anchor="w", padx=10, pady=(6, 2))

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
        self._recv_paste_btn = ctk.CTkButton(
            paste_frame,
            text=t("btn_paste_code"),
            width=120,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            border_width=1,
            border_color="#555555",
            command=self._paste_session_code,
        )
        self._recv_paste_btn.pack(side="left")

        # Save directory
        self._recv_save_lbl = ctk.CTkLabel(
            tab,
            text=t("recv_save_to"),
            font=ctk.CTkFont(size=13),
        )
        self._recv_save_lbl.pack(anchor="w", padx=10, pady=(8, 2))

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

        self._recv_browse_btn = ctk.CTkButton(
            dir_frame,
            text=t("btn_browse"),
            width=100,
            command=self._browse_save_dir,
        )
        self._recv_browse_btn.pack(side="right")

        self.recv_btn = ctk.CTkButton(
            tab,
            text=t("btn_receive"),
            font=ctk.CTkFont(size=14, weight="bold"),
            height=38,
            command=self._on_receive,
        )
        self.recv_btn.pack(fill="x", padx=10, pady=(10, 6))

    # ── UI helpers ─────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(title=t("dialog_choose_file"))
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
                text=f"📄 {name} — {human_size(size)}"
            )
            if size > VPS_MAX_FILE_SIZE:
                self.size_warning_label.configure(
                    text=t("file_size_warning", max_size=human_size(VPS_MAX_FILE_SIZE))
                )
            else:
                self.size_warning_label.configure(text="")
        except Exception:
            self.file_info_label.configure(text="")
            self.size_warning_label.configure(text="")

    def _browse_save_dir(self):
        path = filedialog.askdirectory(title=t("dialog_choose_save_dir"))
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
            self._log(t("log_copied"))

    def _save_log(self):
        """Save the status log to a text file."""
        self.status_box.configure(state="normal")
        text = self.status_box.get("1.0", "end").strip()
        self.status_box.configure(state="disabled")
        if not text:
            return

        path = filedialog.asksaveasfilename(
            title=t("dialog_save_log"),
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
                self._log(t("log_saved", filename=Path(path).name))
            except Exception as exc:
                self._log(t("log_save_error", error=str(exc)))

    # ── Diagnostics ──────────────────────────────────────────────────

    def _run_diagnostics(self):
        """Run connectivity diagnostics in a background thread and show results."""
        open_diagnostics(self)

    # ── Help popup ───────────────────────────────────────────────────

    def _show_help(self):
        """Open a modal help window with step-by-step instructions."""
        open_help(self)

    # ── Update checker ────────────────────────────────────────────

    def _show_startup_tip(self):
        """Show a random helpful tip in the status log on app launch."""
        tip_raw = random.choice(_startup_tips())
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
        self._log(t("log_donate_thanks"))

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
        self._log(t("update_checking"))

        def _worker():
            try:
                release = check_for_update(force=True)
                if release:
                    self.after(0, lambda: self._show_update_dialog(release))
                else:
                    self.after(0, lambda: self._log(
                        t("update_up_to_date", version=APP_VERSION)
                    ))
            except Exception as exc:
                _err = str(exc)
                self.after(0, lambda _e=_err: self._log(
                    t("update_check_failed", error=_e)
                ))

        threading.Thread(target=_worker, daemon=True).start()

    def _show_update_dialog(self, release: ReleaseInfo):
        """Show a modal dialog informing the user about a new version."""
        open_update_dialog(self, release)

    def _set_state(self, state: str):
        """Update the connection status indicator."""
        self._current_state = state
        label_text, color = self._get_state_labels().get(
            state, (t("state_idle"), "gray")
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
                    f"{pct:.1f}%  ·  {human_size(done)} / {human_size(total)}"
                    f"  ·  ⚡ {human_speed(speed)}  ·  ⏱ {human_eta(eta)}"
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
        self._log(t("transfer_cancelled_user"))

    # ── Verification dialog (mandatory MITM check) ────────────────

    def _verify_connection(self, code: str) -> bool:
        """Mandatory MITM check; blocks the calling worker thread (see ui.verify_dialog)."""
        return ask_verification(self, code)

    def _on_transfer_state(self, state: TransferState) -> None:
        """ws_relay reports the transfer phase; mirror it in the indicator."""
        self._set_state(state.value)

    # ════════════════════════════════════════════════════════════════
    #  SEND workflow
    # ════════════════════════════════════════════════════════════════

    def _on_send(self):
        filepath = self.file_entry.get()
        if not filepath or not Path(filepath).is_file():
            messagebox.showwarning(t("msgbox_file_title"), t("msgbox_file_body"))
            return

        # Check file size > 5 GB — warn but allow
        file_size = Path(filepath).stat().st_size
        if file_size > VPS_MAX_FILE_SIZE:
            proceed = messagebox.askyesno(
                t("msgbox_large_file_title"),
                t("msgbox_large_file_body",
                  file_size=human_size(file_size),
                  max_size=human_size(VPS_MAX_FILE_SIZE)),
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
                on_status=self._log,
                on_state=self._on_transfer_state,
                on_verify=self._verify_connection,
            )
            self._current_transfer = sender

            ok = sender.send()

            if ok:
                outcome = "success"
                self._set_state(self.STATE_DONE)
                self._log(t("transfer_complete_send"))
                self._log_donate(
                    t("donate_msg_send"),
                    DONATE_URL,
                )
            elif self._cancel_flag:
                outcome = "cancelled"
                self._set_state(self.STATE_IDLE)
                self._log(t("transfer_cancelled_send"))
            else:
                outcome = "error"
                self._set_state(self.STATE_ERROR)
                self._log(t("transfer_error_send"))

        except Exception as exc:
            outcome = "error"
            error_type = type(exc).__name__
            self._set_state(self.STATE_ERROR)
            self._log(t("transfer_error_generic", error=str(exc)))
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
            messagebox.showwarning(t("msgbox_code_title"), t("msgbox_code_body"))
            return

        save_dir = self._save_dir
        if not save_dir or not Path(save_dir).is_dir():
            messagebox.showwarning(t("msgbox_folder_title"), t("msgbox_folder_body"))
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
                on_status=self._log,
                on_state=self._on_transfer_state,
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
                self._log(t("transfer_complete_recv", path=result))
                self._log_donate(
                    t("donate_msg_recv"),
                    DONATE_URL,
                )
            elif self._cancel_flag:
                outcome = "cancelled"
                self._set_state(self.STATE_IDLE)
                self._log(t("transfer_cancelled_recv"))
            else:
                outcome = "error"
                self._set_state(self.STATE_ERROR)
                self._log(t("transfer_error_recv"))

        except Exception as exc:
            outcome = "error"
            error_type = type(exc).__name__
            self._set_state(self.STATE_ERROR)
            self._log(t("transfer_error_generic", error=str(exc)))
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
