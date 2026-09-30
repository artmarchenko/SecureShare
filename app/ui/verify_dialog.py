"""
SecureShare — verification-code dialog (mandatory MITM check).

Moved out of app/gui.py; `App` keeps a thin method that delegates here.
"""

from __future__ import annotations

import threading
from typing import Optional

import customtkinter as ctk

from ..i18n import t

# Seconds the user has to confirm the verification code
VERIFY_TIMEOUT = 120


def ask_verification(app, code: str) -> bool:
    """Show a modal verification dialog.  Thread-safe (called from worker).

    Returns True if the user confirms the codes match,
    False if cancelled or timed out.
    """
    result: list[Optional[bool]] = [None]
    event = threading.Event()
    dialog_ref: list = [None]

    def _show():
        dialog = ctk.CTkToplevel(app)
        dialog_ref[0] = dialog
        dialog.title(t("verify_title"))
        dialog.geometry("440x320")
        dialog.resizable(False, False)
        dialog.transient(app)
        dialog.grab_set()
        dialog.focus_force()

        # Center over parent
        dialog.update_idletasks()
        x = app.winfo_x() + (app.winfo_width() - 440) // 2
        y = app.winfo_y() + (app.winfo_height() - 320) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

        ctk.CTkLabel(
            dialog,
            text=t("verify_title"),
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(pady=(20, 8))

        ctk.CTkLabel(
            dialog,
            text=t("verify_prompt"),
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
            text=t("verify_warning"),
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
            text=t("btn_codes_match"),
            fg_color="#27ae60",
            hover_color="#2ecc71",
            command=_confirm,
            width=170,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame,
            text=t("btn_cancel_verify"),
            fg_color="#c0392b",
            hover_color="#e74c3c",
            command=_cancel,
            width=170,
        ).pack(side="right", padx=8)

        dialog.protocol("WM_DELETE_WINDOW", _cancel)

    app.after(0, _show)
    event.wait(timeout=VERIFY_TIMEOUT)
    if result[0] is None:
        # B5: nobody answered — close the stale dialog and tell the user
        def _close_stale():
            dialog = dialog_ref[0]
            if dialog is not None and dialog.winfo_exists():
                dialog.grab_release()
                dialog.destroy()
        app.after(0, _close_stale)
        app._log(t("verify_timeout"))
        return False
    return result[0]
