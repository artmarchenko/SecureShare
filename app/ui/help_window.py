"""
SecureShare — help window.

Moved out of app/gui.py; `App` keeps a thin method that delegates here.
"""

from __future__ import annotations

import webbrowser

import customtkinter as ctk

from ..config import APP_NAME, HOMEPAGE_URL, VPS_MAX_FILE_SIZE
from ..i18n import t


def open_help(app) -> None:
    """Open a modal help window with step-by-step instructions."""
    # Prevent multiple help windows
    if hasattr(app, "_help_win") and app._help_win is not None:
        try:
            app._help_win.focus()
            return
        except Exception:
            pass

    win = ctk.CTkToplevel(app)
    win.title(f"{APP_NAME} — {t('help_title')}")
    win.geometry("520x560")
    win.resizable(True, True)
    win.transient(app)
    win.grab_set()
    app._help_win = win

    def _on_close():
        app._help_win = None
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", _on_close)

    # Header with accent background
    header_frame = ctk.CTkFrame(win, fg_color="#1a5276", corner_radius=0)
    header_frame.pack(fill="x")
    ctk.CTkLabel(
        header_frame,
        text=t("help_header"),
        font=ctk.CTkFont(size=18, weight="bold"),
        text_color="white",
    ).pack(padx=20, pady=14)

    # Scrollable content
    scroll = ctk.CTkScrollableFrame(win, fg_color="transparent")
    scroll.pack(fill="both", expand=True, padx=12, pady=(8, 6))

    # Section color scheme: (title, body, card_color, title_color, accent_bar)
    max_gb = VPS_MAX_FILE_SIZE // (1024**3)
    help_sections = [
        (t("help_send_title"), t("help_send_body"), "#1a3a2a", "#2ecc71"),
        (t("help_recv_title"), t("help_recv_body"), "#1a2a3a", "#3498db"),
        (t("help_verify_title"), t("help_verify_body"), "#2a2a1a", "#f1c40f"),
        (t("help_security_title"), t("help_security_body"), "#1a1a2a", "#9b59b6"),
        (t("help_limits_title"), t("help_limits_body", max_gb=max_gb), "#2a1a1a", "#e74c3c"),
        (t("help_reconnect_title"), t("help_reconnect_body"), "#1a2a3a", "#e67e22"),
        (t("help_troubleshoot_title"), t("help_troubleshoot_body"), "#1a2a2a", "#1abc9c", HOMEPAGE_URL),
        (t("help_autoupdate_title"), t("help_autoupdate_body"), "#1a2a2a", "#3498db"),
        (t("help_donate_title"), t("help_donate_body"), "#2a1a2a", "#e91e63"),
    ]

    for item in help_sections:
        title, body, card_bg, title_color = item[:4]
        link_url = item[4] if len(item) > 4 else None

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
        ).pack(fill="x", padx=20, pady=(0, 4 if link_url else 10))

        # Clickable link (if provided)
        if link_url:
            _url = link_url  # capture for lambda
            link_btn = ctk.CTkButton(
                card,
                text=link_url,
                font=ctk.CTkFont(size=12, underline=True),
                text_color="#5dade2",
                fg_color="transparent",
                hover_color=card_bg,
                anchor="w",
                height=20,
                command=lambda u=_url: webbrowser.open(u),
            )
            link_btn.pack(fill="x", padx=20, pady=(0, 10))

    # Close button
    ctk.CTkButton(
        win,
        text=t("btn_close"),
        width=140,
        height=32,
        fg_color="#1a5276",
        hover_color="#2471a3",
        command=_on_close,
    ).pack(pady=(6, 12))
