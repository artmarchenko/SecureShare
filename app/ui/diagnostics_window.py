"""
SecureShare — diagnostics window (connectivity checks + privacy toggles).

Moved out of app/gui.py; `App` keeps a thin method that delegates here.
"""

from __future__ import annotations

import threading

import customtkinter as ctk

from ..config import APP_NAME
from ..diagnostics import run_checks
from ..i18n import t
from ..telemetry import (
    is_crash_reporting_enabled, is_telemetry_enabled,
    set_crash_reporting_enabled, set_telemetry_enabled,
)


def open_diagnostics(app) -> None:
    """Run connectivity diagnostics in a background thread and show results."""
    # Prevent multiple diagnostic windows
    if hasattr(app, "_diag_win") and app._diag_win is not None:
        try:
            app._diag_win.focus()
            return
        except Exception:
            pass

    win = ctk.CTkToplevel(app)
    win.title(f"{APP_NAME} — {t('diag_title')}")
    win.geometry("480x540")
    win.resizable(False, False)
    win.transient(app)
    win.grab_set()
    app._diag_win = win

    def _on_close():
        app._diag_win = None
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", _on_close)

    # Header
    header = ctk.CTkFrame(win, fg_color="#1a3a5c", corner_radius=0)
    header.pack(fill="x")
    ctk.CTkLabel(
        header,
        text=t("diag_header"),
        font=ctk.CTkFont(size=17, weight="bold"),
        text_color="white",
    ).pack(padx=20, pady=12)

    # Results area
    results_frame = ctk.CTkFrame(win, fg_color="transparent")
    results_frame.pack(fill="both", expand=True, padx=20, pady=(12, 6))

    checks = [
        ("internet",  t("diag_internet")),
        ("dns",       t("diag_dns")),
        ("tls",       t("diag_tls")),
        ("websocket", t("diag_websocket")),
        ("latency",   t("diag_latency")),
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
            row, text=t("diag_checking"),
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

    # Privacy toggles (crash reports are on by default, usage stats off)
    privacy = ctk.CTkFrame(win, fg_color="#2a2a2a", corner_radius=8)
    privacy.pack(fill="x", padx=20, pady=(4, 6))
    ctk.CTkLabel(
        privacy, text=t("diag_privacy_title"),
        font=ctk.CTkFont(size=13, weight="bold"), anchor="w",
    ).pack(fill="x", padx=12, pady=(8, 2))

    crash_var = ctk.BooleanVar(value=is_crash_reporting_enabled())
    stats_var = ctk.BooleanVar(value=is_telemetry_enabled())
    app._diag_crash_switch = ctk.CTkSwitch(
        privacy, text=t("diag_crash_reports"), variable=crash_var,
        command=lambda: set_crash_reporting_enabled(bool(crash_var.get())),
    )
    app._diag_crash_switch.pack(anchor="w", padx=12, pady=2)
    app._diag_stats_switch = ctk.CTkSwitch(
        privacy, text=t("diag_usage_stats"), variable=stats_var,
        command=lambda: set_telemetry_enabled(bool(stats_var.get())),
    )
    app._diag_stats_switch.pack(anchor="w", padx=12, pady=(2, 10))

    # Close button
    close_btn = ctk.CTkButton(
        win, text=t("btn_close"), width=140, height=32,
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

    def _update_summary(text: str, color: str):
        win.after(0, lambda: summary_label.configure(text=text, text_color=color))

    # Run checks in background thread
    threading.Thread(target=run_checks, args=(_update_row, _update_summary), daemon=True).start()
