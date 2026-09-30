"""
SecureShare — update available dialog (download, verify, install).

Moved out of app/gui.py; `App` keeps a thin method that delegates here.
"""

from __future__ import annotations

import threading

import customtkinter as ctk

from ..config import APP_NAME, APP_VERSION
from ..i18n import t
from ..updater import (
    ReleaseInfo, can_auto_update, download_and_verify,
    get_update_blocked_reason, install_and_restart, skip_version,
)


def open_update_dialog(app, release: ReleaseInfo) -> None:
    """Show a modal dialog informing the user about a new version."""
    if hasattr(app, "_update_win") and app._update_win is not None:
        try:
            app._update_win.focus()
            return
        except Exception:
            pass

    win = ctk.CTkToplevel(app)
    win.title(f"{APP_NAME} — {t('update_title')}")
    win.geometry("540x580")
    win.resizable(True, True)
    win.transient(app)
    win.grab_set()
    win.focus_force()
    app._update_win = win

    def _on_close():
        app._update_win = None
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", _on_close)

    # Center over parent
    win.update_idletasks()
    x = app.winfo_x() + (app.winfo_width() - 540) // 2
    y = app.winfo_y() + (app.winfo_height() - 580) // 2
    win.geometry(f"+{max(0, x)}+{max(0, y)}")

    # ── Header ────────────────────────────────────────────────
    header = ctk.CTkFrame(win, fg_color="#1a5276", corner_radius=0)
    header.pack(fill="x")
    ctk.CTkLabel(
        header,
        text=t("update_header"),
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
        text=t("update_current", version=APP_VERSION),
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
        text=t("update_new", version=release.version),
        font=ctk.CTkFont(size=13, weight="bold"),
        text_color="#2ecc71",
    ).pack(side="left")

    if release.published:
        pub_date = release.published[:10]  # YYYY-MM-DD
        ctk.CTkLabel(
            info_frame,
            text=t("update_published", date=pub_date),
            font=ctk.CTkFont(size=11),
            text_color="#888888",
        ).pack(padx=16, pady=(0, 10))

    # ── Release notes ─────────────────────────────────────────
    ctk.CTkLabel(
        win,
        text=t("update_whats_new"),
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
        body = t("update_no_description")
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
    _blocked_reason = get_update_blocked_reason()
    if can_auto_update():
        def _auto_update():
            """Download, verify, and install the update automatically."""
            # Disable all buttons
            if auto_update_btn:
                auto_update_btn.configure(state="disabled", text=t("update_updating"))
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
                    text=f"{pct:.0f}%  ·  {mb_done:.1f} / {mb_total:.1f} {t('unit_mb')}"
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

                    _status(t("updater_installing"))
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
                        text=f"❌ {_e}", text_color="#e74c3c",
                    ))
                    win.after(0, lambda: _enable_buttons())

            def _enable_buttons():
                if auto_update_btn:
                    auto_update_btn.configure(
                        state="normal", text=t("btn_update_now")
                    )
                for child in btn_frame.winfo_children():
                    try:
                        child.configure(state="normal")
                    except Exception:
                        pass

            threading.Thread(target=_worker, daemon=True).start()

        auto_update_btn = ctk.CTkButton(
            btn_frame,
            text=t("btn_update_now"),
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2471a3",
            hover_color="#2e86c1",
            height=40,
            command=_auto_update,
        )
        auto_update_btn.pack(side="left", padx=(0, 6), fill="x", expand=True)

    elif _blocked_reason:
        # Running from archive/temp — show warning instead of update btn
        ctk.CTkLabel(
            btn_frame,
            text=t("updater_blocked_archive").split("\n")[0],
            font=ctk.CTkFont(size=11),
            text_color="#e67e22",
        ).pack(side="left", padx=(0, 6))

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
        height=40,
        width=90,
        command=_download,
    ).pack(side="left", padx=(0, 6))

    def _skip():
        """Skip this specific version."""
        skip_version(release.version)
        app._log(t("update_skipped", version=release.version))
        _on_close()

    ctk.CTkButton(
        btn_frame,
        text=t("btn_skip_version"),
        font=ctk.CTkFont(size=12),
        fg_color="#555555",
        hover_color="#666666",
        height=40,
        width=110,
        command=_skip,
    ).pack(side="left", padx=(0, 6))

    ctk.CTkButton(
        btn_frame,
        text=t("btn_later"),
        font=ctk.CTkFont(size=12),
        fg_color="#3a3a3a",
        hover_color="#4a4a4a",
        height=40,
        width=80,
        command=_on_close,
    ).pack(side="right")
