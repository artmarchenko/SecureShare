"""
SecureShare — human-readable formatting of sizes, speeds and durations.

Used by the GUI and by transfer status messages; units are translated.
"""

from __future__ import annotations

from .i18n import t


def human_size(b: int | float) -> str:
    for key in ("unit_b", "unit_kb", "unit_mb", "unit_gb", "unit_tb"):
        if abs(b) < 1024:
            return f"{b:.1f} {t(key)}"
        b /= 1024
    return f"{b:.1f} {t('unit_pb')}"


def human_speed(bps: float) -> str:
    return f"{human_size(bps)}{t('speed_suffix')}"


def human_eta(seconds: float) -> str:
    if seconds < 0 or seconds > 360000:
        return "—"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return t("eta_hours", h=h, m=m)
    if m:
        return t("eta_minutes", m=m, s=s)
    return t("eta_seconds", s=s)
