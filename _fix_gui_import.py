# -*- coding: utf-8 -*-
"""Add 'else' block for blocked auto-update (running from archive)."""
import sys
sys.stdout.reconfigure(errors='replace')

data = open('app/gui.py', 'r', encoding='utf-8').read()

# Find the line after auto_update_btn.pack and add elif block
old = '            auto_update_btn.pack(side="left", padx=(0, 6), fill="x", expand=True)\n\n        def _download():'

new = (
    '            auto_update_btn.pack(side="left", padx=(0, 6), fill="x", expand=True)\n'
    '\n'
    '        elif _blocked_reason:\n'
    '            # Running from archive/temp — show warning instead of update btn\n'
    '            ctk.CTkLabel(\n'
    '                btn_frame,\n'
    '                text="\u26a0\ufe0f \u0420\u043e\u0437\u043f\u0430\u043a\u0443\u0439\u0442\u0435 \u0430\u0440\u0445\u0456\u0432 \u0434\u043b\u044f \u0430\u0432\u0442\u043e\u043e\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u044f",\n'
    '                font=ctk.CTkFont(size=11),\n'
    '                text_color="#e67e22",\n'
    '            ).pack(side="left", padx=(0, 6))\n'
    '\n'
    '        def _download():'
)

if old not in data:
    print("ERROR: target block not found")
    idx = data.find('auto_update_btn.pack')
    if idx >= 0:
        print(repr(data[idx:idx+120]))
    sys.exit(1)

data = data.replace(old, new, 1)
open('app/gui.py', 'w', encoding='utf-8').write(data)
print("OK: archive warning block added")
