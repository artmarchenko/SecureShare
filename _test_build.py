# -*- coding: utf-8 -*-
"""Build with v3.3.0, restore source to v3.3.5, then launch the old build."""
import sys, subprocess
sys.stdout.reconfigure(errors='replace')

old_ver, fake_ver = '3.3.5', '3.3.0'

patches = {
    'app/config.py': [(f'APP_VERSION = "{old_ver}"', f'APP_VERSION = "{fake_ver}"')],
    'version_info.txt': [
        ('(3, 3, 5, 0)', '(3, 3, 0, 0)'),
        (f"u'{old_ver}.0'", f"u'{fake_ver}.0'"),
    ],
}

# Save originals
originals = {}
for path in patches:
    originals[path] = open(path, 'r', encoding='utf-8').read()

try:
    # Patch
    for path, replacements in patches.items():
        data = originals[path]
        for o, n in replacements:
            data = data.replace(o, n)
        open(path, 'w', encoding='utf-8').write(data)
    print(f"Patched to v{fake_ver}")

    # Build
    print("Building...")
    subprocess.check_call([sys.executable, 'build.py'], cwd='.')
    print("Build OK!")
finally:
    # Restore
    for path, content in originals.items():
        open(path, 'w', encoding='utf-8').write(content)
    print(f"Source restored to v{old_ver}")

# Launch
print("Launching...")
subprocess.Popen(['dist/SecureShare.exe'])
print("Done! App should show v3.3.0, server has v3.3.5")
