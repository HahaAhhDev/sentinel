import os

# boring names that scream if touched

NAMES = [
    "taxes_2022.docx",
    "passwords.txt",
    "family_photos.zip",
    "backup_keys.txt",
    "payroll.xlsx",
]


def paths_for(root):
    # spread across top level
    root = os.path.abspath(root)
    return [os.path.join(root, n) for n in NAMES]


def deploy(root):
    # make the ones missing
    made = 0
    for p in paths_for(root):
        if os.path.exists(p):
            continue
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("tripwire, do not touch\n")
            made += 1
        except OSError:
            continue
    return made


def is_canary(root, full):
    # match any of ours
    want = {os.path.abspath(p) for p in paths_for(root)}
    want.add(os.path.abspath(os.path.join(root, ".sentinel", "canary.txt")))
    return os.path.abspath(full) in want
