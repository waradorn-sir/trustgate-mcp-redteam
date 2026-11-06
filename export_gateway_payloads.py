"""
Step 4: export the Round 1 payloads that Sakshat's gateway can use.

His poisoned backend (step58_poisoned_backend.py with round2_payloads.py, tag
round2-freeze) appends payload text to the end of the public notice. So only
tool-output payloads that are appended (class C4, position "append") fit.
Description payloads (C1, C2) cannot reach the model through his proxy,
because the proxy declares its own tool descriptions.

His loader is strict, so this script follows the same rules:
  - every entry has exactly the keys id, class, text
  - id uses only letters, digits, dots, underscores, hyphens (max 100),
    and is not one of his built-in attack names
  - text is not empty
  - his backend glues the text straight onto the notice, so we add the same
    blank-line separator ("\n\n") that his built-in attacks start with

Run:
  python export_gateway_payloads.py
It writes payloads/round1_gateway.json. Sakshat can use it with
TG_PAYLOAD_FILE=<path to the file> and TG58_ATTACK=<payload id>.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent
SOURCE = ROOT / "payloads" / "round1.json"
TARGET = ROOT / "payloads" / "round1_gateway.json"

BUILT_IN_IDS = {"clean", "direct", "authority", "workflow", "metadata", "encoded"}
ID_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")


def main():
    payloads = json.loads(SOURCE.read_text(encoding="utf-8"))
    exported, skipped = [], []
    for p in payloads:
        fits = p["surface"] == "output" and p["position"] == "append"
        if not fits:
            skipped.append(f"{p['id']} ({p['surface']}, {p['position']})")
            continue
        pid = p["id"].lower()
        if not ID_RULE.fullmatch(pid) or pid in BUILT_IN_IDS:
            raise SystemExit(f"Payload id {p['id']!r} breaks the gateway loader's id rules")
        if not p["text"].strip():
            raise SystemExit(f"Payload {p['id']} has empty text")
        exported.append({"id": pid, "class": p["class"], "text": "\n\n" + p["text"].lstrip("\n")})

    TARGET.write_text(json.dumps({"payloads": exported}, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8")
    print(f"Wrote {len(exported)} payloads to {TARGET.relative_to(ROOT)}:")
    for e in exported:
        print(f"  {e['id']} ({e['class']})")
    print(f"Skipped {len(skipped)} (his backend only appends tool output):")
    for s in skipped:
        print(f"  {s}")


if __name__ == "__main__":
    main()
