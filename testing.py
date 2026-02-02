from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path


EVENT_ID = 4625
COUNT = 50


def query_security_log(event_id: int, count: int) -> str:
    query = f"*[System[(EventID={event_id})]]"
    cmd = [
        "wevtutil",
        "qe",
        "Security",
        f"/q:{query}",
        "/f:xml",
        f"/c:{count}",
        "/rd:true",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        err = (result.stderr or result.stdout).strip()
        raise RuntimeError(err if err else "wevtutil returned a non-zero exit code.")

    return result.stdout.strip()


def save_text(text: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    print(f"[Log and Key] Querying Security log for Event ID {EVENT_ID} (latest {COUNT})...")

    try:
        xml_text = query_security_log(EVENT_ID, COUNT)
    except FileNotFoundError:
        print("Error: wevtutil not found (this must be run on Windows).")
        return 1
    except RuntimeError as e:
        print("Error: wevtutil failed.")
        print(str(e))
        return 1

    if not xml_text:
        print("No events returned.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = Path("data") / f"security_{EVENT_ID}_{stamp}.xml"
    save_text(xml_text, out_file)

    print(f"Saved to: {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
