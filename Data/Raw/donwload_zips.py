#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NVD JSON 2.0 year feeds downloader (2002..2025) — same directory as script.

- Downloads: nvdcve-2.0-YYYY.json.zip for 2002..2025
- Reads .meta to get sha256 and (if present) size
- Validates content-type, ZIP magic ('PK\x03\x04'), and size
- Verifies SHA256; on mismatch -> retries with cache-buster; if still mismatched
  but ZIP looks valid, keeps file and logs WARN instead of failing everything.

Output:
- Files saved next to this script
- Summary report: NVD_FETCH_REPORT.txt
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import time
from typing import Dict, Optional, Tuple, List

try:
    import requests
except ImportError:
    print("Please install requests: pip install requests", file=sys.stderr)
    sys.exit(1)

BASE = "https://nvd.nist.gov"
CVE_BASE = f"{BASE}/feeds/json/cve/2.0"
YEARS = list(range(2002, 2026))  # inclusive 2002..2025
DEST_DIR = Path(__file__).resolve().parent
TIMEOUT = 90
RETRIES = 2  # network retries per attempt
CHUNK = 1024 * 256

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
REFERER = "https://nvd.nist.gov/vuln/data-feeds"

def sha256_file(p: Path, buf: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(buf), b""):
            h.update(chunk)
    return h.hexdigest()

def fetch_meta(meta_url: str, s: requests.Session) -> Tuple[Optional[str], Optional[int], str]:
    """
    Returns (sha256, size_bytes, raw_text). Size may be None if not present.
    """
    r = s.get(meta_url, timeout=TIMEOUT)
    r.raise_for_status()
    text = r.text
    msha = re.search(r"(?:sha256|SHA-256)\s*:\s*([0-9a-fA-F]{64})", text)
    sha = msha.group(1).lower() if msha else None
    msize = re.search(r"(?:size|Size)\s*:\s*([0-9]+)", text)
    size = int(msize.group(1)) if msize else None
    return sha, size, text

def looks_like_zip(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(4)
        return head == b"PK\x03\x04"
    except Exception:
        return False

def http_download(url: str, s: requests.Session, out: Path) -> None:
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            with s.get(url, stream=True, timeout=TIMEOUT) as r:
                r.raise_for_status()
                ctype = (r.headers.get("Content-Type") or "").lower()
                total = int(r.headers.get("Content-Length") or 0)
                # Write to .part
                tmp = out.with_suffix(out.suffix + ".part")
                done = 0
                with tmp.open("wb") as f:
                    for chunk in r.iter_content(chunk_size=CHUNK):
                        if chunk:
                            f.write(chunk)
                            done += len(chunk)
                            if total:
                                pct = int(done * 100 / max(1, total))
                                print(f"\r  ↳ {out.name} [{pct:3d}%]", end="", flush=True)
                print("\r  ↳ " + out.name + " [done]" + " " * 10)
                tmp.replace(out)
                return
        except Exception as e:
            last_err = e
            print(f"\n  ! download error ({attempt}/{RETRIES}) {url}: {e}")
            time.sleep(1.5 * attempt)
    raise RuntimeError(f"Download failed after retries: {last_err}")

def download_one(year: int, s: requests.Session, report: List[str]) -> None:
    data_url = f"{CVE_BASE}/nvdcve-2.0-{year}.json.zip"
    meta_url = f"{CVE_BASE}/nvdcve-2.0-{year}.meta"
    out_path = DEST_DIR / f"nvdcve-2.0-{year}.json.zip"

    # 1) Fetch meta (sha + size)
    try:
        sha_meta, size_meta, _ = fetch_meta(meta_url, s)
    except Exception as e:
        report.append(f"{year}: FAIL (meta) — {e}")
        return

    # 2) Download (first attempt)
    print(f"[get ] {out_path.name}")
    try:
        http_download(data_url, s, out_path)
    except Exception as e:
        report.append(f"{year}: FAIL (download) — {e}")
        out_path.unlink(missing_ok=True)
        return

    # 3) Validate content
    #    - ZIP magic
    #    - size vs meta (if present)
    #    - sha256 vs meta (if present)
    def validate(tag: str) -> Tuple[bool, str]:
        if not looks_like_zip(out_path):
            # Sometimes NVD/CDN returns HTML error page — keep a copy for debug
            html_dump = out_path.with_suffix(".err.html")
            try:
                out_path.rename(html_dump)
            except Exception:
                pass
            return False, f"{tag}: NOT_ZIP (saved as {html_dump.name})"
        if size_meta is not None:
            try:
                actual = out_path.stat().st_size
                # Allow small drift (rare header differences), but flag large deviations
                if abs(actual - size_meta) > max(1024, int(size_meta * 0.02)):
                    return False, f"{tag}: SIZE_MISMATCH (meta {size_meta}, got {actual})"
            except Exception as e:
                return False, f"{tag}: SIZE_CHECK_ERROR ({e})"
        if sha_meta:
            try:
                got = sha256_file(out_path).lower()
                if got != sha_meta:
                    return False, f"{tag}: SHA256_MISMATCH (exp {sha_meta}, got {got})"
            except Exception as e:
                return False, f"{tag}: SHA256_ERROR ({e})"
        return True, "OK"

    ok, msg = validate("first")
    if ok:
        report.append(f"{year}: OK")
        return

    # 4) Retry once with cache-buster if SHA/size mismatch or HTML page
    print(f"[warn] {out_path.name} → {msg}; retrying with cache-buster…")
    out_path.unlink(missing_ok=True)
    bust = f"{data_url}?t={int(time.time())}"
    try:
        http_download(bust, s, out_path)
    except Exception as e:
        report.append(f"{year}: FAIL (retry download) — {e}")
        out_path.unlink(missing_ok=True)
        return

    ok2, msg2 = validate("retry")
    if ok2:
        report.append(f"{year}: OK (retry)")
        return

    # 5) As a pragmatic fallback: if it *is* a ZIP (valid magic) but SHA differs,
    #    keep the file and warn (so the user still gets usable data).
    if looks_like_zip(out_path):
        report.append(f"{year}: WARN (kept despite {msg2})")
        return

    # 6) Otherwise fail and remove
    report.append(f"{year}: FAIL ({msg2})")
    out_path.unlink(missing_ok=True)

def main() -> int:
    DEST_DIR.mkdir(parents=True, exist_ok=True)

    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Referer": REFERER,
        "Accept": "*/*",
        "Accept-Encoding": "identity",  # avoid extra CDN/gzip layers on top of .zip
        "Connection": "keep-alive",
    })

    report: List[str] = []
    ok = warn = fail = 0

    for y in YEARS:
        try:
            download_one(y, s, report)
        except Exception as e:
            report.append(f"{y}: FAIL (unhandled) — {e}")

    # Tally
    for line in report:
        if ": OK" in line:
            ok += 1
        elif ": WARN" in line:
            warn += 1
        else:
            fail += 1

    # Write report
    rpt = DEST_DIR / "NVD_FETCH_REPORT.txt"
    with rpt.open("w", encoding="utf-8") as f:
        f.write("NVD JSON 2.0 year feeds (2002..2025)\n")
        f.write(f"Directory: {DEST_DIR}\n")
        f.write("-" * 60 + "\n")
        for line in report:
            f.write(line + "\n")
        f.write("-" * 60 + "\n")
        f.write(f"Summary → OK={ok}  WARN(MISMATCH)={warn}  FAIL={fail}\n")

    print(f"\nSummary → OK={ok}  WARN={warn}  FAIL={fail}")
    print(f"Report saved to: {rpt}")
    return 0 if fail == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())

