"""
netstat_ano.py  -  EVERYTHING in ONE file

On your PC (scan mode):
    python netstat_ano.py                 scan once, update the file, push to GitHub
    python netstat_ano.py --loop          keep scanning every 15 minutes (leave the window open)
    python netstat_ano.py --install       set up automatic scanning every 15 minutes
                                          (Windows Task Scheduler, no window needed)
    python netstat_ano.py --uninstall     remove that automatic scan

In the browser (dashboard mode):
    streamlit run netstat_ano.py          shows foreign_ip_status.txt as a table.
                                          This is what Streamlit Cloud runs online.

The file works out which mode to use by itself.

Setup (once, on your PC):
  - pip install requests streamlit
  - Keep this file inside your git repo folder.
  - Save your VirusTotal key as an environment variable (not in the code):
        setx VT_API_KEY "your_key_here"
    then close and reopen your terminal.
    $env:VT_API_KEY = "126d8d6c1ad85662aa55f46f0a9a3b0e46df995e1d101a66830fcebdeb3b2981"
    setx VT_API_KEY "126d8d6c1ad85662aa55f46f0a9a3b0e46df995e1d101a66830fcebdeb3b2981"
"""

import ipaddress
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta

# -----------------------------------------------------------------------
# Settings
# -----------------------------------------------------------------------

# Always use the folder this script lives in, so it works no matter where
# Task Scheduler starts it from.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "foreign_ip_status.txt")
CACHE_FILE = os.path.join(SCRIPT_DIR, "ip_cache.json")   # stays local
LOG_FILE = os.path.join(SCRIPT_DIR, "scan_log.txt")      # stays local

API_KEY = os.environ.get("VT_API_KEY")

RECHECK_AFTER_DAYS = 7     # re-check an IP on VirusTotal after this long
SHOW_LAST_HOURS = 24       # show IPs seen within this many hours
MAX_LOOKUPS_PER_RUN = 20   # keeps us far below the free daily quota
WAIT_BETWEEN_LOOKUPS = 16  # free tier allows about 4 requests per minute


# -----------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------

def log(message):
    """Add a timestamped line to scan_log.txt so you can see what happened."""
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S}  {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_cache():
    """Read the saved VirusTotal results (an empty dict if there are none)."""
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


# -----------------------------------------------------------------------
# Step 1: find public IPs from ESTABLISHED connections
# -----------------------------------------------------------------------

def get_current_public_ips():
    """Run netstat -ano and return the set of public foreign IPs."""
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    public_ips = set()

    for line in result.stdout.splitlines():
        if "ESTABLISHED" not in line:
            continue

        columns = line.split()
        if len(columns) < 3:
            continue

        foreign = columns[2]  # e.g. "104.18.32.9:443" or "[2606:4700::1]:443"

        # Separate the IP from the port (IPv6 addresses are in [brackets]).
        if foreign.startswith("["):
            ip = foreign[1:foreign.rindex("]")]
        else:
            ip = foreign.rsplit(":", 1)[0]
        ip = ip.split("%")[0]  # remove an IPv6 zone id like "%12" if present

        try:
            # is_global is True only for real internet addresses (not
            # private, loopback, link-local or reserved ranges).
            if ipaddress.ip_address(ip).is_global:
                public_ips.add(ip)
        except ValueError:
            continue

    return public_ips


# -----------------------------------------------------------------------
# Step 2: VirusTotal lookup (only for new or stale IPs)
# -----------------------------------------------------------------------

def needs_lookup(entry, now):
    """True if we've never checked this IP, or the last check is old."""
    if "checked_at" not in entry:
        return True
    checked_at = datetime.fromisoformat(entry["checked_at"])
    return now - checked_at > timedelta(days=RECHECK_AFTER_DAYS)


def lookup_virustotal(ip):
    """Ask VirusTotal about one IP. Returns (result_dict_or_None, status_code)."""
    import requests  # only needed when scanning locally

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers={"x-apikey": API_KEY}, timeout=20)

    if response.status_code != 200:
        return None, response.status_code

    attributes = response.json()["data"]["attributes"]
    stats = attributes.get("last_analysis_stats", {})
    result = {
        "country": attributes.get("country", "Unknown"),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
    }
    return result, 200


# -----------------------------------------------------------------------
# Step 3: write the results table
# -----------------------------------------------------------------------

def write_results_file(cache, now):
    """Write one row per recently seen IP, flagged ones first."""
    cutoff = now - timedelta(hours=SHOW_LAST_HOURS)
    rows = []

    for ip, entry in cache.items():
        last_seen = entry.get("last_seen")
        if not last_seen or datetime.fromisoformat(last_seen) < cutoff:
            continue  # not seen recently, leave it out of the table

        if "checked_at" not in entry:
            country, malicious, suspicious, status = "?", "?", "?", "Unchecked"
        else:
            country = entry["country"]
            malicious = entry["malicious"]
            suspicious = entry["suspicious"]
            status = "FLAGGED" if (malicious > 0 or suspicious > 0) else "Clean"

        rows.append((ip, country, malicious, suspicious, status))

    # FLAGGED first, then Unchecked, then Clean; IP order within each group.
    order = {"FLAGGED": 0, "Unchecked": 1, "Clean": 2}
    rows.sort(key=lambda r: (order[r[4]], r[0]))

    header = f"{'IP Address':<40}{'Country':<10}{'Malicious':<11}{'Suspicious':<12}{'Status':<12}"
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        f.write("-" * len(header) + "\n")
        for ip, country, malicious, suspicious, status in rows:
            f.write(f"{ip:<40}{country:<10}{str(malicious):<11}{str(suspicious):<12}{status:<12}\n")

    return len(rows)


# -----------------------------------------------------------------------
# Step 4: push to GitHub (only if the file changed)
# -----------------------------------------------------------------------

def run_git(*args):
    return subprocess.run(["git", *args], cwd=SCRIPT_DIR, capture_output=True, text=True)


def push_to_github(now):
    # Only this one file is ever added, so your API key, cache and log are
    # never committed by accident.
    run_git("add", "foreign_ip_status.txt")

    # "diff --cached --quiet" exits with 0 when there is nothing new to commit.
    if run_git("diff", "--cached", "--quiet").returncode == 0:
        log("No changes to push.")
        return

    run_git("commit", "-m", f"Update scan {now:%Y-%m-%d %H:%M}")
    result = run_git("push")
    if result.returncode == 0:
        log("Pushed new results to GitHub.")
    else:
        log(f"Git push FAILED: {result.stderr.strip()}")


# -----------------------------------------------------------------------
# SCAN mode
# -----------------------------------------------------------------------

def run_scan():
    if not API_KEY:
        log("ERROR: VT_API_KEY environment variable is not set.")
        sys.exit(1)

    now = datetime.now()
    cache = load_cache()

    # Record every public IP we can see right now.
    current_ips = get_current_public_ips()
    for ip in current_ips:
        cache.setdefault(ip, {})["last_seen"] = now.isoformat(timespec="seconds")

    # Only look up IPs that are new or stale (capped per run).
    to_check = [ip for ip in sorted(current_ips) if needs_lookup(cache[ip], now)]
    to_check = to_check[:MAX_LOOKUPS_PER_RUN]

    for index, ip in enumerate(to_check):
        result, status_code = lookup_virustotal(ip)

        if result:
            cache[ip].update(result)
            cache[ip]["checked_at"] = now.isoformat(timespec="seconds")
        elif status_code == 429:
            log("VirusTotal rate limit reached; the rest will be checked next run.")
            break
        else:
            log(f"Lookup failed for {ip} (HTTP {status_code}); will retry next run.")

        if index < len(to_check) - 1:
            time.sleep(WAIT_BETWEEN_LOOKUPS)

    save_cache(cache)
    row_count = write_results_file(cache, now)
    log(f"Scan done: {len(current_ips)} public IPs now, {len(to_check)} looked up, {row_count} rows written.")

    push_to_github(now)


# -----------------------------------------------------------------------
# DASHBOARD mode
# -----------------------------------------------------------------------

def read_results_from_file():
    """Read foreign_ip_status.txt line by line into a list of dictionaries."""
    rows = []
    if not os.path.exists(OUTPUT_FILE):
        return rows

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Skip the header row and the "-----" divider line.
    for line in lines[2:]:
        if not line.strip():
            continue

        # Split into at most 5 pieces; this works whatever the column widths.
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue

        ip, country, malicious, suspicious, status = parts
        rows.append({
            "ip": ip,
            "country": country,
            "malicious": malicious,
            "suspicious": suspicious,
            "status": status.strip(),
        })
    return rows


def run_dashboard():
    import streamlit as st

    st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")
    st.title("🌐 Foreign IP Reputation Dashboard")

    results = read_results_from_file()

    if not results:
        st.warning("No data yet. Run 'python netstat_ano.py' on your PC to create foreign_ip_status.txt.")
        return

    flagged = sum(1 for r in results if r["status"] == "FLAGGED")
    clean = sum(1 for r in results if r["status"] == "Clean")

    col1, col2, col3 = st.columns(3)
    col1.metric("IPs (last 24h)", len(results))
    col2.metric("Flagged", flagged)
    col3.metric("Clean", clean)

    st.subheader("Results")
    st.table(results)

    if st.button("Refresh"):
        st.rerun()


# -----------------------------------------------------------------------
# Pick the mode
# -----------------------------------------------------------------------

def running_inside_streamlit():
    """True when Streamlit is running this file (streamlit run ...)."""
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
    except Exception:
        return False  # Streamlit isn't installed, so we must be in scan mode
    try:
        return get_script_run_ctx(suppress_warning=True) is not None
    except TypeError:
        return get_script_run_ctx() is not None


# -----------------------------------------------------------------------
# Built-in scheduling (so you don't need any other file or tool)
# -----------------------------------------------------------------------

TASK_NAME = "exIPcheck scan"
SCAN_EVERY_MINUTES = 15


def install_schedule():
    """Create a Windows Task Scheduler job that runs this script's scan."""
    if os.name != "nt":
        print("--install only works on Windows (it uses Task Scheduler).")
        return

    # pythonw.exe runs Python without opening a console window each time.
    python_exe = sys.executable
    pythonw_exe = os.path.join(os.path.dirname(python_exe), "pythonw.exe")
    if os.path.exists(pythonw_exe):
        python_exe = pythonw_exe

    script_path = os.path.abspath(__file__)
    command = f'"{python_exe}" "{script_path}"'

    result = subprocess.run(
        ["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(SCAN_EVERY_MINUTES),
         "/TN", TASK_NAME, "/TR", command],
        capture_output=True, text=True,
    )
    print(result.stdout.strip() or result.stderr.strip())
    if result.returncode == 0:
        print(f"Done. A scan will now run every {SCAN_EVERY_MINUTES} minutes while you are logged in.")


def uninstall_schedule():
    if os.name != "nt":
        print("--uninstall only works on Windows.")
        return
    result = subprocess.run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME],
                            capture_output=True, text=True)
    print(result.stdout.strip() or result.stderr.strip())


def run_loop():
    """Scan, wait, repeat. Press Ctrl+C to stop."""
    print(f"Scanning every {SCAN_EVERY_MINUTES} minutes. Press Ctrl+C to stop.")
    while True:
        try:
            run_scan()
        except SystemExit:
            raise  # e.g. missing API key: stop instead of retrying forever
        except Exception as error:
            log(f"Scan crashed: {error}")  # keep looping; try again next time
        time.sleep(SCAN_EVERY_MINUTES * 60)


def main():
    option = sys.argv[1] if len(sys.argv) > 1 else ""
    if option == "--install":
        install_schedule()
    elif option == "--uninstall":
        uninstall_schedule()
    elif option == "--loop":
        run_loop()
    else:
        run_scan()


if running_inside_streamlit():
    run_dashboard()
elif __name__ == "__main__":
    main()