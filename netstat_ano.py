"""
ip_dashboard.py

An all-in-one Streamlit app that:
1. Runs netstat -ano to find ESTABLISHED connections.
2. Looks up each public foreign IP on VirusTotal.
3. Saves the results to "foreign_ip_status.txt" (one row per IP).
4. Reads that same file back in, LINE BY LINE, and displays it as a
   table/dashboard in the browser.

Before running this:
1. pip install streamlit requests
2. Get a free API key from https://www.virustotal.com and paste it into
   the API_KEY variable below.
3. Run with:
       streamlit run ip_dashboard.py
   (Run your terminal as Administrator first, since netstat needs that.)
"""

import subprocess
import ipaddress
import time
import requests
import streamlit as st
import os

# -----------------------------------------------------------------------
# STEP 0: Settings
# -----------------------------------------------------------------------
API_KEY = "126d8d6c1ad85662aa55f46f0a9a3b0e46df995e1d101a66830fcebdeb3b2981"
OUTPUT_FILE_NAME = "foreign_ip_status.txt"
WAIT_BETWEEN_REQUESTS = 16  # seconds, to respect VirusTotal's free rate limit

# These must match on both the "writing" side and the "reading" side, so
# the columns line up correctly when we slice the text back apart later.
COL_WIDTHS = {"ip": 16, "country": 10, "malicious": 11, "suspicious": 12, "status": 15}


# -----------------------------------------------------------------------
# STEP 1: Run netstat and collect public foreign IPs
# -----------------------------------------------------------------------
def get_public_ips():
    """Run netstat -ano and return a list of unique public foreign IPs
    from ESTABLISHED connections."""
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
    lines = result.stdout.splitlines()

    public_ips = []
    for line in lines:
        if "ESTABLISHED" not in line:
            continue

        columns = line.split()
        if len(columns) < 3:
            continue

        foreign_address = columns[2]
        ip, port = foreign_address.rsplit(":", 1)

        try:
            ip_object = ipaddress.ip_address(ip)
            if ip_object.is_private:
                continue
        except ValueError:
            continue

        if ip not in public_ips:
            public_ips.append(ip)

    return public_ips


# -----------------------------------------------------------------------
# STEP 2: Check IPs on VirusTotal and write results to the file
# -----------------------------------------------------------------------
def scan_and_save(public_ips, progress_bar):
    """Look up each IP on VirusTotal and write one padded row per IP into
    OUTPUT_FILE_NAME. Column widths come from COL_WIDTHS so the file can
    be read back in cleanly afterward."""
    headers = {"x-apikey": API_KEY}

    w = COL_WIDTHS  # short alias, just to keep the line below readable
    header_row = (
        f"{'IP Address':<{w['ip']}}{'Country':<{w['country']}}"
        f"{'Malicious':<{w['malicious']}}{'Suspicious':<{w['suspicious']}}"
        f"{'Status':<{w['status']}}"
    )

    with open(OUTPUT_FILE_NAME, "w", encoding="utf-8") as output_file:
        output_file.write(header_row + "\n")
        output_file.write("-" * len(header_row) + "\n")

        for index, ip in enumerate(public_ips):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            response = requests.get(url, headers=headers)

            if response.status_code != 200:
                country, malicious, suspicious = "?", "?", "?"
                status = f"Error {response.status_code}"
            else:
                data = response.json()
                attributes = data["data"]["attributes"]
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                country = attributes.get("country", "Unknown")
                status = "FLAGGED" if (malicious > 0 or suspicious > 0) else "Clean"

            row = (
                f"{ip:<{w['ip']}}{country:<{w['country']}}"
                f"{malicious:<{w['malicious']}}{suspicious:<{w['suspicious']}}"
                f"{status:<{w['status']}}"
            )
            output_file.write(row + "\n")

            # Update the on-screen progress bar as we go.
            progress_bar.progress((index + 1) / len(public_ips), text=f"Checked {ip}")

            if index < len(public_ips) - 1:
                time.sleep(WAIT_BETWEEN_REQUESTS)


# -----------------------------------------------------------------------
# STEP 3: Read the saved file back in, LINE BY LINE, and parse it
# -----------------------------------------------------------------------
def read_results_from_file():
    """Open OUTPUT_FILE_NAME and read it back line by line, turning each
    data row into a dictionary using the same column widths we wrote it
    with. Returns a list of dictionaries — one per IP."""
    rows = []

    if not os.path.exists(OUTPUT_FILE_NAME):
        return rows  # no file yet, nothing to read

    w = COL_WIDTHS

    with open(OUTPUT_FILE_NAME, "r", encoding="utf-8") as f:
        all_lines = f.readlines()

    # Skip the first two lines (the header row and the "----" divider).
    data_lines = all_lines[2:]

    for line in data_lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue  # skip any blank lines

        # Slice the fixed-width columns back apart using the same widths
        # we used when writing the file. .strip() removes the padding
        # spaces we added for alignment.
        pos = 0
        ip = line[pos: pos + w["ip"]].strip(); pos += w["ip"]
        country = line[pos: pos + w["country"]].strip(); pos += w["country"]
        malicious = line[pos: pos + w["malicious"]].strip(); pos += w["malicious"]
        suspicious = line[pos: pos + w["suspicious"]].strip(); pos += w["suspicious"]
        status = line[pos: pos + w["status"]].strip()

        rows.append({
            "ip": ip,
            "country": country,
            "malicious": malicious,
            "suspicious": suspicious,
            "status": status,
        })

    return rows


# -----------------------------------------------------------------------
# STEP 4: The Streamlit page itself
# -----------------------------------------------------------------------
st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")
st.title("🌐 Foreign IP Reputation Dashboard")
st.write("Checks your computer's active network connections against VirusTotal.")

if st.button("Run scan now"):
    public_ips = get_public_ips()

    if not public_ips:
        st.warning("No public ESTABLISHED connections found.")
    else:
        st.write(f"Found {len(public_ips)} public IP(s). Checking each one...")
        progress_bar = st.progress(0, text="Starting...")
        scan_and_save(public_ips, progress_bar)
        st.success("Scan complete! Results saved to " + OUTPUT_FILE_NAME)

st.divider()

# Read whatever is currently saved in the file (from this run or a past one)
# and display it as a table, line by line.
results = read_results_from_file()

if not results:
    st.info("No results yet. Click 'Run scan now' above to check your connections.")
else:
    flagged_count = sum(1 for r in results if r["status"] == "FLAGGED")
    clean_count = sum(1 for r in results if r["status"] == "Clean")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total IPs", len(results))
    col2.metric("Flagged", flagged_count)
    col3.metric("Clean", clean_count)

    st.subheader("Results")

    # Streamlit can display a list of dictionaries directly as a table.
    st.table(results)