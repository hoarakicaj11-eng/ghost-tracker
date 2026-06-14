#!/usr/bin/env python3
"""
Ghost Tracker - IP Intelligence CLI
Purpose: Legitimate network reconnaissance and red team portfolio tool
Usage:   python3 ghost_tracker.py 8.8.8.8
         python3 ghost_tracker.py --me
         python3 ghost_tracker.py --batch targets.txt --save
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import os
from datetime import datetime

R  = "\033[0m"
B  = "\033[1m"
DIM= "\033[2m"
GRN= "\033[92m"
RED= "\033[91m"
YLW= "\033[93m"
CYN= "\033[96m"
WHT= "\033[97m"

def banner():
    print(f"""
{CYN}{B}
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
 ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
 ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
    ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
    ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{R}
{DIM}  IP Intelligence Platform  |  Red Team Portfolio Tool  |  v1.0{R}
""")

def status(msg, level="info"):
    icons = {"info": f"{CYN}[*]{R}", "ok": f"{GRN}[+]{R}",
             "warn": f"{YLW}[!]{R}", "err": f"{RED}[-]{R}"}
    print(f"  {icons.get(level, '[?]')} {msg}")

def loading(ip):
    print(f"\n  {CYN}[*]{R} Querying intelligence database for {B}{ip}{R}...", end="", flush=True)
    time.sleep(0.3)
    print(f" {GRN}done{R}\n")

def sep(char="─", width=58):
    print(f"  {DIM}{char * width}{R}")

def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)

def risk_score(d):
    score = 0
    org = (d.get("org") or d.get("isp") or "").lower()
    if any(x in org for x in ["vpn", "proxy", "tor"]):
        score += 40
    if any(x in org for x in ["hosting", "aws", "digitalocean", "linode", "vultr", "hetzner", "ovh"]):
        score += 25
    if not d.get("reverse"):
        score += 10
    if d.get("proxy"):
        score += 30
    if d.get("hosting"):
        score += 20
    return min(score, 100)

def risk_label(score):
    if score >= 70:
        return f"{RED}{B}HIGH  {R}"
    if score >= 35:
        return f"{YLW}{B}MEDIUM{R}"
    return f"{GRN}{B}LOW   {R}"

def detect_flags(d):
    org = (d.get("org") or d.get("isp") or "").lower()
    result = []
    if d.get("proxy"):
        result.append(f"{YLW}Proxy / VPN detected{R}")
    if d.get("hosting"):
        result.append(f"{RED}Datacenter / hosting IP{R}")
    if "tor" in org:
        result.append(f"{RED}Tor exit node{R}")
    if any(x in org for x in ["mobile", "cellular", "4g", "5g"]):
        result.append(f"{CYN}Mobile network{R}")
    if not result:
        result.append(f"{GRN}No threats detected{R}")
    return result

def lookup(ip):
    fields = ("status,message,query,country,countryCode,regionName,"
              "city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting")
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GhostTracker/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        status(f"HTTP error {e.code} from API", "err")
        return None
    except urllib.error.URLError:
        status("Cannot reach API — check your internet connection", "err")
        return None
    if data.get("status") == "fail":
        status(f"API error: {data.get('message', 'unknown')}", "err")
        return None
    return data

def get_my_ip():
    try:
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "GhostTracker/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())["ip"]
    except Exception:
        return None

def display(d, verbose=False):
    ip  = d.get("query", "—")
    rs  = risk_score(d)
    lat = d.get("lat", "—")
    lon = d.get("lon", "—")

    sep("═")
    print(f"  {B}{WHT}TARGET{R}  {CYN}{B}{ip}{R}")
    sep("═")

    rows = [
        ("Hostname",     d.get("reverse") or "None resolved"),
        ("Location",     f"{flag_emoji(d.get('countryCode',''))} {d.get('city','—')}, {d.get('regionName','—')}, {d.get('country','—')}"),
        ("Coordinates",  f"{lat}, {lon}  →  maps.google.com/@{lat},{lon},12z"),
        ("Postal",       d.get("zip", "—")),
        ("Timezone",     d.get("timezone", "—")),
        ("ASN",          d.get("as", "—")),
        ("Organisation", d.get("org") or d.get("isp") or "—"),
        ("Mobile",       "Yes" if d.get("mobile") else "No"),
        ("Proxy/VPN",    "Yes" if d.get("proxy") else "No"),
        ("Hosting IP",   "Yes" if d.get("hosting") else "No"),
    ]

    if verbose:
        rows += [
            ("ISP",     d.get("isp", "—")),
            ("AS name", d.get("asname", "—")),
        ]

    for label, val in rows:
        print(f"  {DIM}{label:<14}{R} {val}")

    sep()
    print(f"  {DIM}{'Risk score':<14}{R} {risk_label(rs)} {rs}/100")
    sep()
    print(f"  {DIM}Flags{R}")
    for f in detect_flags(d):
        print(f"    {DIM}•{R} {f}")
    sep("═")
    print()

def save_report(d, out="reports"):
    os.makedirs(out, exist_ok=True)
    ip   = d.get("query", "unknown")
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"ghost_{ip}_{ts}.json")
    with open(path, "w") as fh:
        json.dump({
            "generated":  datetime.now().isoformat(),
            "tool":       "Ghost Tracker v1.0",
            "risk_score": risk_score(d),
            "raw":        d,
        }, fh, indent=2)
    status(f"Report saved → {path}", "ok")

def batch(path, verbose=False, do_save=False):
    try:
        with open(path) as fh:
            ips = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        status(f"File not found: {path}", "err")
        sys.exit(1)
    status(f"Batch mode — {len(ips)} targets", "info")
    sep()
    for ip in ips:
        print(f"\n  {DIM}→{R} Processing {B}{ip}{R}")
        d = lookup(ip)
        if d:
            display(d, verbose)
            if do_save:
                save_report(d)
        time.sleep(1.5)

def main():
    banner()
    p = argparse.ArgumentParser(prog="ghost_tracker",
        description="Ghost Tracker — IP intelligence for red team portfolios")
    p.add_argument("ip",        nargs="?",           help="Target IP address")
    p.add_argument("--me",      action="store_true", help="Look up your own public IP")
    p.add_argument("--batch",   metavar="FILE",      help="Text file with one IP per line")
    p.add_argument("--verbose", action="store_true", help="Show extended data")
    p.add_argument("--save",    action="store_true", help="Save JSON report to ./reports/")
    p.add_argument("--json",    action="store_true", help="Raw JSON output")
    a = p.parse_args()

    if a.batch:
        batch(a.batch, a.verbose, a.save)
        return

    if a.me:
        status("Detecting your public IP...", "info")
        my_ip = get_my_ip()
        if not my_ip:
            status("Could not detect IP", "err")
            sys.exit(1)
        status(f"Your IP: {B}{my_ip}{R}", "ok")
        a.ip = my_ip

    if not a.ip:
        p.print_help()
        sys.exit(0)

    loading(a.ip)
    d = lookup(a.ip)
    if not d:
        sys.exit(1)

    if a.json:
        print(json.dumps(d, indent=2))
    else:
        display(d, a.verbose)

    if a.save:
        save_report(d)

if __name__ == "__main__":
    main()
