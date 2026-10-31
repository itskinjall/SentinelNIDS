"""Link alerts to rolling PCAP files (scripts/capture_pcap.sh) and extract packets with tshark/tcpdump.
All commands are run as argument lists (no shell) and every value is validated first."""
import ipaddress
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

import config

NAME = re.compile(r"^sentinel-(\d{8})-(\d{6})\.pcap$")
SPAN = 60  # seconds per file (tcpdump -G 60)


def _files():
    out = []
    d = Path(config.PCAP_DIR)
    if d.is_dir():
        for p in d.iterdir():
            m = NAME.match(p.name)
            if m:   # tcpdump strftime uses LOCAL time
                start = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
                out.append((start, p))
    return sorted(out)


def find(ts, pad=5):
    """PCAP files that overlap [ts-pad, ts+pad]."""
    return [p for start, p in _files() if start <= ts + pad and start + SPAN + 2 >= ts - pad]


def _ip(v):
    return str(ipaddress.ip_address(v))


def tools():
    return {"tshark": bool(shutil.which("tshark")), "tcpdump": bool(shutil.which("tcpdump"))}


def meta(alert):
    files = find(alert["ts"])
    return {"available": bool(files), "files": [f.name for f in files], "tools": tools(),
            "hint": None if files else "No PCAP covers this alert. Run scripts/capture_pcap.sh before generating traffic."}


def packets(alert, limit=100):
    files = find(alert["ts"])
    if not files:
        return {"available": False, "packets": []}
    a, b = _ip(alert["src_ip"]), _ip(alert["dest_ip"])
    rows = []
    if shutil.which("tshark"):
        for f in files:
            cmd = ["tshark", "-r", str(f), "-Y",
                   f"ip.addr=={a} && ip.addr=={b} && frame.time_epoch>={alert['ts'] - 30:.3f} && frame.time_epoch<={alert['ts'] + 30:.3f}",
                   "-c", str(limit), "-T", "fields", "-E", "separator=|",
                   "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
                   "-e", "frame.len", "-e", "_ws.col.Info"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            for line in r.stdout.splitlines():
                p = line.split("|", 5)
                if len(p) == 6:
                    rows.append(dict(zip(("t", "src", "dst", "proto", "len", "info"), p)))
        return {"available": True, "tool": "tshark", "packets": rows[:limit]}
    if shutil.which("tcpdump"):
        for f in files:
            r = subprocess.run(["tcpdump", "-nn", "-r", str(f), "-c", str(limit), "host", a, "and", "host", b],
                               capture_output=True, text=True, timeout=20)
            rows += [{"info": l} for l in r.stdout.splitlines()]
        return {"available": True, "tool": "tcpdump", "packets": rows[:limit]}
    return {"available": True, "tool": None, "packets": [], "note": "Install tshark or tcpdump to preview packets."}


def filtered_pcap(alert):
    """Bytes of a pcap limited to the alert's two hosts (smaller, shareable evidence)."""
    files = find(alert["ts"])
    if not files or not shutil.which("tcpdump"):
        return None
    a, b = _ip(alert["src_ip"]), _ip(alert["dest_ip"])
    out = b""
    for i, f in enumerate(files[:1]):    # one file keeps the output a valid single pcap
        r = subprocess.run(["tcpdump", "-r", str(f), "-w", "-", "host", a, "and", "host", b],
                           capture_output=True, timeout=30)
        out += r.stdout
    return out
