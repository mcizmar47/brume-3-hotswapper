#!/usr/bin/env python3
"""
VPN hot-standby swap interruption meter for Windows.

No third-party packages required.
Uses Windows ICMP API (IcmpSendEcho2Ex) through ctypes so it can probe
multiple targets at high frequency without spawning ping.exe processes.

Targets:
  - 192.168.8.1 : Brume LAN
  - 1.1.1.1     : Cloudflare
  - 8.8.8.8     : Google

Run:
    python vpn_swap_measure.py

Then trigger the Brume failover in another terminal:
    /root/vpn-watch.sh test_failover

Stop with Ctrl+C. A CSV is written beside the script.
"""

import ctypes
from ctypes import wintypes
import csv
import os
import socket
import struct
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

INTERVAL_S = 0.010          # 10 ms launch cadence per target
TIMEOUT_MS = 300            # lost probes may finish later; launches never block
PAYLOAD = b"vpn-swap-meter"
TARGETS = {
    "LAN": "192.168.8.1",
    "CF": "1.1.1.1",
    "GOOGLE": "8.8.8.8",
}
# A simultaneous Internet outage is considered present when both Internet
# targets have no successful probes between two common-success boundaries.
INTERNET_NAMES = ("CF", "GOOGLE")


if os.name != "nt":
    raise SystemExit("This script is intended for Windows.")

iphlpapi = ctypes.WinDLL("iphlpapi.dll")
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
IP_REQ_TIMED_OUT = 11010

class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.POINTER(ctypes.c_ubyte)),
    ]

class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.ULONG),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", wintypes.LPVOID),
        ("Options", IP_OPTION_INFORMATION),
    ]

iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL

iphlpapi.IcmpSendEcho2Ex.argtypes = [
    wintypes.HANDLE,       # IcmpHandle
    wintypes.HANDLE,       # Event
    wintypes.LPVOID,       # ApcRoutine
    wintypes.LPVOID,       # ApcContext
    wintypes.ULONG,        # SourceAddress
    wintypes.ULONG,        # DestinationAddress
    wintypes.LPVOID,       # RequestData
    wintypes.WORD,         # RequestSize
    ctypes.POINTER(IP_OPTION_INFORMATION),
    wintypes.LPVOID,       # ReplyBuffer
    wintypes.DWORD,        # ReplySize
    wintypes.DWORD,        # Timeout
]
iphlpapi.IcmpSendEcho2Ex.restype = wintypes.DWORD


def ipv4_to_ulong(ip):
    # Windows IPAddr is the four IPv4 bytes as laid out in memory.
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def wall_stamp(ns):
    dt = datetime.fromtimestamp(ns / 1_000_000_000)
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond:06d}"[:3]


records = []
records_lock = threading.Lock()
stop_event = threading.Event()
start_perf_ns = time.perf_counter_ns()
start_wall_ns = time.time_ns()


def now_pair():
    perf = time.perf_counter_ns()
    wall = start_wall_ns + (perf - start_perf_ns)
    return perf, wall


def one_probe(name, ip, handle, dest):
    request = ctypes.create_string_buffer(PAYLOAD)
    reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(PAYLOAD) + 64
    reply_buf = ctypes.create_string_buffer(reply_size)

    send_perf, send_wall = now_pair()
    count = iphlpapi.IcmpSendEcho2Ex(
        handle, None, None, None, 0, dest,
        ctypes.cast(request, wintypes.LPVOID), len(PAYLOAD),
        None, reply_buf, reply_size, TIMEOUT_MS
    )
    recv_perf, recv_wall = now_pair()

    ok = False
    rtt_ms = None
    status = None

    if count:
        reply = ctypes.cast(reply_buf, ctypes.POINTER(ICMP_ECHO_REPLY)).contents
        status = int(reply.Status)
        ok = status == 0
        if ok:
            rtt_ms = int(reply.RoundTripTime)
    else:
        err = ctypes.get_last_error()
        status = int(err) if err else IP_REQ_TIMED_OUT

    with records_lock:
        records.append({
            "target": name,
            "ip": ip,
            "send_perf_ns": send_perf,
            "recv_perf_ns": recv_perf,
            "send_wall_ns": send_wall,
            "recv_wall_ns": recv_wall,
            "ok": ok,
            "rtt_ms": rtt_ms,
            "status": status,
        })


def probe_worker(name, ip):
    handle = iphlpapi.IcmpCreateFile()
    if handle == INVALID_HANDLE_VALUE:
        print(f"\nERROR: could not create ICMP handle for {name}.")
        stop_event.set()
        return

    dest = ipv4_to_ulong(ip)
    next_launch = time.perf_counter()
    inflight = []

    try:
        while not stop_event.is_set():
            now = time.perf_counter()

            # Reap completed per-probe threads.
            inflight = [t for t in inflight if t.is_alive()]

            if now < next_launch:
                stop_event.wait(min(next_launch - now, 0.002))
                continue

            # Each ICMP call runs independently. A lost packet can spend the
            # full timeout waiting without preventing the next 10-ms launch.
            t = threading.Thread(
                target=one_probe,
                args=(name, ip, handle, dest),
                daemon=True,
            )
            t.start()
            inflight.append(t)

            next_launch += INTERVAL_S
            if next_launch < now - INTERVAL_S:
                next_launch = now + INTERVAL_S
    finally:
        # Give already-launched probes a chance to finish so outage edges are
        # retained in the CSV after Ctrl+C.
        deadline = time.perf_counter() + (TIMEOUT_MS / 1000) + 0.2
        for t in inflight:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            t.join(remaining)
        iphlpapi.IcmpCloseHandle(handle)

def save_csv(snapshot):
    out_dir = Path(__file__).resolve().parent
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"vpn_swap_measure_{stamp}.csv"

    ordered = sorted(snapshot, key=lambda r: r["send_perf_ns"])
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "target", "ip", "sent_at", "reply_at", "success",
            "rtt_ms", "status", "elapsed_ms"
        ])
        base = min((r["send_perf_ns"] for r in ordered), default=start_perf_ns)
        for r in ordered:
            w.writerow([
                r["target"],
                r["ip"],
                wall_stamp(r["send_wall_ns"]),
                wall_stamp(r["recv_wall_ns"]),
                1 if r["ok"] else 0,
                "" if r["rtt_ms"] is None else r["rtt_ms"],
                r["status"],
                f"{(r['send_perf_ns'] - base) / 1_000_000:.3f}",
            ])
    return path


def intervals_from_successes(rows):
    """Return gaps between consecutive successful probes."""
    successes = sorted(
        (r for r in rows if r["ok"]),
        key=lambda r: r["send_perf_ns"]
    )
    gaps = []
    for a, b in zip(successes, successes[1:]):
        gap_ms = (b["send_perf_ns"] - a["send_perf_ns"]) / 1_000_000
        # Normal successful cadence is ~50 ms. Require >2.5 intervals to
        # avoid calling ordinary scheduling jitter an interruption.
        if gap_ms > INTERVAL_S * 1000 * 2.5:
            gaps.append((a, b, gap_ms))
    return gaps


def analyze(snapshot):
    by_name = defaultdict(list)
    for r in snapshot:
        by_name[r["target"]].append(r)

    print("\n\n=== RESULTS ===")
    duration = (
        (max(r["recv_perf_ns"] for r in snapshot) -
         min(r["send_perf_ns"] for r in snapshot)) / 1e9
        if snapshot else 0
    )
    print(f"measurement duration: {duration:.2f} s")
    print(f"probe interval:        {INTERVAL_S * 1000:.0f} ms")
    print()

    for name in TARGETS:
        rows = by_name[name]
        sent = len(rows)
        ok = sum(r["ok"] for r in rows)
        lost = sent - ok
        loss = (lost / sent * 100) if sent else 0
        print(f"{name:7}  sent={sent:5}  ok={ok:5}  "
              f"lost={lost:4}  loss={loss:6.2f}%")

    # Determine Internet-wide gaps conservatively from the union of successful
    # external probes. Since CF and Google are staggered independently, a gap
    # in this union means neither target produced a success during that span.
    external = []
    for name in INTERNET_NAMES:
        external.extend(by_name[name])
    internet_gaps = intervals_from_successes(external)

    # With two independent 100-Hz streams, ordinary success spacing is only a
    # few ms. Treat >=30 ms without either external target succeeding as a
    # meaningful interruption candidate.
    internet_gaps = [g for g in internet_gaps if g[2] >= 30.0]

    print()
    if not internet_gaps:
        print("no Internet-wide interruption >= 30 ms was detected.")
        print("if the swap happened during this run, interruption was below "
              "the meter's reliable detection threshold.")
        return

    print(f"detected Internet-wide interruption(s): {len(internet_gaps)}")
    for i, (before, after, gap_ms) in enumerate(internet_gaps, 1):
        # The actual outage starts sometime after the last successful probe
        # and ends no later than the first successful probe after it.
        print(f"\n#{i}")
        print(f"  last external success:  "
              f"{wall_stamp(before['send_wall_ns'])} "
              f"({before['target']}, {before['rtt_ms']} ms)")
        print(f"  first external success: "
              f"{wall_stamp(after['send_wall_ns'])} "
              f"({after['target']}, {after['rtt_ms']} ms)")
        print(f"  observed success gap:   {gap_ms:.1f} ms")

        lo = before["send_perf_ns"]
        hi = after["send_perf_ns"]
        lan_window = [
            r for r in by_name["LAN"]
            if lo <= r["send_perf_ns"] <= hi
        ]
        lan_fail = sum(not r["ok"] for r in lan_window)
        if lan_window and lan_fail == 0:
            print("  LAN during gap:          continuous")
        elif lan_window:
            print(f"  LAN during gap:          {lan_fail}/"
                  f"{len(lan_window)} probes failed")
        else:
            print("  LAN during gap:          no probe samples")

        # Quantization note: last-success -> first-success overstates exact
        # outage by at most roughly one probe interval on each boundary.
        lower = max(0.0, gap_ms - 2 * INTERVAL_S * 1000)
        print(f"  likely outage range:     ~{lower:.0f}–{gap_ms:.0f} ms")
        print("  (range reflects 10 ms sampling uncertainty at each edge)")


def main():
    print("VPN hot-standby swap interruption meter")
    print("----------------------------------------")
    print(f"sampling each target every {INTERVAL_S * 1000:.0f} ms:")
    for name, ip in TARGETS.items():
        print(f"  {name:7} {ip}")
    print()
    print("start this, wait a few seconds, trigger the VPN failover,")
    print("wait another 5-10 seconds, then press Ctrl+C here.")
    print()

    threads = [
        threading.Thread(target=probe_worker, args=(name, ip),
                         daemon=True, name=f"probe-{name}")
        for name, ip in TARGETS.items()
    ]
    for t in threads:
        t.start()

    print("measuring...", end="", flush=True)
    try:
        while not stop_event.wait(1):
            with records_lock:
                n = len(records)
            print(f"\rmeasuring... {n} probes", end="", flush=True)
    except KeyboardInterrupt:
        print("\nstop requested.")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=(TIMEOUT_MS / 1000) + 1)

    with records_lock:
        snapshot = list(records)

    if not snapshot:
        print("no measurements were collected.")
        return 1

    path = save_csv(snapshot)
    analyze(snapshot)
    print(f"\nraw measurements saved to:\n{path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
