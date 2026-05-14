#!/usr/bin/env python3
"""
Generate one-second time-series plots from IEC 61850 attack traces.

Expected input files by default:
  Built_in_DoS_attack.pcap
  Script_based_DoS_attack.pcap
  Built_in_FDI_attack.pcapng

Usage:
  python generate_pcap_timeseries.py --data-dir . --out-dir ./figures --zip

Dependencies:
  pip install numpy pandas matplotlib

The script detects PCAP/PCAPNG from file magic, so it also handles captures
whose extension is .pcap but whose content is PCAPNG.
"""

from __future__ import annotations

from pathlib import Path
import argparse
import math
import struct
import zipfile

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

ATTACKER_MAC = "00:06:5b:00:00:66"
IEC104_PORT = 2404


def detect_format(path: Path) -> str:
    magic = path.read_bytes()[:4]
    if magic in (
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    ):
        return "pcap"
    if magic == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    raise ValueError(f"{path.name}: unsupported capture magic {magic!r}")


def read_legacy_pcap(path: Path) -> list[tuple[float, bytes]]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"{path.name}: file too short for pcap")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_scale = "<", 1e-6
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_scale = ">", 1e-6
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_scale = "<", 1e-9
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_scale = ">", 1e-9
    else:
        raise ValueError(f"{path.name}: unrecognized pcap magic {magic!r}")

    off = 24
    packets = []
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len
        if len(pkt) == incl_len:
            packets.append((ts_sec + ts_frac * ts_scale, pkt))

    if not packets:
        raise ValueError(f"{path.name}: no packets found")
    t0 = packets[0][0]
    return [(t - t0, pkt) for t, pkt in packets]


def read_pcapng(path: Path) -> list[tuple[float, bytes]]:
    data = path.read_bytes()
    off = 0
    endian = "<"
    ts_resolutions: dict[int, float] = {}
    packets = []

    while off + 12 <= len(data):
        raw_block_type = data[off:off + 4]

        if raw_block_type == b"\x0a\x0d\x0d\x0a":
            body_start = off + 8
            magic = data[body_start:body_start + 4]
            if magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError(f"{path.name}: unknown pcapng byte-order magic {magic!r}")
            block_type, block_len = struct.unpack_from(endian + "II", data, off)
        else:
            block_type, block_len = struct.unpack_from(endian + "II", data, off)

        if block_len < 12 or off + block_len > len(data):
            break

        body_start = off + 8
        body_end = off + block_len - 4

        if block_type == 1:  # Interface Description Block
            interface_index = len(ts_resolutions)
            ts_resolution = 1e-6
            opt_off = body_start + 8
            while opt_off + 4 <= body_end:
                code, opt_len = struct.unpack_from(endian + "HH", data, opt_off)
                opt_off += 4
                val = data[opt_off:opt_off + opt_len]
                opt_off += ((opt_len + 3) // 4) * 4
                if code == 0:
                    break
                if code == 9 and opt_len >= 1:  # if_tsresol
                    b = val[0]
                    ts_resolution = 2 ** (-(b & 0x7F)) if (b & 0x80) else 10 ** (-b)
            ts_resolutions[interface_index] = ts_resolution

        elif block_type == 6:  # Enhanced Packet Block
            iface, ts_high, ts_low, cap_len, _pkt_len = struct.unpack_from(
                endian + "IIIII", data, body_start
            )
            pkt_start = body_start + 20
            pkt = data[pkt_start:pkt_start + cap_len]
            timestamp = ((ts_high << 32) | ts_low) * ts_resolutions.get(iface, 1e-6)
            packets.append((timestamp, pkt))

        off += block_len

    if not packets:
        raise ValueError(f"{path.name}: no packets found")
    t0 = packets[0][0]
    return [(t - t0, pkt) for t, pkt in packets]


def read_capture(path: Path) -> list[tuple[float, bytes]]:
    fmt = detect_format(path)
    return read_legacy_pcap(path) if fmt == "pcap" else read_pcapng(path)


def mac_addr(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def parse_packet(t: float, pkt: bytes) -> dict:
    row = {
        "time": t,
        "length": len(pkt),
        "eth_src": None,
        "eth_dst": None,
        "eth_type": None,
        "is_ipv4": False,
        "is_arp": False,
        "is_goose": False,
        "ip_src": None,
        "ip_dst": None,
        "ip_proto": None,
        "tcp_srcport": None,
        "tcp_dstport": None,
        "tcp_flags": None,
        "tcp_syn_only": False,
        "tcp_rst": False,
        "tcp_ack": False,
        "tcp_psh_ack": False,
        "to_2404": False,
        "is_fdi_injected": False,
    }

    if len(pkt) < 14:
        return row

    row["eth_dst"] = mac_addr(pkt[0:6])
    row["eth_src"] = mac_addr(pkt[6:12])
    eth_type = int.from_bytes(pkt[12:14], "big")
    row["eth_type"] = eth_type
    row["is_arp"] = eth_type == 0x0806
    row["is_goose"] = eth_type == 0x88B8
    row["is_fdi_injected"] = row["eth_src"] == ATTACKER_MAC

    if eth_type == 0x0800 and len(pkt) >= 34:
        row["is_ipv4"] = True
        ip_offset = 14
        ihl = (pkt[ip_offset] & 0x0F) * 4
        if len(pkt) >= ip_offset + ihl + 20:
            proto = pkt[ip_offset + 9]
            row["ip_proto"] = proto
            row["ip_src"] = ".".join(map(str, pkt[ip_offset + 12:ip_offset + 16]))
            row["ip_dst"] = ".".join(map(str, pkt[ip_offset + 16:ip_offset + 20]))

            if proto == 6:  # TCP
                tcp_offset = ip_offset + ihl
                row["tcp_srcport"] = int.from_bytes(pkt[tcp_offset:tcp_offset + 2], "big")
                row["tcp_dstport"] = int.from_bytes(pkt[tcp_offset + 2:tcp_offset + 4], "big")
                flags = pkt[tcp_offset + 13]
                row["tcp_flags"] = flags
                row["to_2404"] = row["tcp_dstport"] == IEC104_PORT or row["tcp_srcport"] == IEC104_PORT
                row["tcp_syn_only"] = bool(flags & 0x02) and not bool(flags & 0x10)
                row["tcp_rst"] = bool(flags & 0x04)
                row["tcp_ack"] = bool(flags & 0x10)
                row["tcp_psh_ack"] = bool(flags & 0x08) and bool(flags & 0x10)

    return row


def df_from_capture(path: Path) -> pd.DataFrame:
    rows = [parse_packet(t, pkt) for t, pkt in read_capture(path)]
    df = pd.DataFrame(rows)
    df["second"] = np.floor(df["time"]).astype(int)
    return df


def sec_index(df: pd.DataFrame) -> np.ndarray:
    return np.arange(0, int(math.floor(df["time"].max())) + 1)


def save_pdf_png(fig, out_dir: Path, stem: str) -> None:
    fig.savefig(out_dir / f"{stem}.pdf", bbox_inches="tight")
    fig.savefig(out_dir / f"{stem}.png", dpi=300, bbox_inches="tight")
    plt.close(fig)


def plot_dos_packet_rate(dos_df: pd.DataFrame, out_dir: Path) -> None:
    x = sec_index(dos_df)
    all_frames = dos_df.groupby("second").size().reindex(x, fill_value=0)

    fig = plt.figure(figsize=(7.2, 4.6))
    plt.plot(x, all_frames.values, linewidth=2, label="DoS trace, all frames")
    plt.axhline(6.4, linestyle="--", linewidth=1.5, label="Reported IEC 104 baseline mean: 6.4 pps")
    plt.yscale("log")
    plt.xlabel("Elapsed time in attack trace (s)")
    plt.ylabel("Packets per second (log scale)")
    plt.title("Volumetric DoS: one-second packet-rate bins")
    plt.grid(True, which="both", linewidth=0.4)
    plt.legend(frameon=False)
    save_pdf_png(fig, out_dir, "fig_dos_packet_rate_exact")


def plot_dos_tcp_flags(dos_df: pd.DataFrame, out_dir: Path) -> None:
    x = sec_index(dos_df)
    syn = dos_df[dos_df["tcp_syn_only"]].groupby("second").size().reindex(x, fill_value=0)
    rst = dos_df[dos_df["tcp_rst"]].groupby("second").size().reindex(x, fill_value=0)
    psh = dos_df[dos_df["tcp_psh_ack"]].groupby("second").size().reindex(x, fill_value=0)

    fig = plt.figure(figsize=(7.2, 4.6))
    plt.plot(x, syn.values, linewidth=2, label="SYN-only frames")
    plt.plot(x, rst.values, linewidth=2, label="RST-containing frames")
    plt.plot(x, psh.values, linewidth=2, label="PSH/ACK frames")
    plt.xlabel("Elapsed time in attack trace (s)")
    plt.ylabel("Frames per second")
    plt.title("Volumetric DoS: TCP-flag evidence")
    plt.grid(True, linewidth=0.4)
    plt.legend(frameon=False)
    save_pdf_png(fig, out_dir, "fig_dos_tcp_flags_exact")


def plot_syn_trace_evidence(syn_df: pd.DataFrame, out_dir: Path) -> None:
    x = sec_index(syn_df)
    all_frames = syn_df.groupby("second").size().reindex(x, fill_value=0)
    syn_only = syn_df[(syn_df["tcp_syn_only"]) & (syn_df["tcp_dstport"] == IEC104_PORT)].groupby("second").size().reindex(x, fill_value=0)
    arp = syn_df[syn_df["is_arp"]].groupby("second").size().reindex(x, fill_value=0)
    to_2404 = syn_df[syn_df["to_2404"]].groupby("second").size().reindex(x, fill_value=0)

    fig = plt.figure(figsize=(7.2, 4.6))
    plt.plot(x, all_frames.values, linewidth=2, label="All frames")
    plt.plot(x, syn_only.values, linewidth=2, label="SYN-only to TCP/2404")
    plt.plot(x, arp.values, linewidth=2, label="ARP frames")
    plt.plot(x, to_2404.values, linewidth=2, label="Frames to/from TCP/2404")
    plt.xlabel("Elapsed time in attack trace (s)")
    plt.ylabel("Frames per second")
    plt.title("TCP SYN flood: one-second trace evidence")
    plt.grid(True, linewidth=0.4)
    plt.legend(frameon=False)
    save_pdf_png(fig, out_dir, "fig_syn_trace_evidence_exact")

    fig = plt.figure(figsize=(7.2, 4.6))
    plt.plot(x, syn_only.cumsum().values, linewidth=2, label="Cumulative SYN-only to TCP/2404")
    plt.plot(x, arp.cumsum().values, linewidth=2, label="Cumulative ARP frames")
    plt.plot(x, to_2404.cumsum().values, linewidth=2, label="Cumulative frames to/from TCP/2404")
    plt.xlabel("Elapsed time in attack trace (s)")
    plt.ylabel("Cumulative frames")
    plt.title("TCP SYN flood: cumulative evidence")
    plt.grid(True, linewidth=0.4)
    plt.legend(frameon=False)
    save_pdf_png(fig, out_dir, "fig_syn_cumulative_exact")


def plot_fdi_goose(fdi_df: pd.DataFrame, out_dir: Path) -> None:
    x = sec_index(fdi_df)
    goose_all = fdi_df[fdi_df["is_goose"]].groupby("second").size().reindex(x, fill_value=0)
    goose_injected = fdi_df[fdi_df["is_fdi_injected"]].groupby("second").size().reindex(x, fill_value=0)
    goose_legitimate = goose_all - goose_injected

    fig = plt.figure(figsize=(7.2, 4.6))
    plt.plot(x, goose_legitimate.values, linewidth=2, label="Legitimate GOOSE frames")
    plt.plot(x, goose_injected.values, linewidth=2, label="Injected GOOSE frames")
    plt.xlabel("Elapsed time in attack trace (s)")
    plt.ylabel("GOOSE frames per second")
    plt.title("GOOSE FDI: one-second frame bins")
    plt.grid(True, linewidth=0.4)
    plt.legend(frameon=False)
    save_pdf_png(fig, out_dir, "fig_fdi_goose_frames_exact")

    fig = plt.figure(figsize=(7.2, 4.6))
    plt.plot(x, goose_legitimate.cumsum().values, linewidth=2, label="Cumulative legitimate GOOSE")
    plt.plot(x, goose_injected.cumsum().values, linewidth=2, label="Cumulative injected GOOSE")
    plt.xlabel("Elapsed time in attack trace (s)")
    plt.ylabel("Cumulative GOOSE frames")
    plt.title("GOOSE FDI: cumulative frame evidence")
    plt.grid(True, linewidth=0.4)
    plt.legend(frameon=False)
    save_pdf_png(fig, out_dir, "fig_fdi_cumulative_goose_exact")


def build_summary(dfs: dict[str, pd.DataFrame], paths: dict[str, Path], out_dir: Path) -> pd.DataFrame:
    rows = []
    for name, df in dfs.items():
        rows.append({
            "trace_key": name,
            "file": paths[name].name,
            "format": detect_format(paths[name]),
            "duration_s": float(df["time"].max()),
            "frames": int(len(df)),
            "avg_pps": float(len(df) / df["time"].max()),
            "arp_frames": int(df["is_arp"].sum()),
            "ipv4_frames": int(df["is_ipv4"].sum()),
            "tcp_syn_only": int(df["tcp_syn_only"].sum()),
            "tcp_rst_containing": int(df["tcp_rst"].sum()),
            "tcp_psh_ack": int(df["tcp_psh_ack"].sum()),
            "frames_to_from_2404": int(df["to_2404"].sum()),
            "goose_frames": int(df["is_goose"].sum()),
            "injected_goose_frames": int(df["is_fdi_injected"].sum()),
            "legitimate_goose_frames": int((df["is_goose"] & ~df["is_fdi_injected"]).sum()),
        })

    summary = pd.DataFrame(rows)
    summary.to_csv(out_dir / "all_trace_summary.csv", index=False)
    return summary


def make_zip(out_dir: Path) -> Path:
    zip_path = out_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in out_dir.iterdir():
            if p.is_file():
                z.write(p, arcname=p.name)
    return zip_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate one-second time-series plots from IEC 61850 attack traces.")
    parser.add_argument("--data-dir", default=".", help="Directory containing the capture files.")
    parser.add_argument("--out-dir", default="./all_exact_trace_timeseries", help="Output directory.")
    parser.add_argument("--dos-file", default="Built_in_DoS_attack.pcap")
    parser.add_argument("--syn-file", default="Script_based_DoS_attack.pcap")
    parser.add_argument("--fdi-file", default="Built_in_FDI_attack.pcapng")
    parser.add_argument("--zip", action="store_true", help="Create a zip archive of the output folder.")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "dos": data_dir / args.dos_file,
        "syn": data_dir / args.syn_file,
        "fdi": data_dir / args.fdi_file,
    }

    missing = [str(p) for p in paths.values() if not p.exists()]
    if missing:
        raise FileNotFoundError("Missing capture file(s): " + ", ".join(missing))

    dfs = {name: df_from_capture(path) for name, path in paths.items()}

    plot_dos_packet_rate(dfs["dos"], out_dir)
    plot_dos_tcp_flags(dfs["dos"], out_dir)
    plot_syn_trace_evidence(dfs["syn"], out_dir)
    plot_fdi_goose(dfs["fdi"], out_dir)

    summary = build_summary(dfs, paths, out_dir)

    print("Generated one-second time-series outputs in:", out_dir)
    print(summary.to_string(index=False))

    if args.zip:
        zip_path = make_zip(out_dir)
        print("Created ZIP package:", zip_path)


if __name__ == "__main__":
    main()
