#!/usr/bin/env python3
"""
Wireless Packet Loss & Latency Test System — Sender.

Generates traffic via proxy threads (UDP / TCP) according to the active
mode in config_wireless.ini.  TCP streams use RTSP Interleaved framing.

Usage:
    python wireless_send_test.py [--config CONFIG_PATH]
"""

import argparse
import configparser
import logging
import os
import re
import signal
import socket
import struct
import sys
import threading
import time

FRAME_HDR_FMT = "!BBH"          # magic(1) + channel(1) + length(2) = 4 bytes
PAYLOAD_HDR_FMT = "!qq"         # send_ts_us(8) + seq_id(8) = 16 bytes
FRAME_HDR_SIZE = 4
PAYLOAD_HDR_SIZE = 16

shutdown_event = threading.Event()


def load_config(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(current_dir, path)
    if not cfg.read(path):
        print(f"ERROR: cannot read config file '{path}'", file=sys.stderr)
        sys.exit(1)

    mode_keys = ["udp_1", "udp_1_2", "udp_1_2_tcp_1"]
    enabled = [k for k in mode_keys if cfg.getboolean("mode", k, fallback=False)]
    if len(enabled) != 1:
        print(f"ERROR: exactly one mode must be true, got: {enabled}", file=sys.stderr)
        sys.exit(1)
    return cfg


def get_active_mode(cfg: configparser.ConfigParser) -> str:
    mode_keys = ["udp_1", "udp_1_2", "udp_1_2_tcp_1"]
    return next(k for k in mode_keys if cfg.getboolean("mode", k, fallback=False))


# ── logging ────────────────────────────────────────────────────────────────────

def _logs_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


def _setup_port_logger(label: str, port: int) -> logging.Logger:
    logs_dir = _logs_dir()
    os.makedirs(logs_dir, exist_ok=True)
    logger = logging.getLogger(label)
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)7s] [%(name)s]: %(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    log_path = os.path.join(logs_dir, f"proxy_{label}_{port}.log")
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def _next_seq(mode: str, logs_root: str = None) -> int:
    pattern = re.compile(rf"^SEND_{mode}_seq(\d+)\.log$")
    logs_dir = logs_root if logs_root is not None else _logs_dir()
    try:
        entries = os.listdir(logs_dir)
    except FileNotFoundError:
        return 1
    seqs = []
    for entry in entries:
        m = pattern.match(entry)
        if m:
            seqs.append(int(m.group(1)))
    return max(seqs) + 1 if seqs else 1


def _write_send_log(mode: str, cfg: configparser.ConfigParser) -> None:
    seq = _next_seq(mode)
    logs_dir = _logs_dir()
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, f"SEND_{mode}_seq{seq}.log")

    src_addr = _src_addr(cfg)
    dest_addr = _dest_addr(cfg)
    mtu = _mtu(cfg)
    mtu_tcp_val = _mtu_tcp(cfg)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    def _format_udp(label: str, bw_key: str, src_key: str, dst_key: str) -> str:
        bw = _bw(cfg, bw_key)
        src = _src_port(cfg, src_key)
        dst = _dst_port(cfg, dst_key)
        bpp = mtu
        pps = (bw * 1000) / (bpp * 8)
        interval_ms = 1000 / pps
        return (
            f"{timestamp} [    INFO] [proxy.{label}_{src}_{dst}]: "
            f"UDP sender started → {dest_addr}:{dst}  bw={bw:.1f} kbps  pkt={bpp}B  "
            f"packet_per_second={pps:.1f}  interval={interval_ms:.2f} ms\n"
        )

    def _format_tcp(label: str, bw_key: str, src_key: str, dst_key: str) -> str:
        bw = _bw(cfg, bw_key)
        src = _src_port(cfg, src_key)
        dst = _dst_port(cfg, dst_key)
        bpf = FRAME_HDR_SIZE + mtu_tcp_val
        pps = (bw * 1000) / (bpf * 8)
        interval_ms = 1000 / pps
        return (
            f"{timestamp} [    INFO] [proxy.{label}_{src}_{dst}]: "
            f"TCP sender started → {dest_addr}:{dst}  bw={bw:.1f} kbps  frame={bpf}B  "
            f"packet_per_second={pps:.1f}  interval={interval_ms:.2f} ms\n"
        )

    with open(log_path, 'w') as f:
        if mode == "udp_1":
            f.write(_format_udp("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_from", "udp_1_0_addr_to"))
        elif mode == "udp_1_2":
            f.write(_format_udp("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_from", "udp_1_0_addr_to"))
            f.write(_format_udp("udp_rec0", "bandwidth_udp_2_0", "udp_2_0_addr_from", "udp_2_0_addr_to"))
            f.write(_format_udp("udp_rec1", "bandwidth_udp_2_1", "udp_2_1_addr_from", "udp_2_1_addr_to"))
        elif mode == "udp_1_2_tcp_1":
            f.write(_format_udp("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_from", "udp_1_0_addr_to"))
            f.write(_format_udp("udp_rec0", "bandwidth_udp_2_0", "udp_2_0_addr_from", "udp_2_0_addr_to"))
            f.write(_format_udp("udp_rec1", "bandwidth_udp_2_1", "udp_2_1_addr_from", "udp_2_1_addr_to"))
            f.write(_format_tcp("tcp_main", "bandwidth_tcp_1_0", "tcp_1_0_addr_from", "tcp_1_0_addr_to"))


# ── sender threads ─────────────────────────────────────────────────────────────

def udp_send_thread(label: str, src_addr: str, dest_addr: str, dest_port: int,
                    bandwidth_kbps: float, mtu: int, src_port: int,
                    shutdown_event: threading.Event) -> None:
    logger = _setup_port_logger(label, src_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((src_addr, src_port))
    except OSError:
        pass

    bytes_per_packet = mtu
    packet_per_second = (bandwidth_kbps * 1000) / (bytes_per_packet * 8)
    interval_s = 1.0 / packet_per_second

    logger.info(
        "UDP sender started → %s:%d  bw=%.1f kbps  pkt=%dB  "
        "packet_per_second=%.1f  interval=%.2f ms",
        dest_addr, dest_port, bandwidth_kbps, bytes_per_packet,
        packet_per_second, interval_s * 1000,
    )

    seq_id = 1
    while not shutdown_event.is_set():
        send_ts_us = time.time_ns() // 1_000
        payload = struct.pack(PAYLOAD_HDR_FMT, send_ts_us, seq_id)
        payload = payload.ljust(mtu, b'\x00')
        try:
            sock.sendto(payload, (dest_addr, dest_port))
        except OSError:
            pass
        seq_id += 1
        time.sleep(interval_s)

    sock.close()
    logger.info("UDP sender stopped (seq_id=%d)", seq_id)


def tcp_send_thread(label: str, dest_addr: str, dest_port: int,
                    bandwidth_kbps: float, mtu_tcp: int, src_port: int,
                    shutdown_event: threading.Event) -> None:
    logger = _setup_port_logger(label, src_port)

    payload_size = mtu_tcp
    bytes_per_frame = FRAME_HDR_SIZE + payload_size
    packet_per_second = (bandwidth_kbps * 1000) / (bytes_per_frame * 8)
    interval_s = 1.0 / packet_per_second

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)

    connected = False
    while not shutdown_event.is_set() and not connected:
        try:
            sock.connect((dest_addr, dest_port))
            connected = True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)

    if not connected:
        sock.close()
        return

    logger.info(
        "TCP sender started → %s:%d  bw=%.1f kbps  frame=%dB  "
        "packet_per_second=%.1f  interval=%.2f ms",
        dest_addr, dest_port, bandwidth_kbps, bytes_per_frame,
        packet_per_second, interval_s * 1000,
    )

    seq_id = 1
    while not shutdown_event.is_set():
        send_ts_us = time.time_ns() // 1_000
        payload = struct.pack(PAYLOAD_HDR_FMT, send_ts_us, seq_id)
        payload = payload.ljust(payload_size, b'\x00')
        frame = struct.pack(FRAME_HDR_FMT, 0x24, 0x00, payload_size) + payload
        try:
            sock.sendall(frame)
        except (BrokenPipeError, OSError):
            break
        seq_id += 1
        time.sleep(interval_s)

    sock.close()
    logger.info("TCP sender stopped (seq_id=%d)", seq_id)


# ── config helpers ─────────────────────────────────────────────────────────────

def _src_addr(cfg: configparser.ConfigParser) -> str:
    return cfg.get("addr", "addr_send", fallback=None) or cfg.get("addr", "addr", fallback="127.0.0.1")


def _dest_addr(cfg: configparser.ConfigParser) -> str:
    return cfg.get("addr", "addr_recv", fallback=None) or cfg.get("addr", "addr", fallback="127.0.0.1")


def _bw(cfg: configparser.ConfigParser, key: str) -> float:
    return cfg.getfloat("config", key, fallback=0.0)


def _mtu(cfg: configparser.ConfigParser) -> int:
    return cfg.getint("config", "mtu", fallback=1400)


def _mtu_tcp(cfg: configparser.ConfigParser) -> int:
    return cfg.getint("config", "mtu_tcp", fallback=100)


def _src_port(cfg: configparser.ConfigParser, key: str) -> int:
    return cfg.getint("address_from", key, fallback=0)


def _dst_port(cfg: configparser.ConfigParser, key: str) -> int:
    return cfg.getint("address_to", key, fallback=0)


# ── proxy dispatchers ──────────────────────────────────────────────────────────

def udp_1_proxy(cfg: configparser.ConfigParser) -> tuple:
    src_addr = _src_addr(cfg)
    dest_addr = _dest_addr(cfg)
    src = _src_port(cfg, "udp_1_0_addr_from")
    dst = _dst_port(cfg, "udp_1_0_addr_to")
    bw = _bw(cfg, "bandwidth_udp_1_0")
    mtu = _mtu(cfg)

    t = threading.Thread(
        target=udp_send_thread,
        args=("udp_main", src_addr, dest_addr, dst, bw, mtu, src, shutdown_event),
        daemon=True,
    )
    t.start()
    return [t], [("udp_main", src, dst, bw, mtu, "UDP")]


def udp_1_2_proxy(cfg: configparser.ConfigParser) -> tuple:
    src_addr = _src_addr(cfg)
    dest_addr = _dest_addr(cfg)
    mtu = _mtu(cfg)
    threads = []
    stream_infos = []

    streams = [
        ("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_from", "udp_1_0_addr_to"),
        ("udp_rec0", "bandwidth_udp_2_0", "udp_2_0_addr_from", "udp_2_0_addr_to"),
        ("udp_rec1", "bandwidth_udp_2_1", "udp_2_1_addr_from", "udp_2_1_addr_to"),
    ]
    for label, bw_key, src_key, dst_key in streams:
        bw = _bw(cfg, bw_key)
        src = _src_port(cfg, src_key)
        dst = _dst_port(cfg, dst_key)
        t = threading.Thread(
            target=udp_send_thread,
            args=(label, src_addr, dest_addr, dst, bw, mtu, src, shutdown_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
        stream_infos.append((label, src, dst, bw, mtu, "UDP"))
    return threads, stream_infos


def udp_1_2_tcp_1_proxy(cfg: configparser.ConfigParser) -> tuple:
    src_addr = _src_addr(cfg)
    dest_addr = _dest_addr(cfg)
    mtu = _mtu(cfg)
    mtu_tcp_val = _mtu_tcp(cfg)
    threads = []
    stream_infos = []

    udp_streams = [
        ("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_from", "udp_1_0_addr_to"),
        ("udp_rec0", "bandwidth_udp_2_0", "udp_2_0_addr_from", "udp_2_0_addr_to"),
        ("udp_rec1", "bandwidth_udp_2_1", "udp_2_1_addr_from", "udp_2_1_addr_to"),
    ]
    for label, bw_key, src_key, dst_key in udp_streams:
        bw = _bw(cfg, bw_key)
        src = _src_port(cfg, src_key)
        dst = _dst_port(cfg, dst_key)
        t = threading.Thread(
            target=udp_send_thread,
            args=(label, src_addr, dest_addr, dst, bw, mtu, src, shutdown_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
        stream_infos.append((label, src, dst, bw, mtu, "UDP"))

    bw_tcp = _bw(cfg, "bandwidth_tcp_1_0")
    src_tcp = _src_port(cfg, "tcp_1_0_addr_from")
    dst_tcp = _dst_port(cfg, "tcp_1_0_addr_to")
    t_tcp = threading.Thread(
        target=tcp_send_thread,
        args=("tcp_main", dest_addr, dst_tcp, bw_tcp, mtu_tcp_val, src_tcp, shutdown_event),
        daemon=True,
    )
    t_tcp.start()
    threads.append(t_tcp)
    stream_infos.append(("tcp_main", src_tcp, dst_tcp, bw_tcp, mtu_tcp_val, "TCP"))

    return threads, stream_infos


def select_proxies(cfg: configparser.ConfigParser) -> tuple:
    mode = get_active_mode(cfg)
    if mode == "udp_1":
        return udp_1_proxy(cfg)
    elif mode == "udp_1_2":
        return udp_1_2_proxy(cfg)
    elif mode == "udp_1_2_tcp_1":
        return udp_1_2_tcp_1_proxy(cfg)
    else:
        print(f"ERROR: unknown mode '{mode}'", file=sys.stderr)
        sys.exit(1)


# ── signal handling ────────────────────────────────────────────────────────────

def _signal_handler(signum, frame):
    print("\n[INFO] Received signal, shutting down...")
    shutdown_event.set()


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    parser = argparse.ArgumentParser(description="Wireless packet loss test — sender.")
    parser.add_argument(
        "--config", default="config_wireless.ini",
        help="Path to config file (default: config_wireless.ini)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    mode = get_active_mode(cfg)

    print(f"[INFO] Active mode: {mode}")
    print("[INFO] Starting proxy threads...")

    threads, stream_infos = select_proxies(cfg)

    _write_send_log(mode, cfg)

    print(f"[INFO] {len(threads)} proxy thread(s) running. Press Ctrl+C to stop.")

    try:
        while not shutdown_event.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        shutdown_event.set()

    print("[INFO] Waiting for threads to finish...")
    for t in threads:
        t.join(timeout=3.0)

    print("[INFO] Sender shutdown complete.")


if __name__ == "__main__":
    main()
