#!/usr/bin/env python3
"""
Wireless Packet Loss & Latency Test System — Receiver.

Listens on configured ports, computes per-stream statistics, and logs
them every second.  TCP streams use RTSP Interleaved frame parsing.

Usage:
    python wireless_recv_test.py [--config CONFIG_PATH]
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
from collections import deque
from dataclasses import dataclass, field
from statistics import mean

FRAME_HDR_FMT = "!3sBH"
PAYLOAD_HDR_FMT = "!qq3s"
FRAME_HDR_SIZE = 6
PAYLOAD_HDR_SIZE = 19
MAGIC = b'\x66\xCC\xFF'

shutdown_event = threading.Event()


@dataclass
class StreamStats:
    received_packets: int = 0
    lost_packets: int = 0
    total_packets: int = 0
    last_seq_id: int = 0
    latency_deque: deque = field(default_factory=deque)
    lock: threading.Lock = field(default_factory=threading.Lock)
    jitter_rfc3550: float = 0.0
    prev_latency_us: float = 0.0
    prev_latency_set: bool = False
    seen_seq_ids: set = field(default_factory=set)
    lost_seq_ids: set = field(default_factory=set)
    seq_window_size: int = 500000
    # --- NEW: instantaneous loss_rate tracking (sample-window based) ---
    instant_loss_rate: float = 0.0
    _sample_total: int = 0
    _sample_loss: int = 0
    _sample_interval: int = 1000
    # --- END NEW ---


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


def _setup_port_logger(label: str, port: int) -> logging.Logger:
    logs_dir = os.path.dirname(os.path.abspath(__file__))
    logs_path = os.path.join(logs_dir, "logs")
    os.makedirs(logs_path, exist_ok=True)
    logger = logging.getLogger(label)
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)7s] [%(name)s]: %(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    log_path = os.path.join(logs_path, f"proxy_{label}_{port}.log")
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def _logs_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


def _next_seq(mode: str, logs_root: str = None) -> int:
    pattern = re.compile(rf"^RECV_{mode}_seq(\d+)\.log$")
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


def _compute_window_entries(bandwidth_kbps: float, mtu: int) -> int:
    packet_per_second = (bandwidth_kbps * 1000) / (mtu * 8)
    return max(1, int(packet_per_second * 10))


def _update_stats(stats: StreamStats, send_ts_us: int, seq_id: int) -> float:
    recv_ts_us = time.time_ns() // 1_000
    latency_us = float(recv_ts_us - send_ts_us)

    with stats.lock:
        if seq_id > stats.total_packets:
            gap_start = stats.total_packets + 1
            gap_end = seq_id - 1
            if gap_end >= gap_start and stats.received_packets > 0:
                gap_size = gap_end - gap_start + 1
                # Count gap entries already seen or already marked lost.
                # Iterate over the smaller collection to keep large gaps fast.
                tracked_count = len(stats.seen_seq_ids) + len(stats.lost_seq_ids)
                if gap_size <= tracked_count:
                    already_accounted = sum(
                        1 for s in range(gap_start, gap_end + 1)
                        if s in stats.seen_seq_ids or s in stats.lost_seq_ids
                    )
                else:
                    already_accounted = sum(
                        1 for s in stats.seen_seq_ids
                        if gap_start <= s <= gap_end
                    ) + sum(
                        1 for s in stats.lost_seq_ids
                        if gap_start <= s <= gap_end
                    )
                stats.lost_packets += gap_size - already_accounted
                stats.lost_seq_ids.update(range(gap_start, gap_end + 1))
            stats.total_packets = seq_id

        if seq_id not in stats.seen_seq_ids:
            stats.seen_seq_ids.add(seq_id)
            stats.received_packets += 1
            if seq_id in stats.lost_seq_ids:
                stats.lost_seq_ids.remove(seq_id)
                stats.lost_packets -= 1

            stats.latency_deque.append(latency_us)

            # RFC 3550: online jitter computation
            if stats.prev_latency_set:
                diff = abs(latency_us - stats.prev_latency_us)
                stats.jitter_rfc3550 = stats.jitter_rfc3550 + (diff - stats.jitter_rfc3550) / 16.0
            stats.prev_latency_us = latency_us
            stats.prev_latency_set = True

            if seq_id > stats.last_seq_id:
                stats.last_seq_id = seq_id

        # Periodically prune old sequence IDs to prevent unbounded memory growth
        if stats.total_packets % 10000 == 0 and stats.total_packets > stats.seq_window_size:
            threshold = stats.total_packets - stats.seq_window_size
            stats.seen_seq_ids = {s for s in stats.seen_seq_ids if s > threshold}
            stats.lost_seq_ids = {s for s in stats.lost_seq_ids if s > threshold}

        # --- NEW: compute instantaneous loss_rate over the sample window (packet-count based) ---
        # calculate each _sample_interval packets, the loss rate over that interval
        # defult _sample_interval is 1000 packets, can be adjusted in StreamStats
        since_sample = stats.total_packets - stats._sample_total
        if since_sample >= stats._sample_interval:
            delta_total = since_sample
            delta_loss = stats.lost_packets - stats._sample_loss
            stats.instant_loss_rate = delta_loss / delta_total * 100.0 if delta_total > 0 else 0.0
            stats._sample_total = stats.total_packets
            stats._sample_loss = stats.lost_packets
        # --- END NEW ---

    return latency_us


def udp_recv_thread(label: str, listen_addr: str, listen_port: int,
                    src_addr: str, src_port: int,
                    bandwidth_kbps: float, mtu: int, stats: StreamStats,
                    shutdown_event: threading.Event) -> None:
    logger = _setup_port_logger(label, listen_port)
    logger.info("UDP listener started on %s:%d", listen_addr, listen_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen_addr, listen_port))
    sock.settimeout(1.0)

    expected_src = (src_addr, src_port) if src_port > 0 else None

    while not shutdown_event.is_set():
        try:
            data, addr = sock.recvfrom(mtu)
        except socket.timeout:
            continue
        except OSError:
            break

        if expected_src is not None and addr != expected_src:
            logger.debug("Ignoring packet from unexpected source %s:%d", addr[0], addr[1])
            continue

        if len(data) < PAYLOAD_HDR_SIZE:
            continue

        send_ts_us, seq_id, magic = struct.unpack(PAYLOAD_HDR_FMT, data[:PAYLOAD_HDR_SIZE])
        if magic != MAGIC:
            logger.debug("Ignoring UDP packet with bad magic 0x%04x", magic)
            continue

        _update_stats(stats, send_ts_us, seq_id)

    sock.close()
    logger.info("UDP listener stopped on %s:%d", listen_addr, listen_port)


def tcp_recv_thread(label: str, listen_addr: str, listen_port: int,
                    bandwidth_kbps: float, mtu_tcp: int, stats: StreamStats,
                    shutdown_event: threading.Event) -> None:
    logger = _setup_port_logger(label, listen_port)
    logger.info("TCP listener started on %s:%d", listen_addr, listen_port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_addr, listen_port))
    server.listen(1)
    server.settimeout(1.0)

    while not shutdown_event.is_set():
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        logger.info("TCP connection from %s:%d", addr[0], addr[1])
        conn.settimeout(1.0)
        buffer = b''
        while not shutdown_event.is_set():
            # Phase 1: read 4-byte frame header
            while len(buffer) < FRAME_HDR_SIZE:
                try:
                    chunk = conn.recv(FRAME_HDR_SIZE - len(buffer))
                except socket.timeout:
                    continue
                except OSError:
                    chunk = None
                if not chunk:
                    break
                buffer += chunk
            if len(buffer) < FRAME_HDR_SIZE:
                break

            frame_hdr = buffer[:FRAME_HDR_SIZE]
            magic, channel, payload_size = struct.unpack(FRAME_HDR_FMT, frame_hdr)

            if magic != MAGIC:
                idx = buffer.find(MAGIC, 1)
                buffer = buffer[idx:] if idx >= 0 else b''
                continue

            buffer = buffer[FRAME_HDR_SIZE:]

            # Phase 2: read payload
            while len(buffer) < payload_size:
                try:
                    chunk = conn.recv(payload_size - len(buffer))
                except socket.timeout:
                    continue
                except OSError:
                    chunk = None
                if not chunk:
                    break
                buffer += chunk
            if len(buffer) < payload_size:
                break

            payload = buffer[:payload_size]
            buffer = buffer[payload_size:]

            if len(payload) < PAYLOAD_HDR_SIZE:
                continue

            send_ts_us, seq_id, magic = struct.unpack(PAYLOAD_HDR_FMT, payload[:PAYLOAD_HDR_SIZE])
            if magic != MAGIC:
                logger.debug("Ignoring TCP frame with bad payload magic 0x%04x", magic)
                continue

            _update_stats(stats, send_ts_us, seq_id)

        conn.close()
        logger.info("TCP connection from %s:%d closed", addr[0], addr[1])

    server.close()
    logger.info("TCP listener stopped on %s:%d", listen_addr, listen_port)


def _compute_stats_line(label: str, stats: StreamStats) -> str:
    with stats.lock:
        recv = stats.received_packets
        loss = stats.lost_packets
        total = stats.total_packets

        if total > 0:
            loss_rate = loss / total * 100
        else:
            loss_rate = 0.0

        deque_list = list(stats.latency_deque)
        if deque_list:
            avg_lat = mean(deque_list)
            latest_latency = deque_list[-1]
        else:
            avg_lat = 0.0
            latest_latency = 0.0

        if avg_lat == 0.0 or len(deque_list) < 2:
            jitter_mean_abs = 0.0
            jitter_mean_pct = 0.0
        else:
            diffs = [abs(deque_list[i] - deque_list[i - 1]) for i in range(1, len(deque_list))]
            jitter_mean_abs = mean(diffs)
            jitter_mean_pct = jitter_mean_abs / avg_lat * 100

        jitter_rfc3550 = stats.jitter_rfc3550
        if avg_lat == 0.0:
            jitter_rfc3550_pct = 0.0
        else:
            jitter_rfc3550_pct = jitter_rfc3550 / avg_lat * 100

    return (
        f"[    INFO] [recv.{label}]: recv={recv}  loss={loss}  total={total}  "
        f"loss_rate={loss_rate:.4f}%  "
        # --- NEW: instantaneous loss_rate over the last sample window ---
        f"instant_loss_rate={stats.instant_loss_rate:.4f}%  "
        # --- END NEW ---
        f"latest_latency={latest_latency:.4f}us  "
        f"avg_lat={avg_lat:.2f}us  "
        f"jitter_mean_abs={jitter_mean_abs:.4f}us  "
        f"jitter_mean_pct={jitter_mean_pct:.4f}%  "
        f"jitter_RFC_3550={jitter_rfc3550:.4f}us  "
        f"jitter_RFC_3550_pct={jitter_rfc3550_pct:.4f}%"
    )


def stats_reporter(streams: list, mode: str, shutdown_event: threading.Event) -> None:
    seq = _next_seq(mode)
    logs_path = _logs_dir()
    log_path = os.path.join(logs_path, f"RECV_{mode}_seq{seq}.log")

    os.makedirs(logs_path, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)7s] [%(name)s]: %(message)s")
    stats_logger = logging.getLogger(f"recv_stats_{mode}_{seq}")
    stats_logger.setLevel(logging.INFO)
    stats_logger.propagate = False

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(fmt)
    stats_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    stats_logger.addHandler(console_handler)

    stream_infos = []
    for label, stats, _bw, _mtu in streams:
        window_entries = _compute_window_entries(_bw, _mtu)
        stream_infos.append((label, stats, window_entries))

    while not shutdown_event.is_set():
        time.sleep(1.0)

        for label, stats, window_entries in stream_infos:
            with stats.lock:
                deque_len = len(stats.latency_deque)
            if deque_len < window_entries:
                continue

            line = _compute_stats_line(label, stats)
            stats_logger.info(line.rstrip())

    for label, stats, window_entries in stream_infos:
        with stats.lock:
            deque_len = len(stats.latency_deque)
        if deque_len > 0:
            line = _compute_stats_line(label, stats)
            stats_logger.info(line.rstrip())


def _addr(cfg: configparser.ConfigParser) -> str:
    return cfg.get("addr", "addr_recv", fallback=None) or cfg.get("addr", "addr", fallback="127.0.0.1")


def _bw(cfg: configparser.ConfigParser, key: str) -> float:
    return cfg.getfloat("config", key, fallback=0.0)


def _mtu(cfg: configparser.ConfigParser) -> int:
    return cfg.getint("config", "mtu", fallback=1400)


def _mtu_tcp(cfg: configparser.ConfigParser) -> int:
    return cfg.getint("config", "mtu_tcp", fallback=100)


def _dst_port(cfg: configparser.ConfigParser, key: str) -> int:
    return cfg.getint("address_to", key, fallback=0)


def _src_addr(cfg: configparser.ConfigParser) -> str:
    return cfg.get("addr", "addr_send", fallback=None) or cfg.get("addr", "addr", fallback="127.0.0.1")


def _src_port(cfg: configparser.ConfigParser, key: str) -> int:
    return cfg.getint("address_from", key, fallback=0)


def udp_1_recv(cfg: configparser.ConfigParser) -> list:
    addr = _addr(cfg)
    src_addr = _src_addr(cfg)
    port = _dst_port(cfg, "udp_1_0_addr_to")
    src_port = _src_port(cfg, "udp_1_0_addr_from")
    bw = _bw(cfg, "bandwidth_udp_1_0")
    mtu = _mtu(cfg)
    stats = StreamStats(latency_deque=deque(maxlen=_compute_window_entries(bw, mtu) * 2))

    t = threading.Thread(
        target=udp_recv_thread,
        args=("udp_main", addr, port, src_addr, src_port, bw, mtu, stats, shutdown_event),
        daemon=True,
    )
    t.start()
    return [[t], [("udp_main", stats, bw, mtu)]]


def udp_1_2_recv(cfg: configparser.ConfigParser) -> list:
    addr = _addr(cfg)
    src_addr = _src_addr(cfg)
    mtu = _mtu(cfg)
    streams = [
        ("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_to", "udp_1_0_addr_from"),
        ("udp_rec0", "bandwidth_udp_2_0", "udp_2_0_addr_to", "udp_2_0_addr_from"),
        ("udp_rec1", "bandwidth_udp_2_1", "udp_2_1_addr_to", "udp_2_1_addr_from"),
    ]
    threads = []
    stream_infos = []
    for label, bw_key, dst_key, src_key in streams:
        bw = _bw(cfg, bw_key)
        port = _dst_port(cfg, dst_key)
        src_port = _src_port(cfg, src_key)
        stats = StreamStats(latency_deque=deque(maxlen=_compute_window_entries(bw, mtu) * 2))
        t = threading.Thread(
            target=udp_recv_thread,
            args=(label, addr, port, src_addr, src_port, bw, mtu, stats, shutdown_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
        stream_infos.append((label, stats, bw, mtu))
    return [threads, stream_infos]


def udp_1_2_tcp_1_recv(cfg: configparser.ConfigParser) -> list:
    addr = _addr(cfg)
    src_addr = _src_addr(cfg)
    mtu = _mtu(cfg)
    mtu_tcp_val = _mtu_tcp(cfg)
    threads = []
    stream_infos = []

    udp_streams = [
        ("udp_main", "bandwidth_udp_1_0", "udp_1_0_addr_to", "udp_1_0_addr_from"),
        ("udp_rec0", "bandwidth_udp_2_0", "udp_2_0_addr_to", "udp_2_0_addr_from"),
        ("udp_rec1", "bandwidth_udp_2_1", "udp_2_1_addr_to", "udp_2_1_addr_from"),
    ]
    for label, bw_key, dst_key, src_key in udp_streams:
        bw = _bw(cfg, bw_key)
        port = _dst_port(cfg, dst_key)
        src_port = _src_port(cfg, src_key)
        stats = StreamStats(latency_deque=deque(maxlen=_compute_window_entries(bw, mtu) * 2))
        t = threading.Thread(
            target=udp_recv_thread,
            args=(label, addr, port, src_addr, src_port, bw, mtu, stats, shutdown_event),
            daemon=True,
        )
        t.start()
        threads.append(t)
        stream_infos.append((label, stats, bw, mtu))

    bw_tcp = _bw(cfg, "bandwidth_tcp_1_0")
    port_tcp = _dst_port(cfg, "tcp_1_0_addr_to")
    tcp_stats = StreamStats(latency_deque=deque(maxlen=_compute_window_entries(bw_tcp, mtu_tcp_val) * 2))
    t_tcp = threading.Thread(
        target=tcp_recv_thread,
        args=("tcp_main", addr, port_tcp, bw_tcp, mtu_tcp_val, tcp_stats, shutdown_event),
        daemon=True,
    )
    t_tcp.start()
    threads.append(t_tcp)
    stream_infos.append(("tcp_main", tcp_stats, bw_tcp, mtu_tcp_val))

    return [threads, stream_infos]


def select_proxies(cfg: configparser.ConfigParser) -> tuple:
    mode = get_active_mode(cfg)
    if mode == "udp_1":
        return udp_1_recv(cfg)
    elif mode == "udp_1_2":
        return udp_1_2_recv(cfg)
    elif mode == "udp_1_2_tcp_1":
        return udp_1_2_tcp_1_recv(cfg)
    else:
        print(f"ERROR: unknown mode '{mode}'", file=sys.stderr)
        sys.exit(1)


def _signal_handler(signum, frame):
    print("\n[INFO] Received signal, shutting down...")
    shutdown_event.set()


def main():
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    parser = argparse.ArgumentParser(description="Wireless packet loss test — receiver.")
    parser.add_argument(
        "--config", default="config_wireless.ini",
        help="Path to config file (default: config_wireless.ini)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    mode = get_active_mode(cfg)

    print(f"[INFO] Active mode: {mode}")
    print("[INFO] Starting listener threads...")

    threads, stream_infos = select_proxies(cfg)

    reporter = threading.Thread(
        target=stats_reporter,
        args=(stream_infos, mode, shutdown_event),
        daemon=True,
    )
    reporter.start()

    print(f"[INFO] {len(threads)} listener thread(s) running. Press Ctrl+C to stop.")

    try:
        while not shutdown_event.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        shutdown_event.set()

    print("[INFO] Waiting for threads to finish...")
    for t in threads:
        t.join(timeout=3.0)
    reporter.join(timeout=3.0)

    print("[INFO] Receiver shutdown complete.")


if __name__ == "__main__":
    main()
