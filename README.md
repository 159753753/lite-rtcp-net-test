# Wireless Packet Loss & Latency Test

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A Python-based tool for measuring **packet loss**, **latency**, and **jitter** over UDP/TCP networks. Designed for wireless link quality assessment with multi-stream concurrent testing.

## Features

- Three modes: single UDP, redundant UDP, UDP+TCP hybrid
- Loss recovery: delayed packets heal prior loss counts
- Source address filtering on UDP receive
- Magic byte validation (`0x66CCFF`)
- Dual jitter: RFC 1889 (mean absolute difference) and RFC 3550 (online exponential)
- Instant loss rate over configurable sample window
- Rate-drift compensation via deadline scheduling
- Thread-safe per-stream statistics

## Quick Start

```bash
# 1. Edit config
vim config_wireless.ini

# 2. Start receiver (destination machine)
python3 wireless_recv_test.py

# 3. Start sender (source machine)
python3 wireless_send_test.py
```

Press `Ctrl+C` to stop. Both scripts accept `--config PATH` to specify a custom config file (default: `config_wireless.ini`).

## Modes

| Mode | Streams | Description |
|---|---|---|
| `udp_1` | 1 × UDP | Single-stream baseline |
| `udp_1_2` | 3 × UDP | Redundant-path simulation |
| `udp_1_2_tcp_1` | 3 × UDP + 1 × TCP | UDP vs TCP comparison |

Enable exactly one mode:

```ini
[mode]
udp_1=true
udp_1_2=false
udp_1_2_tcp_1=false
```

## Protocol

### UDP Packet

```
+------------------+------------------+---------------------------+
| send_ts_us (8 B) |  seq_id (8 B)    | magic (3 B) 0x66CCFF     |
+------------------+------------------+---------------------------+
|                       padding zeros ...                      |
+--------------------------------------------------------------+
                          Total = mtu
```

### TCP Frame (RTSP Interleaved)

```
+-----------------------------+-------------------+
| magic (3 B) 0x66CCFF        | ch (1 B) | len (2 B) |
+-----------------------------+----------+-----------+
| send_ts_us (8 B) | seq_id (8 B) | magic (3 B) 0x66CCFF |
+------------------+--------------+----------------------+
|                   padding zeros ...                     |
+--------------------------------------------------------+
               Frame header = 6 B  +  Payload = mtu_tcp
```

Header fields: `send_ts_us` (uint64, microseconds), `seq_id` (uint64), `magic` (3 bytes, `0x66CCFF`).

TCP framing adds a 6-byte RTSP interleaved header: magic (3 B) + channel (1 B) + length (2 B).

## Usage

### Local Loopback

```ini
# config_wireless.ini
[addr]
addr=127.0.0.1
```

```bash
python3 wireless_recv_test.py &    # Terminal 1
python3 wireless_send_test.py      # Terminal 2
```

### Cross-Machine

```ini
[addr]
addr_send=192.168.50.51
addr_recv=192.168.50.52
```

Run receiver on `192.168.50.52`, sender on `192.168.50.51`. If `addr_send` or `addr_recv` is unset, both fall back to `addr`.

### Custom Config Path

```bash
python3 wireless_recv_test.py --config /path/to/custom.ini
python3 wireless_send_test.py --config /path/to/custom.ini
```

## Configuration

All settings in `config_wireless.ini`:

### `[mode]`

| Key | Fallback | Description |
|---|---|---|
| `udp_1` | `false` | Single UDP stream |
| `udp_1_2` | `false` | 3 UDP streams (main + 2 recovery) |
| `udp_1_2_tcp_1` | `false` | 3 UDP + 1 TCP |

### `[config]`

| Key | Fallback | Description |
|---|---|---|
| `mtu` | `1400` | UDP packet size (bytes) |
| `mtu_tcp` | `100` | TCP payload size (bytes) |
| `bandwidth_udp_1_0` | `0` | Main UDP bandwidth (kbps) |
| `bandwidth_udp_2_0` | `0` | Recovery UDP #0 bandwidth (kbps) |
| `bandwidth_udp_2_1` | `0` | Recovery UDP #1 bandwidth (kbps) |
| `bandwidth_tcp_1_0` | `0` | TCP bandwidth (kbps) |

### `[addr]`

| Key | Fallback | Description |
|---|---|---|
| `addr` | `127.0.0.1` | Fallback when `addr_send` or `addr_recv` is unset |
| `addr_send` | — | Sender bind address |
| `addr_recv` | — | Receiver bind address |

### `[address_from]` — Source Ports

| Key | Fallback | Description |
|---|---|---|
| `udp_1_0_addr_from` | `0` | Main UDP source port |
| `udp_2_0_addr_from` | `0` | Recovery UDP #0 source port |
| `udp_2_1_addr_from` | `0` | Recovery UDP #1 source port |
| `tcp_1_0_addr_from` | `0` | TCP source port |

### `[address_to]` — Destination Ports

| Key | Fallback | Description |
|---|---|---|
| `udp_1_0_addr_to` | `0` | Main UDP destination port |
| `udp_2_0_addr_to` | `0` | Recovery UDP #0 destination port |
| `udp_2_1_addr_to` | `0` | Recovery UDP #1 destination port |
| `tcp_1_0_addr_to` | `0` | TCP destination port |

## Architecture

```
config_wireless.ini
        │
        ├──────────────────┐
        ▼                  ▼
 wireless_send_test   wireless_recv_test
    (Sender)             (Receiver)
        │                    │
   udp_send_thread      udp_recv_thread
   tcp_send_thread      tcp_recv_thread
        │                    │
        └──── UDP/TCP ──────►│
                             ▼
                        StreamStats
                        (per stream)
                             │
                             ▼
                      logs/RECV_*.log
```

### Packet Filtering (Receiver)

```
Packet arrives → src address match? → len ≥ 19? → magic == 0x66CCFF? → update stats
                      │ NO               │ NO           │ NO
                      ▼                  ▼              ▼
                    drop               drop           drop
```

Filtering applies to UDP only. TCP uses stream framing with magic byte resynchronization.

### Loss Recovery

Packets are tracked by `seq_id` in two sets:

- `seen_seq_ids` — confirmed received
- `lost_seq_ids` — tentatively lost (gap inferred)

When a higher `seq_id` reveals a gap, missing IDs enter `lost_seq_ids`. If they arrive later, they move to `seen_seq_ids` and the loss counter decreases. Only packets that never arrive count as truly lost.

## Output

### Stats Log (`logs/RECV_<mode>_seq<N>.log`)

Reported every second per stream once the deque window fills:

```
2026-01-01 12:00:01,234 [    INFO] [recv.udp_main]: recv=178  loss=2  total=180  loss_rate=1.1111%  instant_loss_rate=0.5000%  latest_latency=1234.5678us  avg_lat=1100.23us  jitter_mean_abs=45.6789us  jitter_mean_pct=4.15%  jitter_RFC_3550=38.9123us  jitter_RFC_3550_pct=3.54%
```

| Field | Description |
|---|---|
| `recv` | Packets received |
| `loss` | Packets lost (net, after recovery) |
| `total` | Highest `seq_id` seen |
| `loss_rate` | Cumulative loss percentage |
| `instant_loss_rate` | Loss rate over last 1000 packets |
| `latest_latency` | Most recent packet latency (µs) |
| `avg_lat` | Mean latency over deque window (µs) |
| `jitter_mean_abs` | RFC 1889 mean absolute difference (µs) |
| `jitter_mean_pct` | RFC 1889 jitter as % of average latency |
| `jitter_RFC_3550` | RFC 3550 online jitter estimate (µs) |
| `jitter_RFC_3550_pct` | RFC 3550 jitter as % of average latency |

### Per-Port Log (`logs/proxy_<label>_<port>.log`)

Thread start/stop events and source-filtered packet warnings.

### Sender Log (`logs/SEND_<mode>_seq<N>.log`)

One-time stream parameter summary written at sender startup. Logs configured bandwidth, packet size, packets-per-second, and send interval for each active stream.

## Files

| File | Description |
|---|---|
| `wireless_send_test.py` | Sender — UDP/TCP traffic generator |
| `wireless_recv_test.py` | Receiver — statistics collector |
| `config_wireless.ini` | Configuration |
| `logs/` | Runtime log output |

## License

MIT
