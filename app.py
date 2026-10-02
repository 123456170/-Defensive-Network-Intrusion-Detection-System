# app.py
# Defensive Network Intrusion Detection System - Streamlit demo
# Defensive use only. Defaults to synthetic demo mode. Blocking is not implemented.

from __future__ import annotations

import copy
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import socket
import sqlite3
import struct
import tempfile
import threading
import time
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st
import streamlit.components.v1 as components
import yaml

try:
    import psutil
except Exception:
    psutil = None

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, sniff, rdpcap
except Exception:
    IP = None
    IPv6 = None
    TCP = None
    UDP = None
    ICMP = None
    Raw = None
    sniff = None
    rdpcap = None


st.set_page_config(
    page_title="Defensive NIDS Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

APP_VERSION = "1.0.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ETH_DST = bytes.fromhex("0242ac110002")
ETH_SRC = bytes.fromhex("0242ac110003")


DEFAULT_YAML = """
schema_version: 1
mode: demo

capture:
  interface: any
  bpf_filter: ""
  promisc: true
  max_pps: 20000

demo:
  events_per_second: 80
  attack_cycle_seconds: 70

storage:
  max_alerts: 5000
  max_metrics: 2000
  window_minutes: 60

detection:
  port_scan:
    enabled: true
    distinct_ports: 100
    window_seconds: 10
    rate_limit_seconds: 20
  syn_flood:
    enabled: true
    min_syn: 220
    window_seconds: 5
    ratio: 3.0
    rate_limit_seconds: 15
  signatures:
    enabled: true

allowlist_scanners:
  - 192.0.2.10
  - 2001:db8::10

ui:
  refresh_seconds: 1.0
  default_role: admin
"""

DEFAULT_CONFIG = yaml.safe_load(DEFAULT_YAML)


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def validate_config(cfg: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    try:
        if cfg.get("mode") not in {"demo", "live", "replay"}:
            errors.append("mode must be demo, live, or replay")

        eps = float(cfg["demo"]["events_per_second"])
        if not 1 <= eps <= 2000:
            errors.append("demo.events_per_second must be between 1 and 2000")

        cycle = float(cfg["demo"]["attack_cycle_seconds"])
        if not 20 <= cycle <= 3600:
            errors.append("demo.attack_cycle_seconds must be between 20 and 3600")

        max_alerts = int(cfg["storage"]["max_alerts"])
        if not 100 <= max_alerts <= 100000:
            errors.append("storage.max_alerts must be between 100 and 100000")

        max_metrics = int(cfg["storage"]["max_metrics"])
        if not 100 <= max_metrics <= 20000:
            errors.append("storage.max_metrics must be between 100 and 20000")

        ps_cfg = cfg["detection"]["port_scan"]
        if int(ps_cfg["distinct_ports"]) < 2 or int(ps_cfg["distinct_ports"]) > 10000:
            errors.append("detection.port_scan.distinct_ports must be between 2 and 10000")
        if float(ps_cfg["window_seconds"]) < 1 or float(ps_cfg["window_seconds"]) > 300:
            errors.append("detection.port_scan.window_seconds must be between 1 and 300")
        if float(ps_cfg["rate_limit_seconds"]) < 1 or float(ps_cfg["rate_limit_seconds"]) > 600:
            errors.append("detection.port_scan.rate_limit_seconds must be between 1 and 600")

        syn_cfg = cfg["detection"]["syn_flood"]
        if int(syn_cfg["min_syn"]) < 10 or int(syn_cfg["min_syn"]) > 100000:
            errors.append("detection.syn_flood.min_syn must be between 10 and 100000")
        if float(syn_cfg["window_seconds"]) < 1 or float(syn_cfg["window_seconds"]) > 120:
            errors.append("detection.syn_flood.window_seconds must be between 1 and 120")
        if float(syn_cfg["ratio"]) < 1 or float(syn_cfg["ratio"]) > 1000:
            errors.append("detection.syn_flood.ratio must be between 1 and 1000")

        refresh = float(cfg["ui"]["refresh_seconds"])
        if not 0.5 <= refresh <= 10:
            errors.append("ui.refresh_seconds must be between 0.5 and 10")

        for item in cfg.get("allowlist_scanners", []):
            text = str(item)
            try:
                if "/" in text:
                    ipaddress.ip_network(text, strict=False)
                else:
                    ipaddress.ip_address(text)
            except Exception:
                errors.append(f"invalid allowlist_scanners entry: {item}")
    except Exception as exc:
        errors.append(f"config validation error: {exc}")

    return errors


def parse_config_text(text: str) -> Tuple[Dict[str, Any], List[str]]:
    try:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            data = {}
        cfg = deep_merge(DEFAULT_CONFIG, data)
        errors = validate_config(cfg)
        if errors:
            return copy.deepcopy(DEFAULT_CONFIG), errors
        return cfg, []
    except Exception as exc:
        return copy.deepcopy(DEFAULT_CONFIG), [str(exc)]


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()


def tcp_flags_from_text(text: str) -> int:
    mapping = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16, "U": 32, "E": 64, "C": 128}
    value = 0
    for ch in str(text).upper():
        value |= mapping.get(ch, 0)
    return value or 2


def build_pcap(events: List[Dict[str, Any]]) -> bytes:
    if not events:
        return b""

    out = io.BytesIO()
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    for ev in events[:12]:
        try:
            ts = float(ev.get("ts", time.time()))
            proto_raw = ev.get("proto", 6)
            try:
                proto = int(proto_raw)
            except Exception:
                proto = 6

            payload = str(ev.get("payload", ""))[:200].encode("utf-8", "ignore")
            src = str(ev.get("src", "10.0.0.1"))
            dst = str(ev.get("dst", "10.0.0.2"))
            sport = int(ev.get("sport", 0) or 0)
            dport = int(ev.get("dport", 0) or 0)
            ip6 = ":" in src or ":" in dst

            if proto == 6:
                flags = tcp_flags_from_text(ev.get("flags", "S"))
                transport = struct.pack(
                    "!HHIIBBHHH",
                    sport,
                    dport,
                    int(ev.get("seq", 0) or 0),
                    int(ev.get("ack", 0) or 0),
                    0x50,
                    flags,
                    65535,
                    0,
                    0,
                )
            elif proto == 17:
                udp_len = 8 + len(payload)
                transport = struct.pack("!HHHH", sport, dport, udp_len, 0)
            else:
                transport = struct.pack("!BBH", 8, 0, 0)
                payload = payload[:64]

            if ip6:
                try:
                    srcb = socket.inet_pton(socket.AF_INET6, src)
                except Exception:
                    srcb = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
                try:
                    dstb = socket.inet_pton(socket.AF_INET6, dst)
                except Exception:
                    dstb = socket.inet_pton(socket.AF_INET6, "2001:db8::2")

                ip_header = struct.pack(
                    "!IHBB16s16s",
                    0x60000000,
                    len(transport) + len(payload),
                    proto,
                    64,
                    srcb,
                    dstb,
                )
                eth_type = b"\x86\xdd"
            else:
                try:
                    srcb = socket.inet_pton(socket.AF_INET, src)
                except Exception:
                    srcb = socket.inet_pton(socket.AF_INET, "10.0.0.1")
                try:
                    dstb = socket.inet_pton(socket.AF_INET, dst)
                except Exception:
                    dstb = socket.inet_pton(socket.AF_INET, "10.0.0.2")

                total_len = 20 + len(transport) + len(payload)
                ip_header = struct.pack(
                    "!BBHHHBBH4s4s",
                    0x45,
                    0,
                    total_len,
                    random.randint(0, 65535),
                    0,
                    64,
                    proto,
                    0,
                    srcb,
                    dstb,
                )
                eth_type = b"\x08\x00"

            packet = ETH_DST + ETH_SRC + eth_type + ip_header + transport + payload
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            out.write(struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)))
            out.write(packet)
        except Exception:
            continue

    return out.getvalue()


def sqlite3_connect_memory():
    return sqlite3.connect(":memory:", check_same_thread=False)


class NIDSEngine:
    def __init__(self, config: Dict[str, Any], start: bool = True, seed: bool = True):
        self.config = copy.deepcopy(config)
        self.lock = threading.RLock()
        self.running = True
        self.started = time.time()
        self.rng = random.Random(42)

        self.conn = sqlite3_connect_memory()
        self.conn.row_factory = sqlite3.Row

        self.alert_last_hash = hashlib.sha256(b"nids-alert-genesis").hexdigest()
        self.audit_last_hash = hashlib.sha256(b"nids-audit-genesis").hexdigest()

        self.alerts = deque(maxlen=int(self.config["storage"]["max_alerts"]))
        self.metrics = deque(maxlen=int(self.config["storage"]["max_metrics"]))
        self.event_window = deque(maxlen=2000)

        self.port_windows = defaultdict(deque)
        self.syn_windows = defaultdict(lambda: {"syn": deque(), "synack": deque()})
        self.sig_windows = defaultdict(deque)
        self.rate = {}
        self.flow_cache = {}
        self.fragment_buffer = defaultdict(list)
        self.attack_states = {}
        self.next_attack = self.started + 2.0
        self.detected_incidents = set()

        self.counters = defaultdict(float)
        self.rule_stats = defaultdict(lambda: {"matches": 0, "alerts": 0, "suppressed": 0})
        self.signatures = self._default_signatures()

        self._metric_last = None
        self._last_metrics_run = 0.0

        self._create_db()
        self._append_audit("startup", f"mode={self.config.get('mode')}", actor="system")

        if seed:
            self._seed_demo_history()

        self.thread = None
        if start:
            self.thread = threading.Thread(target=self._run, daemon=True)
            self.thread.start()

    def _default_signatures(self) -> List[Dict[str, Any]]:
        return [
            {
                "sid": "2000001",
                "msg": "HTTP LFI attempt /etc/passwd",
                "severity": "high",
                "proto": 6,
                "dports": [80, 8080],
                "content": "/etc/passwd",
                "mitre": "T1190 Exploit Public-Facing Application",
                "rate_limit_seconds": 20,
            },
            {
                "sid": "2000002",
                "msg": "DNS unusually long query name",
                "severity": "medium",
                "proto": 17,
                "dports": [53],
                "dns_qname_len": 52,
                "mitre": "T1071.004 DNS",
                "rate_limit_seconds": 30,
            },
            {
                "sid": "2000003",
                "msg": "SSH brute-force banner exposure",
                "severity": "medium",
                "proto": 6,
                "dports": [22],
                "content": "SSH-2.0",
                "threshold": 8,
                "window_seconds": 10,
                "mitre": "T1110 Brute Force",
                "rate_limit_seconds": 30,
            },
            {
                "sid": "2000004",
                "msg": "Outbound TLS or C2-like traffic on rare high port",
                "severity": "low",
                "proto": 6,
                "dports": [6697],
                "metadata_only": True,
                "mitre": "T1571 Non-Standard Port",
                "rate_limit_seconds": 60,
            },
        ]

    def _create_db(self) -> None:
        with self.lock, self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src TEXT,
                    dst TEXT,
                    rule_id TEXT,
                    severity TEXT,
                    message TEXT,
                    evidence TEXT,
                    pcap_ref TEXT,
                    mitre TEXT,
                    latency_ms REAL,
                    prev_hash TEXT,
                    alert_hash TEXT
                );

                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    pps REAL,
                    mbps REAL,
                    alerts REAL,
                    drop_rate REAL,
                    cpu REAL,
                    mem REAL
                );

                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    actor TEXT,
                    action TEXT,
                    detail TEXT,
                    prev_hash TEXT,
                    hash TEXT
                );
                """
            )

    def _append_audit(self, action: str, detail: str, actor: str = "engine", ts: Optional[float] = None) -> None:
        ts = float(ts or time.time())
        iso = utc_iso(ts)
        detail = str(detail)[:1000]
        prev = self.audit_last_hash
        payload = f"{iso}|{actor}|{action}|{detail}|{prev}"
        current = hashlib.sha256(payload.encode()).hexdigest()
        self.audit_last_hash = current

        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO audit(ts, actor, action, detail, prev_hash, hash) VALUES(?,?,?,?,?,?)",
                (iso, actor, action, detail, prev, current),
            )

    def _insert_alert(
        self,
        ts: float,
        rule_id: str,
        severity: str,
        message: str,
        src: str,
        dst: str,
        evidence: str,
        pcap_events: List[Dict[str, Any]],
        mitre: str,
        latency_ms: float = 0.0,
        label: str = "unknown",
        attack_id: Optional[str] = None,
        count_stats: bool = True,
    ) -> Dict[str, Any]:
        iso = utc_iso(ts)
        evidence = str(evidence)[:800]
        prev = self.alert_last_hash
        alert_hash = hashlib.sha256(
            f"{prev}|{iso}|{src}|{dst}|{rule_id}|{severity}|{message}|{evidence}".encode()
        ).hexdigest()
        self.alert_last_hash = alert_hash

        pcap_bytes = build_pcap(pcap_events) if pcap_events else b""
        pcap_ref = hashlib.sha256(pcap_bytes).hexdigest()[:16] if pcap_bytes else ""

        with self.lock, self.conn:
            cur = self.conn.execute(
                """
                INSERT INTO alerts(
                    timestamp, src, dst, rule_id, severity, message,
                    evidence, pcap_ref, mitre, latency_ms, prev_hash, alert_hash
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    iso,
                    src,
                    dst,
                    rule_id,
                    severity,
                    message,
                    evidence,
                    pcap_ref,
                    mitre,
                    float(latency_ms),
                    prev,
                    alert_hash,
                ),
            )
            alert_id = cur.lastrowid

        row = {
            "id": alert_id,
            "timestamp": iso,
            "ts": float(ts),
            "src": src,
            "dst": dst,
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "evidence": evidence,
            "pcap_ref": pcap_ref,
            "mitre": mitre,
            "latency_ms": float(latency_ms),
            "prev_hash": prev,
            "alert_hash": alert_hash,
            "pcap_bytes": pcap_bytes,
            "pcap_len": len(pcap_bytes),
        }

        self.alerts.appendleft(row)
        self._append_audit("alert", f"rule={rule_id} src={src} dst={dst} sev={severity}", actor="engine", ts=ts)

        if count_stats:
            self.counters["alerts_total"] += 1
            self.counters[f"alerts_{severity}"] += 1
            if label == "attack":
                if attack_id and attack_id not in self.detected_incidents:
                    self.detected_incidents.add(attack_id)
                    self.counters["detected_incidents"] += 1
            elif label == "benign":
                self.counters["false_positives"] += 1

        return row

    def _rate_allow(self, key: str, ts: float, limit: float) -> bool:
        last = self.rate.get(key, 0.0)
        if ts - last >= float(limit):
            self.rate[key] = ts
            return True
        return False

    def _alert(
        self,
        rule_id: str,
        severity: str,
        message: str,
        pkt: Dict[str, Any],
        evidence: str,
        pcap_events: List[Dict[str, Any]],
        mitre: str,
        rate_limit: float,
        ts: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        ts = float(ts or pkt.get("ts", time.time()))
        src = str(pkt.get("src", "?"))
        dst = str(pkt.get("dst", "?"))
        key = f"{rule_id}:{src}:{dst}"

        with self.lock:
            self.rule_stats[rule_id]["matches"] += 1
            if not self._rate_allow(key, ts, rate_limit):
                self.rule_stats[rule_id]["suppressed"] += 1
                return None

            latency_ms = max(0.0, (time.time() - ts) * 1000.0)
            row = self._insert_alert(
                ts=ts,
                rule_id=rule_id,
                severity=severity,
                message=message,
                src=src,
                dst=dst,
                evidence=evidence,
                pcap_events=pcap_events,
                mitre=mitre,
                latency_ms=latency_ms,
                label=str(pkt.get("label", "unknown")),
                attack_id=pkt.get("attack_id"),
                count_stats=True,
            )
            self.rule_stats[rule_id]["alerts"] += 1
            return row

    def _allowlisted(self, ip_text: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except Exception:
            return False

        for item in self.config.get("allowlist_scanners", []):
            text = str(item)
            try:
                if "/" in text:
                    if ip_obj in ipaddress.ip_network(text, strict=False):
                        return True
                elif ipaddress.ip_address(text) == ip_obj:
                    return True
            except Exception:
                continue
        return False

    def _choose_allowed_scanner(self) -> str:
        for item in self.config.get("allowlist_scanners", []):
            text = str(item)
            if "/" in text:
                continue
            try:
                ipaddress.ip_address(text)
                return text
            except Exception:
                continue
        return "192.0.2.10"

    def _audit_scanner(self, src: str) -> None:
        with self.lock:
            key = f"authorized_scanner:{src}"
            if self._rate_allow(key, time.time(), 60):
                self._append_audit("authorized_scan", f"allowed scanner src={src}", actor="allowlist")

    def _mini(self, pkt: Dict[str, Any]) -> Dict[str, Any]:
        keep = ("ts", "src", "dst", "proto", "sport", "dport", "flags", "payload", "len", "qname")
        return {k: pkt.get(k) for k in keep if k in pkt}

    def _count_benign_flow(self, pkt: Dict[str, Any]) -> None:
        key = "|".join(
            [
                str(pkt.get("src")),
                str(pkt.get("dst")),
                str(pkt.get("proto")),
                str(pkt.get("sport", "")),
                str(pkt.get("dport", "")),
            ]
        )
        ts = float(pkt.get("ts", time.time()))
        last = self.flow_cache.get(key)
        if last is None or ts - last > 30:
            self.counters["benign_flows"] += 1
        self.flow_cache[key] = ts
        if len(self.flow_cache) > 30000:
            self.flow_cache.clear()

    def ingest(self, pkt: Dict[str, Any], source: str = "demo") -> None:
        if not isinstance(pkt, dict):
            with self.lock:
                self.counters["parser_errors"] += 1
            return

        with self.lock:
            self.counters["events_received"] += 1

        try:
            ts = float(pkt.get("ts", time.time()))
        except Exception:
            ts = time.time()
            with self.lock:
                self.counters["parser_errors"] += 1

        now = time.time()
        if ts > now + 5:
            ts = now
            with self.lock:
                self.counters["clock_skew"] += 1

        src = str(pkt.get("src") or "").strip()
        dst = str(pkt.get("dst") or "").strip()

        if not src or not dst:
            with self.lock:
                self.counters["parser_errors"] += 1
                self.counters["missing_data"] += 1
            return

        try:
            ipaddress.ip_address(src)
            ipaddress.ip_address(dst)
        except Exception:
            with self.lock:
                self.counters["parser_errors"] += 1
            return

        try:
            proto = int(pkt.get("proto", 0))
        except Exception:
            proto = 0

        pkt = dict(pkt)
        pkt.update({"src": src, "dst": dst, "proto": proto, "ts": ts})

        payload_text = str(pkt.get("payload", ""))
        if len(payload_text) > 4096:
            pkt["payload"] = payload_text[:4096]

        with self.lock:
            self.counters["packets"] += 1
            self.counters["bytes"] += int(pkt.get("len", 60))
            self.event_window.append(
                {
                    "ts": ts,
                    "src": src,
                    "dst": dst,
                    "proto": proto,
                    "dport": pkt.get("dport"),
                    "label": pkt.get("label", "unknown"),
                }
            )

            if pkt.get("label") == "benign":
                self._count_benign_flow(pkt)

            if pkt.get("frag_offset") is not None or pkt.get("more_fragments"):
                fid = pkt.get("frag_id") or f"{src}:{dst}:{proto}"
                self.fragment_buffer[fid].append(self._mini(pkt))
                self.counters["fragments"] += 1

                if not pkt.get("more_fragments") and len(self.fragment_buffer[fid]) >= 2:
                    pkt["reassembled"] = True
                    self.fragment_buffer.pop(fid, None)
                    self.counters["reassembled"] += 1
                else:
                    return

        if self._allowlisted(src):
            self._audit_scanner(src)
            return

        self._detect_port_scan(pkt)
        self._detect_syn_flood(pkt)

        if self.config["detection"]["signatures"]["enabled"]:
            self._match_signatures(pkt)

    def _detect_port_scan(self, pkt: Dict[str, Any]) -> None:
        cfg = self.config["detection"]["port_scan"]
        if not cfg.get("enabled"):
            return
        if pkt.get("proto") not in (6, 17):
            return
        if not pkt.get("dport"):
            return

        src = str(pkt.get("src"))
        ts = float(pkt.get("ts"))
        dport = int(pkt.get("dport"))

        with self.lock:
            q = self.port_windows[src]
            q.append((ts, dport, self._mini(pkt)))

            window = float(cfg["window_seconds"])
            while q and ts - q[0][0] > window:
                q.popleft()

            distinct = len({p for _, p, _ in q})
            if distinct >= int(cfg["distinct_ports"]):
                sample = sorted({str(p) for _, p, _ in q})[:12]
                evidence = f"distinct_ports={distinct} window={window}s sample={','.join(sample)}"
                pcap_events = [mini for _, _, mini in list(q)[-8:]]
                row = self._alert(
                    rule_id="PORT_SCAN",
                    severity="high",
                    message="Possible port scan",
                    pkt=pkt,
                    evidence=evidence,
                    pcap_events=pcap_events,
                    mitre="TA0007 Discovery",
                    rate_limit=float(cfg["rate_limit_seconds"]),
                    ts=ts,
                )
                if row:
                    q.clear()
                else:
                    for _ in range(min(50, len(q))):
                        q.popleft()

    def _detect_syn_flood(self, pkt: Dict[str, Any]) -> None:
        cfg = self.config["detection"]["syn_flood"]
        if not cfg.get("enabled"):
            return
        if pkt.get("proto") != 6:
            return

        flags = str(pkt.get("flags", "")).upper()
        ts = float(pkt.get("ts"))
        window = float(cfg["window_seconds"])
        server = None

        with self.lock:
            if "S" in flags and "A" not in flags:
                server = str(pkt.get("dst"))
                win = self.syn_windows[server]
                win["syn"].append((ts, self._mini(pkt)))
            elif "S" in flags and "A" in flags:
                server = str(pkt.get("src"))
                win = self.syn_windows[server]
                win["synack"].append(ts)
            else:
                return

            win = self.syn_windows.get(server)
            if not win:
                return

            while win["syn"] and ts - win["syn"][0][0] > window:
                win["syn"].popleft()
            while win["synack"] and ts - win["synack"][0] > window:
                win["synack"].popleft()

            syn_count = len(win["syn"])
            synack_count = len(win["synack"])

            if syn_count >= int(cfg["min_syn"]) and syn_count / max(1, synack_count) >= float(cfg["ratio"]):
                evidence = f"syn={syn_count} synack={synack_count} window={window}s server={server}"
                pcap_events = [mini for _, mini in list(win["syn"])[-8:]]
                last_pkt = win["syn"][-1][1]
                row = self._alert(
                    rule_id="SYN_FLOOD",
                    severity="critical",
                    message="Possible SYN flood",
                    pkt=last_pkt,
                    evidence=evidence,
                    pcap_events=pcap_events,
                    mitre="T1498 Network Denial of Service",
                    rate_limit=float(cfg["rate_limit_seconds"]),
                    ts=ts,
                )
                if row:
                    win["syn"].clear()
                    win["synack"].clear()
                else:
                    for _ in range(min(50, len(win["syn"]))):
                        win["syn"].popleft()

    def _match_signatures(self, pkt: Dict[str, Any]) -> None:
        proto = pkt.get("proto")
        dport = pkt.get("dport")
        payload = str(pkt.get("payload", "")).lower()
        qname = str(pkt.get("qname", ""))
        ts = float(pkt.get("ts"))

        for sig in self.signatures:
            if sig.get("proto") and proto != sig.get("proto"):
                continue
            if sig.get("dports") and dport not in sig.get("dports", []):
                continue

            matched = False
            if "content" in sig and sig["content"].lower() in payload:
                matched = True
            if "dns_qname_len" in sig and len(qname) >= int(sig["dns_qname_len"]):
                matched = True

            if not matched:
                continue

            if sig.get("threshold"):
                key = f"{sig['sid']}:{pkt.get('src')}"
                q = self.sig_windows[key]
                q.append(ts)
                window = float(sig.get("window_seconds", 10))
                while q and ts - q[0] > window:
                    q.popleft()
                if len(q) < int(sig["threshold"]):
                    continue
                q.clear()

            payload_snippet = str(pkt.get("payload", ""))[:80]
            qname_snippet = qname[:60]
            evidence = (
                f"signature={sig['msg']} dport={dport} "
                f"payload_snippet={payload_snippet} qname={qname_snippet}"
            )

            self._alert(
                rule_id=str(sig["sid"]),
                severity=str(sig["severity"]),
                message=str(sig["msg"]),
                pkt=pkt,
                evidence=evidence,
                pcap_events=[self._mini(pkt)],
                mitre=str(sig.get("mitre", "")),
                rate_limit=float(sig.get("rate_limit_seconds", 30)),
                ts=ts,
            )

    def _random_client(self) -> str:
        return f"10.20.{self.rng.randint(0, 255)}.{self.rng.randint(2, 254)}"

    def _random_server(self) -> str:
        return f"10.10.0.{self.rng.randint(2, 20)}"

    def _random_client6(self) -> str:
        return f"2001:db8:20::{self.rng.randint(2, 999):x}"

    def _random_server6(self) -> str:
        return f"2001:db8:10::{self.rng.randint(2, 50):x}"

    def _make_benign_event(self, ts: float) -> Dict[str, Any]:
        ipv6 = self.rng.random() < 0.06
        src = self._random_client6() if ipv6 else self._random_client()
        dst = self._random_server6() if ipv6 else self._random_server()
        proto = self.rng.choice([6, 6, 6, 17, 17, 1])

        event: Dict[str, Any] = {
            "ts": ts,
            "src": src,
            "dst": dst,
            "proto": proto,
            "label": "benign",
            "len": self.rng.randint(60, 1400),
        }

        if proto == 6:
            event["sport"] = self.rng.randint(1024, 65535)
            event["dport"] = self.rng.choice([80, 443, 22, 53, 8080, 3306])
            event["seq"] = self.rng.randint(0, 1_000_000)
            event["ack"] = self.rng.randint(0, 1_000_000)
            event["flags"] = self.rng.choice(["S", "A", "PA", "FA", "A"])

            if event["dport"] == 80:
                event["payload"] = self.rng.choice(
                    [
                        "GET /index.html HTTP/1.1",
                        "GET /api/status HTTP/1.1",
                        "POST /api/login HTTP/1.1",
                    ]
                )
            elif event["dport"] == 443:
                event["payload"] = ""
            elif event["dport"] == 22 and self.rng.random() < 0.2:
                event["payload"] = "SSH-2.0-OpenSSH_9.2"

            if self.rng.random() < 0.02:
                event["frag_id"] = self.rng.randint(1, 65535)
                event["frag_offset"] = 0
                event["more_fragments"] = True

        elif proto == 17:
            event["sport"] = self.rng.randint(1024, 65535)
            event["dport"] = self.rng.choice([53, 123, 500, 5353])
            if event["dport"] == 53:
                event["qname"] = self.rng.choice(
                    [
                        "example.com",
                        "internal.corp",
                        "cdn.example.net",
                        "updates.vendor.com",
                    ]
                )
        else:
            event["payload"] = "echo-request"

        if self.rng.random() < 0.004:
            event.pop("src", None)

        return event

    def _maybe_start_attacks(self, now: float) -> None:
        if now < self.next_attack:
            return

        cycle = float(self.config["demo"].get("attack_cycle_seconds", 70))
        base = now + 1.0
        cycle_id = int(self.counters.get("attack_cycles", 0))
        self.counters["attack_cycles"] += 1

        allowed_src = self._choose_allowed_scanner()
        authorized_dst = "2001:db8:10::11" if ":" in allowed_src else "10.10.0.11"

        self.attack_states["port_scan"] = {
            "start": base,
            "end": base + 4.0,
            "port": 1,
            "src": "203.0.113.77",
            "dst": "10.10.0.5",
            "attack_id": f"port_scan_{cycle_id}",
        }

        self.attack_states["syn_flood"] = {
            "start": base + 6.0,
            "end": base + 9.0,
            "src": "198.51.100.66",
            "dst": "10.10.0.7",
            "attack_id": f"syn_flood_{cycle_id}",
        }

        self.attack_states["signature"] = {
            "start": base + 11.0,
            "end": base + 12.5,
            "count": 0,
            "src": "203.0.113.99",
            "dst": "10.10.0.9",
            "attack_id": f"signature_{cycle_id}",
        }

        self.attack_states["authorized"] = {
            "start": base + 15.0,
            "end": base + 16.5,
            "port": 1,
            "src": allowed_src,
            "dst": authorized_dst,
            "attack_id": f"authorized_{cycle_id}",
        }

        self.counters["attack_incidents"] += 3
        self.next_attack = now + cycle

    def _process_attack_states(self, now: float, duration: float) -> None:
        for name, state in list(self.attack_states.items()):
            if now < state["start"] or now > state["end"]:
                if now > state["end"]:
                    self.attack_states.pop(name, None)
                continue

            if name == "port_scan":
                total_ports = 1000
                dur = max(0.1, state["end"] - state["start"])
                count = int(total_ports / dur * duration) + 1
                for _ in range(count):
                    port = int(state.get("port", 1))
                    if port > total_ports:
                        break
                    ev = {
                        "ts": now + self.rng.uniform(0, duration),
                        "src": state["src"],
                        "dst": state["dst"],
                        "proto": 6,
                        "sport": 40000 + (port % 20000),
                        "dport": port,
                        "flags": "S",
                        "label": "attack",
                        "attack_id": state["attack_id"],
                        "len": 60,
                        "payload": "",
                    }
                    self.ingest(ev, source="demo")
                    state["port"] = port + 1
                if int(state.get("port", 1)) > total_ports:
                    self.attack_states.pop(name, None)

            elif name == "syn_flood":
                dur = max(0.1, state["end"] - state["start"])
                count = int(350 / dur * duration) + 1
                for _ in range(count):
                    ev = {
                        "ts": now + self.rng.uniform(0, duration),
                        "src": state["src"],
                        "dst": state["dst"],
                        "proto": 6,
                        "sport": self.rng.randint(1024, 65535),
                        "dport": 443,
                        "flags": "S",
                        "label": "attack",
                        "attack_id": state["attack_id"],
                        "len": 60,
                        "payload": "",
                    }
                    self.ingest(ev, source="demo")

            elif name == "signature":
                count = int(state.get("count", 0))
                ev = None
                if count == 0:
                    ev = {
                        "ts": now,
                        "src": state["src"],
                        "dst": state["dst"],
                        "proto": 6,
                        "sport": 40001,
                        "dport": 80,
                        "flags": "PA",
                        "payload": "GET /../../etc/passwd HTTP/1.1",
                        "label": "attack",
                        "attack_id": state["attack_id"],
                        "len": 120,
                    }
                elif count == 1:
                    ev = {
                        "ts": now + 0.05,
                        "src": state["src"],
                        "dst": state["dst"],
                        "proto": 6,
                        "sport": 40002,
                        "dport": 8080,
                        "flags": "PA",
                        "payload": "GET /etc/passwd HTTP/1.1",
                        "label": "attack",
                        "attack_id": state["attack_id"],
                        "len": 110,
                    }
                elif count == 2:
                    ev = {
                        "ts": now + 0.10,
                        "src": state["src"],
                        "dst": "10.10.0.2",
                        "proto": 17,
                        "sport": 5353,
                        "dport": 53,
                        "qname": ("a" * 70) + ".exfil.example",
                        "payload": "",
                        "label": "attack",
                        "attack_id": state["attack_id"],
                        "len": 130,
                    }
                elif count == 3:
                    ev = {
                        "ts": now + 0.15,
                        "src": "10.20.30.40",
                        "dst": "203.0.113.123",
                        "proto": 6,
                        "sport": 40111,
                        "dport": 6697,
                        "flags": "PA",
                        "payload": "",
                        "label": "attack",
                        "attack_id": state["attack_id"],
                        "len": 90,
                    }

                if ev:
                    self.ingest(ev, source="demo")

                state["count"] = count + 1
                if int(state["count"]) >= 5:
                    self.attack_states.pop(name, None)

            elif name == "authorized":
                dur = max(0.1, state["end"] - state["start"])
                count = int(120 / dur * duration) + 1
                for _ in range(count):
                    port = int(state.get("port", 1))
                    if port > 200:
                        break
                    ev = {
                        "ts": now + self.rng.uniform(0, duration),
                        "src": state["src"],
                        "dst": state["dst"],
                        "proto": 6,
                        "sport": 50000 + port,
                        "dport": port,
                        "flags": "S",
                        "label": "scanner",
                        "len": 60,
                        "payload": "",
                    }
                    self.ingest(ev, source="demo")
                    state["port"] = port + 1
                if int(state.get("port", 1)) > 200:
                    self.attack_states.pop(name, None)

    def _generate_demo_chunk(self, now: float, duration: float) -> None:
        self._maybe_start_attacks(now)

        eps = float(self.config["demo"].get("events_per_second", 80))
        n = max(1, int(eps * duration * self.rng.uniform(0.7, 1.3)))

        for _ in range(n):
            ts = now + self.rng.uniform(0, duration)
            ev = self._make_benign_event(ts)
            self.ingest(ev, source="demo")

            if ev.get("proto") == 6 and ev.get("flags") == "S" and ev.get("src") and self.rng.random() < 0.9:
                synack = dict(ev)
                synack["src"], synack["dst"] = ev["dst"], ev["src"]
                synack["sport"], synack["dport"] = ev.get("dport"), ev.get("sport")
                synack["flags"] = "SA"
                synack["ts"] = ts + 0.001
                self.ingest(synack, source="demo")

        if self.rng.random() < 0.03:
            with self.lock:
                self.counters["drops"] += self.rng.randint(0, 3)

        self._process_attack_states(now, duration)

    def _live_capture_once(self) -> None:
        if sniff is None:
            time.sleep(0.2)
            return

        cfg = self.config.get("capture", {})
        iface = cfg.get("interface") or None
        bpf = cfg.get("bpf_filter") or None

        try:
            packets = sniff(iface=iface, filter=bpf, timeout=1, store=1)
            for packet in packets:
                self.ingest_scapy(packet, source="live")
        except Exception:
            with self.lock:
                self.counters["capture_errors"] += 1

    def ingest_scapy(self, packet: Any, source: str = "live") -> None:
        try:
            ts = float(getattr(packet, "time", time.time()))
            event: Dict[str, Any] = {"ts": ts, "label": "unknown", "len": len(packet)}

            if IP is not None and packet.haslayer(IP):
                event["src"] = packet[IP].src
                event["dst"] = packet[IP].dst
                event["proto"] = packet[IP].proto
                if packet[IP].frag:
                    event["frag_offset"] = packet[IP].frag
                    event["more_fragments"] = bool(packet[IP].flags.MF)
            elif IPv6 is not None and packet.haslayer(IPv6):
                event["src"] = packet[IPv6].src
                event["dst"] = packet[IPv6].dst
                event["proto"] = packet[IPv6].nh
            else:
                with self.lock:
                    self.counters["unsupported_packets"] += 1
                return

            if TCP is not None and packet.haslayer(TCP):
                event["sport"] = packet[TCP].sport
                event["dport"] = packet[TCP].dport
                event["flags"] = str(packet[TCP].flags)
                event["seq"] = packet[TCP].seq
                event["ack"] = packet[TCP].ack
            elif UDP is not None and packet.haslayer(UDP):
                event["sport"] = packet[UDP].sport
                event["dport"] = packet[UDP].dport

            if Raw is not None and packet.haslayer(Raw):
                event["payload"] = bytes(packet[Raw].load)[:200].decode("utf-8", "ignore")

            self.ingest(event, source=source)
        except Exception:
            with self.lock:
                self.counters["parser_errors"] += 1

    def _insert_metrics(
        self,
        ts: float,
        pps: float,
        mbps: float,
        alerts: float,
        drop_rate: float,
        cpu: float,
        mem: float,
    ) -> None:
        iso = utc_iso(ts)
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT INTO metrics(ts, pps, mbps, alerts, drop_rate, cpu, mem) VALUES(?,?,?,?,?,?,?)",
                (iso, float(pps), float(mbps), float(alerts), float(drop_rate), float(cpu), float(mem)),
            )

        self.metrics.append(
            {
                "ts": float(ts),
                "iso": iso,
                "pps": float(pps),
                "mbps": float(mbps),
                "alerts": float(alerts),
                "drop_rate": float(drop_rate),
                "cpu": float(cpu),
                "mem": float(mem),
            }
        )

    def _update_metrics(self, now: float) -> None:
        with self.lock:
            if self._metric_last is None:
                self._metric_last = {
                    "ts": now,
                    "packets": self.counters.get("packets", 0.0),
                    "bytes": self.counters.get("bytes", 0.0),
                    "alerts": self.counters.get("alerts_total", 0.0),
                    "drops": self.counters.get("drops", 0.0),
                }
                return

            last = self._metric_last
            interval = max(0.2, now - float(last["ts"]))
            packets = max(0.0, self.counters.get("packets", 0.0) - float(last["packets"]))
            bytes_ = max(0.0, self.counters.get("bytes", 0.0) - float(last["bytes"]))
            alerts = max(0.0, self.counters.get("alerts_total", 0.0) - float(last["alerts"]))
            drops = max(0.0, self.counters.get("drops", 0.0) - float(last["drops"]))

            pps = packets / interval
            mbps = bytes_ * 8.0 / interval / 1_000_000.0
            denom = packets + drops
            drop_rate = 0.0 if denom <= 0 else drops / denom * 100.0

            max_pps = float(self.config["capture"].get("max_pps", 20000))
            if pps > max_pps:
                self.counters["drops"] += int(pps / 50)

            cpu = self.rng.uniform(3, 20)
            mem = self.rng.uniform(70, 180)
            if psutil is not None:
                try:
                    proc = psutil.Process()
                    cpu = proc.cpu_percent(None)
                    mem = proc.memory_info().rss / 1_000_000.0
                except Exception:
                    pass

            self._insert_metrics(now, pps, mbps, alerts, drop_rate, cpu, mem)

            self._metric_last = {
                "ts": now,
                "packets": self.counters.get("packets", 0.0),
                "bytes": self.counters.get("bytes", 0.0),
                "alerts": self.counters.get("alerts_total", 0.0),
                "drops": self.counters.get("drops", 0.0),
            }

    def _run(self) -> None:
        if psutil is not None:
            try:
                psutil.Process().cpu_percent(None)
            except Exception:
                pass

        while self.running:
            now = time.time()
            try:
                mode = self.config.get("mode", "demo")
                if mode == "demo":
                    self._generate_demo_chunk(now, 0.20)
                elif mode == "live" and sniff is not None:
                    self._live_capture_once()
                else:
                    time.sleep(0.2)
            except Exception:
                with self.lock:
                    self.counters["runtime_errors"] += 1

            now2 = time.time()
            if now2 - self._last_metrics_run >= 1.0:
                self._update_metrics(now2)
                self._last_metrics_run = now2

            time.sleep(0.2)

    def _seed_demo_history(self) -> None:
        now = time.time()

        for i in range(240, 0, -4):
            ts = now - i
            pps = self.rng.uniform(1500, 6000)
            mbps = pps * self.rng.uniform(0.004, 0.010)
            alerts = self.rng.randint(0, 2)
            drop_rate = self.rng.uniform(0, 0.8)
            cpu = self.rng.uniform(4, 22)
            mem = self.rng.uniform(70, 160)
            self._insert_metrics(ts, pps, mbps, alerts, drop_rate, cpu, mem)

        self.counters["packets"] = 850000
        self.counters["bytes"] = 70_000_000
        self.counters["benign_flows"] = 14500
        self.counters["attack_incidents"] = 28
        self.counters["detected_incidents"] = 27
        self.counters["false_positives"] = 1
        self.counters["drops"] = 120
        self.counters["parser_errors"] = 8
        self.counters["clock_skew"] = 2
        self.counters["fragments"] = 430
        self.counters["reassembled"] = 415

        seed_alerts = [
            {
                "ts": now - 220,
                "rule_id": "PORT_SCAN",
                "severity": "high",
                "message": "Possible port scan",
                "src": "198.51.100.23",
                "dst": "10.10.0.5",
                "evidence": "distinct_ports=132 window=10s sample=22,80,443,445",
                "mitre": "TA0007 Discovery",
                "proto": 6,
                "dport": 443,
            },
            {
                "ts": now - 180,
                "rule_id": "SYN_FLOOD",
                "severity": "critical",
                "message": "Possible SYN flood",
                "src": "198.51.100.66",
                "dst": "10.10.0.7",
                "evidence": "syn=420 synack=2 window=5s",
                "mitre": "T1498 Network Denial of Service",
                "proto": 6,
                "dport": 443,
            },
            {
                "ts": now - 120,
                "rule_id": "2000001",
                "severity": "high",
                "message": "HTTP LFI attempt /etc/passwd",
                "src": "203.0.113.99",
                "dst": "10.10.0.9",
                "evidence": "payload_snippet=GET /../../etc/passwd HTTP/1.1",
                "mitre": "T1190 Exploit Public-Facing Application",
                "proto": 6,
                "dport": 80,
            },
            {
                "ts": now - 70,
                "rule_id": "2000002",
                "severity": "medium",
                "message": "DNS unusually long query name",
                "src": "10.20.14.9",
                "dst": "10.10.0.2",
                "evidence": "qname_len=71",
                "mitre": "T1071.004 DNS",
                "proto": 17,
                "dport": 53,
            },
            {
                "ts": now - 25,
                "rule_id": "2000004",
                "severity": "low",
                "message": "Outbound TLS or C2-like traffic on rare high port",
                "src": "10.20.30.40",
                "dst": "203.0.113.123",
                "evidence": "dport=6697 metadata_only",
                "mitre": "T1571 Non-Standard Port",
                "proto": 6,
                "dport": 6697,
            },
        ]

        for item in seed_alerts:
            fake_event = {
                "ts": item["ts"],
                "src": item["src"],
                "dst": item["dst"],
                "proto": item["proto"],
                "sport": 40000,
                "dport": item["dport"],
                "flags": "PA",
                "payload": item["evidence"],
            }
            self._insert_alert(
                ts=item["ts"],
                rule_id=item["rule_id"],
                severity=item["severity"],
                message=item["message"],
                src=item["src"],
                dst=item["dst"],
                evidence=item["evidence"],
                pcap_events=[fake_event],
                mitre=item["mitre"],
                latency_ms=15.0,
                label="attack",
                attack_id=None,
                count_stats=False,
            )

        self.counters["alerts_total"] = float(len(seed_alerts))
        self.counters["alerts_critical"] = 1.0
        self.counters["alerts_high"] = 2.0
        self.counters["alerts_medium"] = 1.0
        self.counters["alerts_low"] = 1.0

        self._append_audit("seed", "loaded synthetic historical demo data", actor="system")

    def update_config(self, cfg: Dict[str, Any]) -> None:
        with self.lock:
            self.config = copy.deepcopy(cfg)
            self.alerts = deque(self.alerts, maxlen=int(cfg["storage"]["max_alerts"]))
            self.metrics = deque(self.metrics, maxlen=int(cfg["storage"]["max_metrics"]))
        self._append_audit("config_update", "configuration updated by operator", actor="operator")

    def get_alerts_df(self) -> pd.DataFrame:
        with self.lock:
            rows = []
            for alert in self.alerts:
                row = {k: v for k, v in alert.items() if k != "pcap_bytes"}
                rows.append(row)
            return pd.DataFrame(rows)

    def get_metrics_df(self) -> pd.DataFrame:
        with self.lock:
            rows = list(self.metrics)
        df = pd.DataFrame(rows)
        if df.empty:
            return pd.DataFrame(columns=["dt", "pps", "mbps", "alerts", "drop_rate", "cpu", "mem"])
        df["dt"] = pd.to_datetime(df["iso"], utc=True, errors="coerce")
        return df

    def get_event_window_df(self) -> pd.DataFrame:
        with self.lock:
            rows = list(self.event_window)
        df = pd.DataFrame(rows)
        if df.empty:
            return pd.DataFrame(columns=["ts", "src", "dst", "proto", "dport", "label"])
        df["dt"] = pd.to_datetime(df["ts"], unit="s", utc=True, errors="coerce")
        return df.tail(250).iloc[::-1].reset_index(drop=True)

    def get_audit_df(self) -> pd.DataFrame:
        with self.lock:
            cur = self.conn.execute(
                "SELECT id, ts, actor, action, detail, hash FROM audit ORDER BY id DESC LIMIT 500"
            )
            rows = [dict(r) for r in cur.fetchall()]
        return pd.DataFrame(rows)

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        alert_id = int(alert_id)
        with self.lock:
            for alert in self.alerts:
                if int(alert.get("id", -1)) == alert_id:
                    return dict(alert)
        return None

    def get_rule_stats_df(self) -> pd.DataFrame:
        with self.lock:
            rows = []
            for rule_id, stats in self.rule_stats.items():
                rows.append(
                    {
                        "rule_id": rule_id,
                        "matches": stats["matches"],
                        "alerts": stats["alerts"],
                        "suppressed": stats["suppressed"],
                    }
                )
        return pd.DataFrame(rows)

    def anomaly_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            port_scan = {}
            for src, q in list(self.port_windows.items())[-12:]:
                port_scan[src] = len({p for _, p, _ in q})

            syn_flood = {}
            for server, win in list(self.syn_windows.items())[-12:]:
                syn_flood[server] = {
                    "syn": len(win["syn"]),
                    "synack": len(win["synack"]),
                }

            active_attacks = {}
            for name, state in self.attack_states.items():
                active_attacks[name] = {
                    k: v for k, v in state.items() if k not in {"packets", "state"}
                }

            return {
                "port_scan_windows": port_scan,
                "syn_flood_windows": syn_flood,
                "active_attack_states": active_attacks,
                "fragments": int(self.counters.get("fragments", 0)),
                "reassembled": int(self.counters.get("reassembled", 0)),
                "parser_errors": int(self.counters.get("parser_errors", 0)),
                "clock_skew_events": int(self.counters.get("clock_skew", 0)),
            }

    def ui_snapshot(self) -> Dict[str, Any]:
        with self.lock:
            latest_metrics = dict(self.metrics[0]) if self.metrics else None
            return {
                "counters": dict(self.counters),
                "latest_metrics": latest_metrics,
                "uptime_seconds": time.time() - self.started,
            }

    def quality_stats(self) -> Dict[str, float]:
        with self.lock:
            attack_incidents = max(1.0, float(self.counters.get("attack_incidents", 0)))
            detected_incidents = float(self.counters.get("detected_incidents", 0))
            detection_rate = min(100.0, detected_incidents / attack_incidents * 100.0)

            benign_flows = max(1.0, float(self.counters.get("benign_flows", 0)))
            false_positives = float(self.counters.get("false_positives", 0))
            fp_per_10k = false_positives / benign_flows * 10000.0

            latencies = [
                float(a.get("latency_ms", 0.0))
                for a in list(self.alerts)[:500]
                if a.get("latency_ms") is not None
            ]
            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

            packets = float(self.counters.get("packets", 0))
            drops = float(self.counters.get("drops", 0))
            packet_loss = drops / (packets + drops) * 100.0 if packets + drops > 0 else 0.0

            return {
                "detection_rate": detection_rate,
                "fp_per_10k": fp_per_10k,
                "avg_latency_ms": avg_latency,
                "packet_loss": packet_loss,
            }

    def verify_audit(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        with self.lock:
            cur = self.conn.execute(
                "SELECT ts, actor, action, detail, prev_hash, hash FROM audit ORDER BY id ASC LIMIT 5000"
            )
            rows = [dict(r) for r in cur.fetchall()]

        prev = hashlib.sha256(b"nids-audit-genesis").hexdigest()
        for row in rows:
            payload = f"{row['ts']}|{row['actor']}|{row['action']}|{row['detail']}|{row['prev_hash']}"
            calc = hashlib.sha256(payload.encode()).hexdigest()
            if row["prev_hash"] != prev or calc != row["hash"]:
                return False, row
            prev = row["hash"]

        return True, None


def get_engine() -> NIDSEngine:
    if "engine" not in st.session_state:
        cfg, errors = parse_config_text(DEFAULT_YAML)
        st.session_state.config_errors = errors
        st.session_state.config_text = DEFAULT_YAML
        st.session_state.engine = NIDSEngine(cfg, start=True, seed=True)
        st.session_state.role = cfg.get("ui", {}).get("default_role", "admin")
        st.session_state.auto_refresh = True
        st.session_state.refresh_seconds = float(cfg.get("ui", {}).get("refresh_seconds", 1.0))
    return st.session_state.engine


def prometheus_text(engine: NIDSEngine) -> str:
    snap = engine.ui_snapshot()
    quality = engine.quality_stats()
    counters = snap["counters"]

    lines = [
        "# HELP nids_packets_total Total packets observed",
        "# TYPE nids_packets_total counter",
        f"nids_packets_total {counters.get('packets', 0)}",
        "# HELP nids_bytes_total Total bytes observed",
        "# TYPE nids_bytes_total counter",
        f"nids_bytes_total {counters.get('bytes', 0)}",
        "# HELP nids_alerts_total Total alerts generated",
        "# TYPE nids_alerts_total counter",
        f"nids_alerts_total {counters.get('alerts_total', 0)}",
        "# HELP nids_drops_total Total dropped packets",
        "# TYPE nids_drops_total counter",
        f"nids_drops_total {counters.get('drops', 0)}",
        "# HELP nids_parser_errors_total Parser errors",
        "# TYPE nids_parser_errors_total counter",
        f"nids_parser_errors_total {counters.get('parser_errors', 0)}",
        "# HELP nids_detection_rate_percent Detection rate",
        "# TYPE nids_detection_rate_percent gauge",
        f"nids_detection_rate_percent {quality['detection_rate']:.2f}",
        "# HELP nids_false_positives_per_10k_flows False positives per 10k flows",
        "# TYPE nids_false_positives_per_10k_flows gauge",
        f"nids_false_positives_per_10k_flows {quality['fp_per_10k']:.4f}",
        "# HELP nids_avg_alert_latency_ms Average alert latency milliseconds",
        "# TYPE nids_avg_alert_latency_ms gauge",
        f"nids_avg_alert_latency_ms {quality['avg_latency_ms']:.2f}",
        "# HELP nids_packet_loss_percent Packet loss percent",
        "# TYPE nids_packet_loss_percent gauge",
        f"nids_packet_loss_percent {quality['packet_loss']:.4f}",
    ]
    return "\n".join(lines) + "\n"


def run_self_tests() -> pd.DataFrame:
    results: List[Dict[str, str]] = []

    def add_result(name: str, fn) -> None:
        try:
            fn()
            results.append({"test": name, "status": "PASS", "detail": ""})
        except Exception as exc:
            results.append({"test": name, "status": "FAIL", "detail": str(exc)})

    cfg, errors = parse_config_text(DEFAULT_YAML)
    if errors:
        return pd.DataFrame([{"test": "config_parse", "status": "FAIL", "detail": "; ".join(errors)}])

    def test_config_validation():
        bad = copy.deepcopy(cfg)
        bad["mode"] = "invalid-mode"
        errs = validate_config(bad)
        assert errs, "expected validation errors"

    def test_pcap_builder():
        ev = {
            "ts": time.time(),
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "proto": 6,
            "sport": 1234,
            "dport": 80,
            "flags": "S",
            "payload": "test",
        }
        data = build_pcap([ev])
        assert data[:4] == struct.pack("<I", 0xA1B2C3D4), "bad pcap magic"

    def test_port_scan():
        engine = NIDSEngine(cfg, start=False, seed=False)
        now = time.time()
        for port in range(1, 130):
            engine.ingest(
                {
                    "ts": now,
                    "src": "10.9.9.9",
                    "dst": "10.8.8.8",
                    "proto": 6,
                    "sport": 1000 + port,
                    "dport": port,
                    "flags": "S",
                    "label": "attack",
                    "attack_id": "test-port-scan",
                },
                source="test",
            )
        df = engine.get_alerts_df()
        assert not df.empty and (df["rule_id"] == "PORT_SCAN").any(), "port scan not detected"

    def test_allowlist_suppression():
        cfg2 = copy.deepcopy(cfg)
        cfg2["allowlist_scanners"] = ["10.7.7.7"]
        engine = NIDSEngine(cfg2, start=False, seed=False)
        now = time.time()
        for port in range(1, 130):
            engine.ingest(
                {
                    "ts": now,
                    "src": "10.7.7.7",
                    "dst": "10.8.8.8",
                    "proto": 6,
                    "sport": 2000 + port,
                    "dport": port,
                    "flags": "S",
                    "label": "scanner",
                },
                source="test",
            )
        df = engine.get_alerts_df()
        assert df.empty or not (df["rule_id"] == "PORT_SCAN").any(), "allowlisted scanner alerted"

    def test_syn_flood():
        engine = NIDSEngine(cfg, start=False, seed=False)
        now = time.time()
        for i in range(350):
            engine.ingest(
                {
                    "ts": now + i * 0.001,
                    "src": "10.1.1.1",
                    "dst": "10.2.2.2",
                    "proto": 6,
                    "sport": 1000 + i,
                    "dport": 443,
                    "flags": "S",
                    "label": "attack",
                    "attack_id": "test-syn-flood",
                },
                source="test",
            )
        df = engine.get_alerts_df()
        assert not df.empty and (df["rule_id"] == "SYN_FLOOD").any(), "syn flood not detected"

    add_result("config_validation", test_config_validation)
    add_result("pcap_builder", test_pcap_builder)
    add_result("port_scan_detection", test_port_scan)
    add_result("allowlist_suppression", test_allowlist_suppression)
    add_result("syn_flood_detection", test_syn_flood)

    return pd.DataFrame(results)


RECORDER_HTML = """
<div style="font-family: sans-serif; padding: 8px;">
  <button id="recordBtn" style="padding: 10px 14px; font-size: 16px;">
    Start 60-second screen recording
  </button>
  <p id="status" style="margin-top: 8px; color: #444;">
    Click the button, choose screen/tab to share, and the recording will automatically stop and download after 60 seconds.
  </p>
  <video id="preview" controls style="width: 100%; margin-top: 10px; display: none;"></video>
</div>

<script>
const btn = document.getElementById('recordBtn');
const status = document.getElementById('status');
const preview = document.getElementById('preview');
let recorder = null;
let chunks = [];

btn.addEventListener('click', async () => {
  try {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      status.innerText = 'Browser screen capture is not available here. Use your OS screen recorder.';
      return;
    }

    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
    chunks = [];

    recorder = new MediaRecorder(stream, { mimeType: 'video/webm' });

    recorder.ondataavailable = function(e) {
      if (e.data && e.data.size > 0) {
        chunks.push(e.data);
      }
    };

    recorder.onstop = function() {
      const blob = new Blob(chunks, { type: 'video/webm' });
      const url = URL.createObjectURL(blob);

      const a = document.createElement('a');
      a.href = url;
      a.download = 'nids_demo.webm';
      document.body.appendChild(a);
      a.click();
      a.remove();

      preview.src = url;
      preview.style.display = 'block';
      status.innerText = 'Recording complete. Download started.';

      stream.getTracks().forEach(function(track) { track.stop(); });
    };

    recorder.start();
    btn.disabled = true;
    status.innerText = 'Recording... will stop automatically in 60 seconds.';

    setTimeout(function() {
      if (recorder && recorder.state === 'recording') {
        recorder.stop();
        btn.disabled = false;
      }
    }, 60000);

  } catch (err) {
    status.innerText = 'Screen capture was blocked or failed. Use your OS screen recorder instead.';
  }
});
</script>
"""


engine = get_engine()

st.title("🛡️ Defensive Network Intrusion Detection System")
st.caption(
    "Defensive lab demo. Synthetic traffic is loaded automatically and the simulation starts immediately. "
    "No blocking is performed by default."
)

with st.sidebar:
    st.header("Control")

    role_options = ["viewer", "operator", "admin"]
    current_role = st.session_state.get("role", "admin")
    role_index = role_options.index(current_role) if current_role in role_options else 2
    st.session_state.role = st.selectbox("Role", role_options, index=role_index)

    st.session_state.auto_refresh = st.checkbox(
        "Live refresh",
        value=bool(st.session_state.get("auto_refresh", True)),
    )

    st.session_state.refresh_seconds = st.slider(
        "Refresh interval (seconds)",
        min_value=0.5,
        max_value=5.0,
        value=float(st.session_state.get("refresh_seconds", 1.0)),
        step=0.5,
    )

    if st.button("Pause refresh for video recording"):
        st.session_state.auto_refresh = False
        st.rerun()

    if st.button("Resume live refresh"):
        st.session_state.auto_refresh = True
        st.rerun()

    snap_sidebar = engine.ui_snapshot()
    st.metric("Uptime", f"{snap_sidebar['uptime_seconds']:.0f} s")
    st.metric("Mode", engine.config.get("mode", "demo"))
    st.metric("Role", st.session_state.role)

    with st.expander("Ethics and scope"):
        st.write(
            "Defensive use only. Run only on systems you own or are authorized to test. "
            "This demo uses synthetic data by default. Live capture requires explicit authorization."
        )

snapshot = engine.ui_snapshot()
quality = engine.quality_stats()
latest_metrics = snapshot["latest_metrics"]

m1, m2, m3, m4, m5, m6, m7, m8 = st.columns(8)

m1.metric("PPS", f"{latest_metrics['pps']:,.0f}" if latest_metrics else "0")
m2.metric("Mbps", f"{latest_metrics['mbps']:,.1f}" if latest_metrics else "0")
m3.metric("Alerts", int(snapshot["counters"].get("alerts_total", 0)))
m4.metric("Packet loss", f"{quality['packet_loss']:.2f}%")
m5.metric("CPU %", f"{latest_metrics['cpu']:.1f}" if latest_metrics else "0")
m6.metric("Mem MB", f"{latest_metrics['mem']:.0f}" if latest_metrics else "0")
m7.metric("Detection rate", f"{quality['detection_rate']:.1f}%")
m8.metric("FP / 10k flows", f"{quality['fp_per_10k']:.2f}")

tabs = st.tabs(
    [
        "Live Overview",
        "Alerts",
        "Anomalies",
        "Rules",
        "Replay & Config",
        "Quality & Metrics",
        "Audit",
        "Self Tests",
        "Demo Video",
    ]
)

with tabs[0]:
    st.subheader("Live Overview")

    alerts_df = engine.get_alerts_df()
    events_df = engine.get_event_window_df()

    if alerts_df.empty:
        st.info("No alerts yet. The live simulation is still running.")
    else:
        alerts_df["dt"] = pd.to_datetime(alerts_df["timestamp"], utc=True, errors="coerce")

        chart_df = alerts_df.dropna(subset=["dt"]).copy()
        if not chart_df.empty:
            chart_df["severity_rank"] = chart_df["severity"].map(SEVERITY_ORDER).fillna(9)
            chart_df = chart_df.sort_values(["dt", "severity_rank"])

            alert_series = chart_df.groupby(pd.Grouper(key="dt", freq="1min")).size().reset_index(name="count")
            fig_alerts = px.area(
                alert_series,
                x="dt",
                y="count",
                title="Alerts per minute",
                labels={"count": "alerts"},
            )
            st.plotly_chart(fig_alerts, use_container_width=True)

            severity_series = (
                chart_df.groupby([pd.Grouper(key="dt", freq="1min"), "severity"])
                .size()
                .reset_index(name="count")
            )
            if not severity_series.empty:
                fig_sev = px.area(
                    severity_series,
                    x="dt",
                    y="count",
                    color="severity",
                    title="Alert severity trend",
                    category_orders={"severity": ["critical", "high", "medium", "low", "info"]},
                )
                st.plotly_chart(fig_sev, use_container_width=True)

            top_src = chart_df["src"].value_counts().head(10).reset_index()
            top_src.columns = ["src", "alerts"]
            fig_src = px.bar(top_src, x="alerts", y="src", orientation="h", title="Top alert sources")
            fig_src.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig_src, use_container_width=True)

    if not events_df.empty:
        events_df["proto_name"] = events_df["proto"].map({1: "ICMP", 6: "TCP", 17: "UDP"}).fillna("OTHER")
        proto_counts = events_df["proto_name"].value_counts().reset_index()
        proto_counts.columns = ["proto", "count"]
        fig_proto = px.pie(proto_counts, names="proto", values="count", title="Recent protocol distribution")
        st.plotly_chart(fig_proto, use_container_width=True)

        st.subheader("Recent event feed")
        st.dataframe(
            events_df[["dt", "src", "dst", "proto_name", "dport", "label"]].head(100),
            use_container_width=True,
        )

with tabs[1]:
    st.subheader("Alerts")

    alerts_df = engine.get_alerts_df()

    if alerts_df.empty:
        st.info("No alerts currently stored.")
    else:
        alerts_df["dt"] = pd.to_datetime(alerts_df["timestamp"], utc=True, errors="coerce")

        f1, f2, f3, f4 = st.columns([2, 2, 2, 1])

        severities = sorted(alerts_df["severity"].unique().tolist(), key=lambda x: SEVERITY_ORDER.get(x, 9))
        default_sev = [s for s in ["critical", "high"] if s in severities] or severities

        with f1:
            sev_filter = st.multiselect("Severity", severities, default=default_sev)

        with f2:
            rule_filter = st.multiselect("Rule", sorted(alerts_df["rule_id"].unique().tolist()))

        with f3:
            search = st.text_input("Search src / dst / message")

        with f4:
            window = st.select_slider(
                "Window (minutes)",
                options=[5, 15, 60, 240, 99999],
                value=60,
                format_func=lambda x: "All" if x == 99999 else str(x),
            )

        filtered = alerts_df.copy()

        if sev_filter:
            filtered = filtered[filtered["severity"].isin(sev_filter)]

        if rule_filter:
            filtered = filtered[filtered["rule_id"].isin(rule_filter)]

        if search:
            text = search.lower()
            filtered = filtered[
                filtered["src"].str.lower().str.contains(text, na=False)
                | filtered["dst"].str.lower().str.contains(text, na=False)
                | filtered["message"].str.lower().str.contains(text, na=False)
            ]

        if window != 99999:
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=int(window))
            filtered = filtered[filtered["dt"] >= cutoff]

        filtered = filtered.sort_values("dt", ascending=False)

        st.dataframe(
            filtered.drop(columns=["dt", "prev_hash", "alert_hash"]).head(500),
            use_container_width=True,
        )

        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "Download filtered alerts CSV",
                filtered.drop(columns=["dt"]).to_csv(index=False).encode(),
                file_name="nids_alerts.csv",
                mime="text/csv",
            )
        with d2:
            st.download_button(
                "Download filtered alerts JSON",
                filtered.drop(columns=["dt"]).to_json(orient="records", date_format="iso").encode(),
                file_name="nids_alerts.json",
                mime="application/json",
            )

        st.divider()
        st.subheader("Alert detail and pcap slice")

        max_id = int(alerts_df["id"].max())
        default_id = int(filtered.iloc[0]["id"]) if not filtered.empty else max_id

        alert_id = st.number_input(
            "Alert ID",
            min_value=1,
            max_value=max_id,
            value=default_id,
            step=1,
        )

        alert = engine.get_alert_by_id(alert_id)
        if alert:
            display_alert = {k: v for k, v in alert.items() if k != "pcap_bytes"}
            st.json(display_alert)

            if alert.get("pcap_bytes"):
                st.download_button(
                    "Download pcap slice for this alert",
                    alert["pcap_bytes"],
                    file_name=f"alert_{alert_id}.pcap",
                    mime="application/vnd.tcpdump.pcap",
                )
            else:
                st.caption("No pcap slice available for this alert.")
        else:
            st.warning("Alert ID not found.")

with tabs[2]:
    st.subheader("Anomaly detection state")

    anomaly = engine.anomaly_snapshot()

    left, right = st.columns(2)

    with left:
        st.markdown("**Port scan windows**")
        if anomaly["port_scan_windows"]:
            st.dataframe(pd.DataFrame(anomaly["port_scan_windows"].items(), columns=["src", "distinct_ports"]))
        else:
            st.caption("No active port scan windows.")

        st.markdown("**SYN flood windows**")
        if anomaly["syn_flood_windows"]:
            syn_df = pd.DataFrame(anomaly["syn_flood_windows"].items(), columns=["server", "state"])
            syn_df["syn"] = syn_df["state"].map(lambda x: x.get("syn", 0))
            syn_df["synack"] = syn_df["state"].map(lambda x: x.get("synack", 0))
            st.dataframe(syn_df.drop(columns=["state"]))
        else:
            st.caption("No active SYN flood windows.")

    with right:
        st.markdown("**Active demo attack states**")
        if anomaly["active_attack_states"]:
            st.json(anomaly["active_attack_states"])
        else:
            st.caption("No active attack states at this instant.")

        st.markdown("**Failure-mode counters**")
        st.json(
            {
                "fragments": anomaly["fragments"],
                "reassembled": anomaly["reassembled"],
                "parser_errors": anomaly["parser_errors"],
                "clock_skew_events": anomaly["clock_skew_events"],
            }
        )

with tabs[3]:
    st.subheader("Signature and threshold rules")

    sig_df = pd.DataFrame(engine.signatures)
    st.dataframe(sig_df, use_container_width=True)

    st.subheader("Rule statistics")
    rule_stats_df = engine.get_rule_stats_df()
    if rule_stats_df.empty:
        st.caption("No rule statistics yet.")
    else:
        st.dataframe(rule_stats_df, use_container_width=True)

    st.subheader("Threshold configuration")
    st.json(engine.config.get("detection", {}))

with tabs[4]:
    st.subheader("Pcap replay and configuration")

    left, right = st.columns(2)

    with left:
        st.markdown("**Pcap replay**")
        if rdpcap is None:
            st.warning("Scapy is not installed, so pcap replay is unavailable in this environment.")
        else:
            uploaded = st.file_uploader("Upload pcap / pcapng", type=["pcap", "pcapng"])
            if uploaded is not None and st.session_state.role in {"operator", "admin"}:
                if st.button("Replay uploaded pcap"):
                    tmp_path = None
                    try:
                        suffix = os.path.splitext(uploaded.name)[1] or ".pcap"
                        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                            tmp.write(uploaded.getvalue())
                            tmp_path = tmp.name

                        packets = rdpcap(tmp_path)
                        for packet in packets:
                            engine.ingest_scapy(packet, source="replay")

                        st.success(f"Replayed {len(packets)} packets into the detection engine.")
                        engine._append_audit(
                            "pcap_replay",
                            f"file={uploaded.name} packets={len(packets)}",
                            actor=st.session_state.role,
                        )
                    except Exception as exc:
                        st.error(f"Replay failed: {exc}")
                    finally:
                        if tmp_path and os.path.exists(tmp_path):
                            try:
                                os.remove(tmp_path)
                            except Exception:
                                pass
            elif uploaded is not None:
                st.info("Operator or admin role is required to replay pcaps.")

        st.markdown("**Live capture notice**")
        st.info(
            "Live capture requires mode=live, Scapy, and sufficient privileges. "
            "This demo defaults to synthetic mode to avoid unauthorized capture."
        )

    with right:
        st.markdown("**YAML configuration**")

        if "config_text" not in st.session_state:
            st.session_state.config_text = DEFAULT_YAML

        config_text = st.text_area("Config", st.session_state.config_text, height=320)

        if st.session_state.role == "admin":
            if st.button("Apply configuration"):
                cfg, errors = parse_config_text(config_text)
                if errors:
                    st.error("Config rejected: " + "; ".join(errors))
                else:
                    engine.update_config(cfg)
                    st.session_state.config_text = config_text
                    st.success("Configuration applied.")
        else:
            st.info("Admin role is required to change configuration.")

        with st.expander("Configuration schema summary"):
            st.json(
                {
                    "mode": ["demo", "live", "replay"],
                    "capture": ["interface", "bpf_filter", "promisc", "max_pps"],
                    "demo": ["events_per_second", "attack_cycle_seconds"],
                    "storage": ["max_alerts", "max_metrics", "window_minutes"],
                    "detection": ["port_scan", "syn_flood", "signatures"],
                    "allowlist_scanners": ["IP address or CIDR"],
                    "ui": ["refresh_seconds", "default_role"],
                }
            )

with tabs[5]:
    st.subheader("Quality targets and operational metrics")

    quality = engine.quality_stats()

    q1, q2, q3, q4 = st.columns(4)

    q1.metric("Detection rate", f"{quality['detection_rate']:.1f}%")
    q2.metric("False positives / 10k flows", f"{quality['fp_per_10k']:.2f}")
    q3.metric("Average alert latency", f"{quality['avg_latency_ms']:.0f} ms")
    q4.metric("Packet loss", f"{quality['packet_loss']:.2f}%")

    targets = pd.DataFrame(
        [
            {"target": "Detection rate >= 95%", "status": quality["detection_rate"] >= 95},
            {"target": "False positives <= 1 per 10k flows", "status": quality["fp_per_10k"] <= 1},
            {"target": "Alert latency <= 5000 ms", "status": quality["avg_latency_ms"] <= 5000},
            {"target": "Packet loss <= 1%", "status": quality["packet_loss"] <= 1},
        ]
    )
    targets["status"] = targets["status"].map({True: "PASS", False: "REVIEW"})
    st.dataframe(targets, use_container_width=True)

    metrics_df = engine.get_metrics_df()
    if not metrics_df.empty:
        c1, c2 = st.columns(2)
        with c1:
            fig_pps = px.line(metrics_df, x="dt", y="pps", title="Packets per second")
            st.plotly_chart(fig_pps, use_container_width=True)

            fig_mbps = px.line(metrics_df, x="dt", y="mbps", title="Mbps")
            st.plotly_chart(fig_mbps, use_container_width=True)

        with c2:
            fig_cpu = px.line(metrics_df, x="dt", y="cpu", title="CPU %")
            st.plotly_chart(fig_cpu, use_container_width=True)

            fig_mem = px.line(metrics_df, x="dt", y="mem", title="Memory MB")
            st.plotly_chart(fig_mem, use_container_width=True)

    st.download_button(
        "Download Prometheus metrics",
        prometheus_text(engine).encode(),
        file_name="nids_metrics.prom",
        mime="text/plain",
    )

with tabs[6]:
    st.subheader("Tamper-evident audit log")

    audit_df = engine.get_audit_df()
    if audit_df.empty:
        st.info("No audit entries yet.")
    else:
        st.dataframe(audit_df.head(250), use_container_width=True)

    if st.button("Verify audit hash chain"):
        ok, bad_row = engine.verify_audit()
        if ok:
            st.success("Audit hash chain is valid.")
        else:
            st.error("Audit hash chain validation failed.")
            st.json(bad_row)

with tabs[7]:
    st.subheader("Self tests")

    st.write("Runs compact in-process tests for configuration, pcap generation, detection, and allowlisting.")

    if st.button("Run self tests"):
        with st.spinner("Running self tests..."):
            test_df = run_self_tests()
        st.dataframe(test_df, use_container_width=True)

        if (test_df["status"] == "FAIL").any():
            st.error("One or more self tests failed.")
        else:
            st.success("All self tests passed.")

with tabs[8]:
    st.subheader("Live demo video recorder")

    st.write(
        "The dashboard is already live. To capture a real 60-second demo video, pause live refresh, "
        "then use the browser recorder below. The recording downloads as a WebM video file."
    )

    if st.session_state.auto_refresh:
        st.warning("Live refresh is currently enabled. Pause it first so the recorder is not reset.")
        if st.button("Pause refresh and enable recorder"):
            st.session_state.auto_refresh = False
            st.rerun()
    else:
        components.html(RECORDER_HTML, height=430)
        if st.button("Resume live refresh after recording"):
            st.session_state.auto_refresh = True
            st.rerun()

if st.session_state.get("auto_refresh", True):
    time.sleep(max(0.5, float(st.session_state.get("refresh_seconds", 1.0))))
    st.rerun()