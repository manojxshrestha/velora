"""Minimal OSINT (finalplan §3/§10 Phase 4): TLS certificate + DNS records.

Public-source discovery restricted to identifiers observed *for in-scope
hosts*: the peer certificate (subject / issuer / validity / SANs) and DNS
records (A/AAAA via the resolver, CNAME/MX/NS/TXT via a minimal UDP
query). Stdlib only. Every lookup degrades to a recorded error — never
fatal, never probing beyond the target host and the system resolver.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import struct
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

CAPABILITY = (
    "partial: TLS certificate + DNS records "
    "(no CT logs or search-engine feeds)"
)

_QTYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
_RAW_RTYPES = ("CNAME", "MX", "NS", "TXT")
_SAN_OID = b"\x55\x1d\x11"  # 2.5.29.17 subjectAltName (OID content)
_COMMON_NAME_OID = b"\x55\x04\x03"


# ---------------------------------------------------------------------------
# DNS: minimal stdlib UDP client (encode / send / parse)
# ---------------------------------------------------------------------------

def encode_query(name: str, rtype: str) -> Tuple[bytes, bytes]:
    """Build (transaction_id, wire_query) for `name`/`rtype` (A, MX, …)."""
    qtype = _QTYPE.get(rtype.upper())
    if qtype is None:
        raise ValueError(f"unsupported DNS record type: {rtype}")
    tid = os.urandom(2)
    labels = [label for label in str(name).strip().split(".") if label]
    encoded_labels = [label.encode("idna") for label in labels]
    qname = b"".join(
        bytes([len(label)]) + label for label in encoded_labels
    ) + b"\x00"
    header = tid + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack(">HH", qtype, 1)
    return tid, header + question


def decode_name(buf: bytes, offset: int, _depth: int = 0) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name; returns (name, next offset)."""
    if _depth > 20:
        raise ValueError("DNS name: compression pointer loop")
    labels: List[str] = []
    jumped = False
    end = offset
    while True:
        if offset >= len(buf):
            raise ValueError("DNS name: truncated")
        length = buf[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("DNS name: truncated pointer")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            tail, _ = decode_name(buf, offset, _depth + 1)
            labels.append(tail)
            break
        offset += 1
        if offset + length > len(buf):
            raise ValueError("DNS name: truncated label")
        labels.append(buf[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def parse_response(buf: bytes, expect_tid: bytes) -> Dict[str, object]:
    """Parse a DNS response → {"answers": {rtype: [str]}, "rcode": int}."""
    if len(buf) < 12:
        raise ValueError("DNS response: shorter than header")
    tid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if expect_tid and tid != struct.unpack(">H", expect_tid)[0]:
        raise ValueError("DNS response: transaction id mismatch")
    rcode = flags & 0x0F
    if not flags & 0x8000:
        raise ValueError("DNS response: not a reply")
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(buf, offset)
        offset += 4
    answers: Dict[str, List[str]] = {}
    for _ in range(an):
        _, offset = decode_name(buf, offset)
        if offset + 10 > len(buf):
            raise ValueError("DNS response: truncated answer header")
        rtype, rclass, _ttl, rdlength = struct.unpack(
            ">HHIH", buf[offset:offset + 10]
        )
        offset += 10
        rdata = buf[offset:offset + rdlength]
        if len(rdata) != rdlength:
            raise ValueError("DNS response: truncated rdata")
        data_offset = offset
        offset += rdlength
        if rclass != 1:
            continue
        value: Optional[str] = None
        if rtype == 1 and len(rdata) == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and len(rdata) == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5):  # NS / CNAME
            value, _ = decode_name(buf, data_offset)
        elif rtype == 15 and len(rdata) >= 3:  # MX
            preference = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = decode_name(buf, data_offset + 2)
            value = f"{preference} {exchange}"
        elif rtype == 16:  # TXT: length-prefixed chunks
            chunks: List[str] = []
            pos = 0
            while pos < len(rdata):
                size = rdata[pos]
                pos += 1
                chunks.append(
                    rdata[pos:pos + size].decode("utf-8", "replace")
                )
                pos += size
            value = "".join(chunks)
        if value is not None:
            name = _rtype_name(rtype)
            if name:
                answers.setdefault(name, []).append(value)
    return {"answers": answers, "rcode": rcode}


def _rtype_name(qtype: int) -> Optional[str]:
    for name, code in _QTYPE.items():
        if code == qtype:
            return name
    return None


def _resolver_ip() -> Tuple[Optional[str], Optional[str]]:
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8",
                  errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    candidate = parts[1].split("%")[0]
                    try:
                        if ipaddress.ip_address(candidate).version == 4:
                            return candidate, None
                    except ValueError:
                        continue
        return None, "no IPv4 nameserver configured in /etc/resolv.conf"
    except OSError as exc:
        return None, str(exc)


def dns_query(name: str, rtype: str, *,
              resolver: Optional[str] = None,
              timeout: float = 1.5) -> Tuple[List[str], Optional[str]]:
    """One UDP DNS lookup → (values, error). Errors are data, not raises."""
    if resolver is None:
        resolver, resolver_error = _resolver_ip()
        if resolver is None:
            return [], resolver_error
    try:
        tid, wire = encode_query(name, rtype)
    except (ValueError, UnicodeError) as exc:
        return [], str(exc)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(wire, (resolver, 53))
        buf, _ = sock.recvfrom(4096)
        parsed = parse_response(buf, tid)
    except (OSError, ValueError) as exc:
        return [], f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()
    if parsed["rcode"]:
        return [], f"rcode {parsed['rcode']}"
    values = parsed["answers"].get(rtype.upper()) or []
    if not values:
        return [], None  # NOERROR / NODATA is a normal answer
    return values, None


def _addresses(host: str) -> Tuple[List[str], List[str], Optional[str]]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        return [], [], str(exc)
    v4 = sorted({info[4][0] for info in infos
                 if len(info[4]) and ":" not in info[4][0]})
    v6 = sorted({info[4][0] for info in infos
                 if len(info[4]) and ":" in info[4][0]})
    return v4, v6, None


def dns_records(host: str, *, resolver: Optional[str] = None,
                timeout: float = 1.5) -> Dict[str, object]:
    """A/AAAA (resolver) + CNAME/MX/NS/TXT (UDP) for `host`."""
    record: Dict[str, object] = {}
    errors: Dict[str, str] = {}
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False

    if literal:
        if ":" in host:
            record["aaaa"] = [host]
        else:
            record["a"] = [host]
    else:
        v4, v6, resolve_error = _addresses(host)
        if resolve_error:
            errors["resolve"] = resolve_error
        if v4:
            record["a"] = v4
        if v6:
            record["aaaa"] = v6
        for rtype in _RAW_RTYPES:
            values, error = dns_query(host, rtype, resolver=resolver,
                                      timeout=timeout)
            if error:
                errors[rtype.lower()] = error
            elif values:
                record[rtype.lower()] = values
    if errors:
        record["errors"] = errors
    return record


# ---------------------------------------------------------------------------
# TLS certificate: fetch (no verification) + minimal DER walk
# ---------------------------------------------------------------------------

def _tlv(buf: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(buf):
        raise ValueError("DER: truncated tag")
    tag = buf[offset]
    offset += 1
    if offset >= len(buf):
        raise ValueError("DER: truncated length")
    first = buf[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or offset + count > len(buf):
            raise ValueError("DER: bad length")
        length = int.from_bytes(buf[offset:offset + count], "big")
        offset += count
    if offset + length > len(buf):
        raise ValueError("DER: value overruns buffer")
    return tag, buf[offset:offset + length], offset + length


def _children(buf: bytes) -> List[Tuple[int, bytes]]:
    out: List[Tuple[int, bytes]] = []
    offset = 0
    while offset < len(buf):
        tag, value, offset = _tlv(buf, offset)
        out.append((tag, value))
    return out


def _name_cn(name_der: bytes) -> Optional[str]:
    for rdn_tag, rdn in _children(name_der):
        if rdn_tag != 0x31:  # SET
            continue
        for attr_tag, attr in _children(rdn):
            if attr_tag != 0x30:  # SEQUENCE { OID, value }
                continue
            parts = _children(attr)
            if len(parts) == 2 and parts[0][1] == _COMMON_NAME_OID:
                try:
                    return parts[1][1].decode("utf-8", "replace")
                except Exception:
                    return None
    return None


def _time(tag: int, value: bytes) -> str:
    text = value.decode("ascii", "replace")
    fmt = {0x17: "%y%m%d%H%M%SZ", 0x18: "%Y%m%d%H%M%SZ"}.get(tag)
    if fmt is None:
        return text
    try:
        moment = datetime.strptime(text, fmt)
    except ValueError:
        return text
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _san_names(a3_value: bytes) -> List[str]:
    names: List[str] = []
    for seq_tag, seq in _children(a3_value):
        if seq_tag != 0x30:
            continue
        for ext_tag, ext in _children(seq):
            if ext_tag != 0x30:
                continue
            parts = _children(ext)
            if not parts or parts[0][1] != _SAN_OID:
                continue
            octets = [v for t, v in parts if t == 0x04]
            if not octets:
                continue
            items = _children(octets[0])
            if len(items) == 1 and items[0][0] == 0x30:
                items = _children(items[0][1])  # unwrap SEQUENCE OF GeneralName
            for gen_tag, gen in items:
                if gen_tag == 0x82:  # dNSName
                    names.append(gen.decode("ascii", "replace"))
    return names


def parse_der_certificate(der: bytes) -> Dict[str, object]:
    """Extract subject / issuer / validity / SANs from a DER certificate."""
    if not der:
        raise ValueError("empty DER certificate")
    try:
        cert_tag, cert_val, _ = _tlv(der, 0)
        if cert_tag != 0x30:
            raise ValueError("outer element is not a SEQUENCE")
        tbs_tag, tbs_val, _ = _tlv(cert_val, 0)
        if tbs_tag != 0x30:
            raise ValueError("missing TBSCertificate")
        parts = _children(tbs_val)
        index = 1 if parts and parts[0][0] == 0xA0 else 0
        if len(parts) < index + 5:
            raise ValueError("TBSCertificate too short")
        validity = _children(parts[index + 3][1])
        if len(validity) < 2:
            raise ValueError("missing validity window")
        sans: List[str] = []
        for tag, value in parts[index + 5:]:
            if tag == 0xA3:
                sans = _san_names(value)
                break
        return {
            "subject": _name_cn(parts[index + 4][1]),
            "issuer": _name_cn(parts[index + 2][1]),
            "not_before": _time(*validity[0]),
            "not_after": _time(*validity[1]),
            "sans": sans,
        }
    except ValueError:
        raise
    except Exception as exc:  # defensive: parse failures are recorded upstream
        raise ValueError(f"certificate parse failed: {exc}") from exc


def fetch_certificate(host: str, port: int, *,
                      timeout: float = 2.0) -> Dict[str, object]:
    """TLS handshake without verification → parsed cert or {error: …}."""
    base: Dict[str, object] = {"host": host, "port": port}
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, int(port)),
                                      timeout=timeout) as raw:
            with context.wrap_socket(raw) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {**base, "error": f"{type(exc).__name__}: {exc}"}
    if not der:
        return {**base, "error": "no peer certificate presented"}
    try:
        parsed = parse_der_certificate(der)
    except ValueError as exc:
        return {**base, "error": str(exc)}
    return {**base, **parsed}


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def _identifier(identifiers: Dict[str, Dict], value: str,
                kind: str, host: str) -> None:
    if not value or len(value) > 253:
        return
    entry = identifiers.setdefault(
        value.lower(), {"value": value, "kinds": [], "hosts": []}
    )
    if kind not in entry["kinds"]:
        entry["kinds"].append(kind)
    if host not in entry["hosts"]:
        entry["hosts"].append(host)


def collect_osint(hosts: Sequence[str], *,
                  cert_ports: Sequence[int] = (443,),
                  resolver: Optional[str] = None,
                  timeout: float = 1.5) -> Dict[str, object]:
    """Cert + DNS snapshot for `hosts`; every failure is a recorded error."""
    entries: List[Dict[str, object]] = []
    identifiers: Dict[str, Dict] = {}
    for raw in hosts:
        host = str(raw).strip()
        if not host:
            continue
        dns = dns_records(host, resolver=resolver, timeout=timeout)
        cert: Optional[Dict[str, object]] = None
        for port in cert_ports:
            candidate = fetch_certificate(host, int(port),
                                          timeout=max(timeout, 2.0))
            if "error" not in candidate:
                cert = candidate
                break
            cert = candidate
        entries.append({"host": host, "dns": dns, "cert": cert})
        for cname in dns.get("cnames") or []:
            _identifier(identifiers, str(cname), "cname", host)
        if cert:
            for san in cert.get("sans") or []:
                _identifier(identifiers, str(san), "san", host)
    return {
        "hosts": entries,
        "identifiers": sorted(identifiers.values(),
                              key=lambda item: item["value"]),
        "capability": CAPABILITY,
    }
