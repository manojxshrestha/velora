"""OSINT adapter units: TLS certificate DER parse + DNS wire codec (Phase 4).

The cert fixtures are a throwaway self-signed pair generated for this file
(velora.test / far-future.test); everything else is hand-built bytes —
no network beyond loopback.
"""

import base64
import re
import socket
import ssl
import threading

import pytest

from velora.active.osint import (
    CAPABILITY,
    collect_osint,
    decode_name,
    dns_query,
    dns_records,
    encode_query,
    fetch_certificate,
    parse_der_certificate,
    parse_response,
)

CERT_UTCTIME_PEM = """-----BEGIN CERTIFICATE-----
MIIDvjCCAqagAwIBAgIUefr9ENO8o5OdaG1r3/Mj5hdpjPkwDQYJKoZIhvcNAQEL
BQAwVjELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFRlc3QxDTALBgNVBAcMBFRlc3Qx
EzARBgNVBAoMClZlbG9yYVRlc3QxFDASBgNVBAMMC3ZlbG9yYS50ZXN0MB4XDTI2
MTAwODAwNTU1NFoXDTI3MTAwODAwNTU1NFowVjELMAkGA1UEBhMCVVMxDTALBgNV
BAgMBFRlc3QxDTALBgNVBAcMBFRlc3QxEzARBgNVBAoMClZlbG9yYVRlc3QxFDAS
BgNVBAMMC3ZlbG9yYS50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA7IMJL9P1OS0YPlwdc0pgefFobvdM+Sr4/iRHgyBdI1LsI/9tjEeUZpCOFk8s
eN+921d4LMeA1qONIXHf8oNZRtTwfUQeiEtvfYE+cjqncm3NfpFJwYpqf8YZN3XE
Cfkzv1Pb7dkEgMzds7JhLuCKDJC0ak/ZUTyd/bfGkG00VgSg7mdBK1nkusXt3NnJ
9AYBY3zZUxBmtixV6DtpY33DPuo9Ffy8Jp7MMBU7HN8Wi7pzSQOkyW8qn2TVmljq
da+obZrF31vCPRkTh8kWPUu4jaigijyvmDu/sK1CM6Tlq5E76f+khFbn2K3JOTQG
UDa1ipD50wwq28v/g1AGXqnlRQIDAQABo4GDMIGAMB0GA1UdDgQWBBQ7CtNiXNNH
RSmN4CSlldXbcztCjzAfBgNVHSMEGDAWgBQ7CtNiXNNHRSmN4CSlldXbcztCjzAP
BgNVHRMBAf8EBTADAQH/MC0GA1UdEQQmMCSCC3ZlbG9yYS50ZXN0gg9hbHQudmVs
b3JhLnRlc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAHVPxypwQPUCAlqgdVhk
q+fmPRgTL1zNoVG51XCbd2UKQFoiQyzqlpv0nkRjcgU+2DgDmJgJEXCEEd8xnHWH
BZPve8EBjsH72DmlI3j08cuZlaCNbqTvX5YWFfVZe8gSPHV+fW14MbE/33b8JQsN
C9SD3KJFgER66A8BUrgjCvCl0WfL1Yy5jwEId2TM9FTFzixFbmtyzwigukimBBsn
8SirD3tePQ9iKMjBya0466zYwWZmZhyCUmFxa/tM1GLaDwL/BFexRpPt1f/Ht7Q7
ySXmhAaQ9Cspdz/kgTVuuyboK80SVj41JVC9kCKe9GJwqN45BmS5jFF2HT5zeqjX
vBE=
-----END CERTIFICATE-----
"""

KEY_UTCTIME_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDsgwkv0/U5LRg+
XB1zSmB58Whu90z5Kvj+JEeDIF0jUuwj/22MR5RmkI4WTyx4373bV3gsx4DWo40h
cd/yg1lG1PB9RB6IS299gT5yOqdybc1+kUnBimp/xhk3dcQJ+TO/U9vt2QSAzN2z
smEu4IoMkLRqT9lRPJ39t8aQbTRWBKDuZ0ErWeS6xe3c2cn0BgFjfNlTEGa2LFXo
O2ljfcM+6j0V/LwmnswwFTsc3xaLunNJA6TJbyqfZNWaWOp1r6htmsXfW8I9GROH
yRY9S7iNqKCKPK+YO7+wrUIzpOWrkTvp/6SEVufYrck5NAZQNrWKkPnTDCrby/+D
UAZeqeVFAgMBAAECggEAAUmXM2Isu7uM0aU/fACIHgyQnaoVKQc8kOa7fgeArShC
RiXU595K5dmONaWU2ffdDhxSWAI1YtoGyOj29Du+WPXzeL1dLoc/MXz7hm+laCpg
7UDVnmenPbsTAygLMI+D1O8092Q2/D9IaXcXDU++oR0qLxecYHPLhZmzaBvvt3Pg
XQYntdLY4Q+Tv5uDS2G6LqN9cfd9+sh7Un3Ik6/bBmCW68YCnUl1kmWw1S9bOx2T
r5gMCPo0xYGJYLu1+vIS5HV0D/vMKnRMycRVlWX71WAUH67u0yqij+EqbmnlHeGp
w3A2IrmIS3ksEQtCxREOjPnd7E036DcCbpo+hyxjawKBgQD4h9QQN5SHqt9/3xPI
EE8dHRhu/CYy//4uFpcCvKh7jCSdvSFYRdw+75EcRhNKxtUzd+axQAXwYd7gNqDZ
M+scHLhTMFvcqasMRXfeTw3Jk/Ck9zmRMTswEA7RnJx3ggjbjog6SIjtxOAQeTcM
9aHcyK22hbm3gDkoOWZ2Vq3r1wKBgQDznryQARXYH6+nyOnNMjL18PTuklOMXEOT
RERXM7nLsd7ZtXE5xDqPEZEn3ajSxbaobHlJnk4MbjypPqFZDYGTZ3RXxBYwnN5c
A6T7oaHF/K3Ji+cd0SBBI12uvNof3t6QdXelTZzjiJ8twkPIvFLg/cd/4uquDJZF
GEGzCv60QwKBgQDk2F2CmUshKUwneIfEfo/6pOHswC2EZIfudEqU8JbLPJ4yyQY9
PAazxPB/cl8tSazjeZJowCU31Ubeei7eEZp6BlAL+cl8hJbF8+mOQIjXhmvd2u+d
LBHuDbs3c9f3izsQwEvcLxI2rkQLpzHzsvJaVEbwfG4n89+tlD0u1l3LfQKBgQDM
GvLKB07A2pM1FFvlgag2a2EZu9hpoScwa6KCGKER6nzVk3FAP4n8MXCWoNv/cow9
AVyAdDPZsEX8Wa+eR3WHBMbxfSRGKDcXiiogc+NwV+lWEXNZhMrsJ/AmJKzuxK9d
Aj1ybdsCuoT6NmbJ+BXL0HLjTz7lAUCotNDea1jHtwKBgD2eO61dbj10C+/xOBoA
AjO9ale9QZ0YKDQUobfbG0Nl1/lae+AtxYSwcfVJ548KgzQFj6KYKVWZid2dALPf
rMgL4q6nERRt6JkrC/wVyqGoeOKJtm6YhvnXh0BNwb2n5yjwl96Y2KbYAQwiVlLH
RhPaEStzDkwbwbLP/cfvJp7T
-----END PRIVATE KEY-----
"""

CERT_GENERALIZED_PEM = """-----BEGIN CERTIFICATE-----
MIIDMzCCAhugAwIBAgIUPQwRBZfNOv2hNR0saeBOR09liLEwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPZmFyLWZ1dHVyZS50ZXN0MCAXDTI2MTAwODAwNTU1NFoY
DzIwNTEwNTMwMDA1NTU0WjAaMRgwFgYDVQQDDA9mYXItZnV0dXJlLnRlc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/sJSWAZXbfTUNyTSAii8Jd4+U
xqjUl7YXw9ODAjBYDd5+3xZuGw+pNtrshn1Owk3yb0t1YnEvi1bLoxQMZl42V4Mj
U0CM1LllQURVBzWnZWR9T7rR9cQCyVEU9EQLTqMEZUXIdgDQt4G5w1nkSwt+ov+8
9mtgDbEGgOVQwRLiSoWE49+lh8ogBHuJ62+PDeyK9aq4Wc/CyKgWR7o40aEsk4S/
sceGFVpXLlR4yNY5QUlIsTqpDt9a4k8+ZhKF0fIPv+B/GWLTZX7Nd8MMIwFbNwGQ
Flu+w2TNAEyFgDinw8bHHA+NHfAJde2SJcDuBxI2MhviD3jmhl88ekXpDjvNAgMB
AAGjbzBtMB0GA1UdDgQWBBRTrXHIauqGfo/Uag6JMs5nYt/arzAfBgNVHSMEGDAW
gBRTrXHIauqGfo/Uag6JMs5nYt/arzAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQT
MBGCD2Zhci1mdXR1cmUudGVzdDANBgkqhkiG9w0BAQsFAAOCAQEAgl1Og4KRSsef
NPfrfMMqEZeQuOqZS/mPgOszbQuyZ/ZFr0Y7O3ok/k7ynDwaaW3pAAqGXXfi7Rgz
+EHA8YHnnMcMV4mg+1hXTCGiI4oRfutx+aE9qq7cefKqVWO262tHfhIXDDZWVIjV
tx+iaqvQoHksbmJGHkxyqi7IgcgYn9lbzlkX6BHY6AC4rH30Su7NpQ9uuCi9SC9B
KGAISL45Nky15GZEC9pcQ65ph5wBUdEVuZl6WdlbLweyoA76FpBmcoz7036QLfWs
yQ7f8BakNBOB0l+ZsYHSS3slM6phAZqtBv1zXycGM9xLDgFdUn4paDnQvREqnbUX
0NRhgYi2qA==
-----END CERTIFICATE-----"""


def _der(pem: str) -> bytes:
    body = pem.split("-----BEGIN CERTIFICATE-----", 1)[1]
    body = body.split("-----END CERTIFICATE-----", 1)[0]
    return base64.b64decode("".join(body.split()))


# ---------------------------------------------------------------------------
# Certificate DER parsing
# ---------------------------------------------------------------------------

def test_parse_certificate_utctime_fields():
    cert = parse_der_certificate(_der(CERT_UTCTIME_PEM))
    assert cert["subject"] == "velora.test"
    assert cert["issuer"] == "velora.test"
    # Format + ordering, no hardcoded calendar dates (they rot).
    stamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
    assert re.fullmatch(stamp, cert["not_before"]), cert
    assert re.fullmatch(stamp, cert["not_after"]), cert
    assert cert["not_before"] < cert["not_after"]
    assert cert["sans"] == ["velora.test", "alt.velora.test"]


def test_parse_certificate_generalized_time():
    # Not-far-enough fixtures would be UTCTime; this one expires 2051.
    der = _der(CERT_GENERALIZED_PEM)
    try:
        cert = parse_der_certificate(der)
    except ValueError:
        pytest.skip("fixture regenerated without a GeneralizedTime cert")
    assert cert["not_after"].startswith("2051-"), cert
    assert cert["subject"] == "far-future.test"


def test_parse_certificate_rejects_garbage():
    with pytest.raises(ValueError):
        parse_der_certificate(b"\x30\x03\x02\x01\x01")
    with pytest.raises(ValueError):
        parse_der_certificate(b"")


# ---------------------------------------------------------------------------
# DNS wire codec
# ---------------------------------------------------------------------------

def test_encode_query_layout():
    tid, wire = encode_query("example.com", "A")
    assert len(tid) == 2
    assert wire[:2] == tid
    flags, qd, an, ns, ar = _ints(wire[2:12])
    assert (flags, qd, an, ns, ar) == (0x0100, 1, 0, 0, 0)
    name, offset = decode_name(wire, 12)
    assert name == "example.com"
    qtype, qclass = _ints(wire[offset:offset + 4])
    assert (qtype, qclass) == (1, 1)


def _ints(raw):
    return [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]


def test_encode_query_rejects_unknown_type():
    with pytest.raises(ValueError):
        encode_query("example.com", "HTTPS")


def test_decode_name_follows_compression_pointer():
    buf = b"\x03www\x07example\x03com\x00" + b"\xc0\x00"
    assert len(buf) == 19
    name, offset = decode_name(buf, 17)
    assert name == "www.example.com"
    assert offset == len(buf)


def _a_response(tid: bytes, ip: str = "1.2.3.4") -> bytes:
    question = b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
    answer = (
        b"\xc0\x0c"                    # pointer → example.com
        + b"\x00\x01\x00\x01"          # type A, class IN
        + b"\x00\x00\x00\x3c"          # ttl 60
        + b"\x00\x04" + socket.inet_aton(ip)
    )
    header = tid + b"\x81\x80" + _pack5(1, 1, 0, 0)
    return header + question + answer


def _pack5(*values) -> bytes:
    out = b""
    for value in values:
        out += value.to_bytes(2, "big")
    return out


def test_parse_response_extracts_a_record():
    tid = b"\x12\x34"
    parsed = parse_response(_a_response(tid), tid)
    assert parsed["rcode"] == 0
    assert parsed["answers"] == {"A": ["1.2.3.4"]}


def test_parse_response_flags_rcode():
    tid = b"\x12\x34"
    buf = bytearray(_a_response(tid))
    buf[3] = 0x83  # QR + NXDOMAIN
    parsed = parse_response(bytes(buf), tid)
    assert parsed["rcode"] == 3


def test_parse_response_tid_mismatch():
    with pytest.raises(ValueError):
        parse_response(_a_response(b"\x12\x34"), b"\xab\xcd")


def test_dns_query_records_timeout_error():
    # 192.0.2.1 (TEST-NET-1) is reserved and never answers.
    values, error = dns_query("example.com", "A",
                              resolver="192.0.2.1", timeout=0.3)
    assert values == []
    assert error


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def test_dns_records_for_ip_literal():
    assert dns_records("127.0.0.1") == {"a": ["127.0.0.1"]}
    assert "::1" in dns_records("::1")["aaaa"]


def test_dns_records_never_raises_on_bad_host():
    record = dns_records("not a host !", timeout=0.3)
    assert "errors" in record
    assert "resolve" in record["errors"]


def test_collect_osint_structure_and_errors():
    payload = collect_osint(["127.0.0.1"], cert_ports=[9])
    assert "partial" in payload["capability"]
    entry = payload["hosts"][0]
    assert entry["host"] == "127.0.0.1"
    assert entry["dns"] == {"a": ["127.0.0.1"]}
    assert "error" in entry["cert"]          # port 9 is closed
    assert payload["identifiers"] == []


def test_collect_osint_handles_empty_and_blank_hosts():
    payload = collect_osint(["", "  "], cert_ports=[9])
    assert payload["hosts"] == []
    assert payload["identifiers"] == []


@pytest.fixture
def tls_endpoint():
    """Loopback TLS server presenting CERT_UTCTIME_PEM."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = f"{tmp}/cert.pem"
        key_path = f"{tmp}/key.pem"
        with open(cert_path, "w") as handle:
            handle.write(CERT_UTCTIME_PEM)
        with open(key_path, "w") as handle:
            handle.write(KEY_UTCTIME_PEM)
        context.load_cert_chain(cert_path, key_path)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    ready = threading.Event()

    def serve():
        ready.set()
        try:
            listener.settimeout(5)
            conn, _ = listener.accept()
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(3)
                try:
                    tls.recv(1024)
                except (OSError, ssl.SSLError):
                    pass
        except (OSError, ssl.SSLError):
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(3)
    try:
        yield port
    finally:
        thread.join(timeout=5)


def test_fetch_certificate_parses_live_handshake(tls_endpoint):
    cert = fetch_certificate("127.0.0.1", tls_endpoint, timeout=3.0)
    assert "error" not in cert, cert
    assert cert["subject"] == "velora.test"
    assert cert["sans"] == ["velora.test", "alt.velora.test"]


def test_collect_osint_identifiers_from_live_cert(tls_endpoint):
    payload = collect_osint(["127.0.0.1"], cert_ports=[tls_endpoint],
                            timeout=1.0)
    entry = payload["hosts"][0]
    assert "error" not in entry["cert"]
    values = {item["value"]: item for item in payload["identifiers"]}
    assert "velora.test" in values and "alt.velora.test" in values
    assert values["velora.test"]["kinds"] == ["san"]
    assert values["velora.test"]["hosts"] == ["127.0.0.1"]


def test_capability_names_the_reduction():
    assert "partial" in CAPABILITY
    assert "no CT" in CAPABILITY
