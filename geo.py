"""Approximate sign-in location (city level) from the visitor's IP address.
Only a masked IP and the city/region/country are stored."""
import ipaddress
from functools import lru_cache

import requests

TIMEOUT_SECONDS = 2
UNKNOWN = "Unknown location"
IP_HEADERS = ["X-Forwarded-For", "X-Real-Ip", "Cf-Connecting-Ip",
              "True-Client-Ip", "X-Client-Ip", "Forwarded"]

# Several HTTPS providers, tried in order (one may block shared cloud servers).
PROVIDERS = [
    ("ipapi.co", "https://ipapi.co/{ip}/json/",
     lambda d: (d.get("city"), d.get("region"), d.get("country_name")) if not d.get("error") else None),
    ("ipwho.is", "https://ipwho.is/{ip}",
     lambda d: (d.get("city"), d.get("region"), d.get("country")) if d.get("success") else None),
    ("ipinfo.io", "https://ipinfo.io/{ip}/json",
     lambda d: (d.get("city"), d.get("region"), d.get("country")) if not d.get("bogon") else None),
]

last_status = {}      # for the admin diagnostic box (no full IPs stored)


def parse_ip(value):
    """Return a valid public IP string, or None. Checks every hop."""
    if not value:
        return None
    text = str(value)
    if text.lower().startswith("for=") or ";" in text:        # "Forwarded" header
        text = ",".join(p.split("=", 1)[1] for p in text.replace(";", ",").split(",")
                        if p.strip().lower().startswith("for="))
    for candidate in text.split(","):
        candidate = candidate.strip().strip('"').strip("[]")
        if candidate.count(":") == 1:                           # ip:port
            candidate = candidate.split(":")[0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local):
            return str(ip)
    return None


def mask_ip(ip):
    if not ip:
        return "hidden"
    parsed = ipaddress.ip_address(ip)
    if parsed.version == 4:
        return ".".join(ip.split(".")[:3] + ["x"])
    return ":".join(parsed.exploded.split(":")[:3]) + ":x"


def client_ip():
    try:
        import streamlit as st
        context_ip = getattr(st.context, "ip_address", None)
        last_status["context_ip"] = "public" if parse_ip(context_ip) else (
            "private/proxy" if context_ip else "none")
        ip = parse_ip(context_ip)
        if ip:
            last_status["ip_source"] = "st.context.ip_address"
            return ip
        headers = st.context.headers
        last_status["headers_present"] = [h for h in IP_HEADERS if headers.get(h)]
        for name in IP_HEADERS:
            ip = parse_ip(headers.get(name))
            if ip:
                last_status["ip_source"] = name
                return ip
        last_status["ip_source"] = "not found"
    except Exception as error:
        last_status["ip_source"] = f"error: {type(error).__name__}"
    return None


def _clean(text):
    return "".join(c for c in str(text or "")[:40] if c.isprintable() and c not in ";=")


@lru_cache(maxsize=512)
def lookup(ip):
    if not ip:
        return UNKNOWN
    results = []
    for name, url, read in PROVIDERS:
        try:
            response = requests.get(url.format(ip=ip), timeout=TIMEOUT_SECONDS,
                                    headers={"User-Agent": "student-performance-predictor"})
            fields = read(response.json()) if response.ok else None
        except Exception as error:
            results.append(f"{name}: {type(error).__name__}")
            continue
        if not response.ok:
            results.append(f"{name}: HTTP {response.status_code}")
            continue
        parts = [_clean(p) for p in (fields or ()) if _clean(p)]
        if parts:
            results.append(f"{name}: ok")
            last_status["lookup"] = results
            return ", ".join(parts)
        results.append(f"{name}: no data")
    last_status["lookup"] = results
    return UNKNOWN


def from_browser(value):
    """Validate the location reported by the visitor's browser component."""
    if not isinstance(value, dict) or value.get("error"):
        return None
    parts = [_clean(value.get(k)) for k in ("city", "region", "country")]
    parts = [p for p in parts if p]
    if not parts:
        return None
    return ", ".join(parts), parse_ip(value.get("ip"))


def describe(browser_value=None):
    """Return (location text, masked IP) for the current visitor.
    Server-side IP first; on hosts that hide it, use the browser's report."""
    ip = client_ip()
    if ip:
        location = lookup(ip)
        if location != UNKNOWN:
            return location, mask_ip(ip)
    reported = from_browser(browser_value)
    if reported:
        last_status["browser"] = "ok"
        location, browser_ip = reported
        return location + " (browser)", mask_ip(browser_ip)
    last_status["browser"] = "no data" if browser_value is None else "unavailable"
    return UNKNOWN, mask_ip(ip)
