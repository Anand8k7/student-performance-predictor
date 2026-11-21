"""Approximate sign-in location (city level) from the visitor's IP address.
Only a masked IP and the city/region/country are stored."""
import ipaddress
from functools import lru_cache

import requests

LOOKUP_URL = "https://ipapi.co/{ip}/json/"     # HTTPS only
TIMEOUT_SECONDS = 2
UNKNOWN = "Unknown location"


def parse_ip(value):
    """Return a valid public IP string, or None."""
    if not value:
        return None
    candidate = str(value).split(",")[0].strip()      # first hop of X-Forwarded-For
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        return None
    return str(ip)


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
        ip = parse_ip(getattr(st.context, "ip_address", None))
        if ip:
            return ip
        headers = st.context.headers
        return parse_ip(headers.get("X-Forwarded-For") or headers.get("X-Real-Ip"))
    except Exception:
        return None


def _clean(text):
    return "".join(c for c in str(text)[:40] if c.isprintable() and c not in ";=")


@lru_cache(maxsize=512)
def lookup(ip):
    if not ip:
        return UNKNOWN
    try:
        response = requests.get(LOOKUP_URL.format(ip=ip), timeout=TIMEOUT_SECONDS)
        data = response.json() if response.ok else {}
    except Exception:
        return UNKNOWN
    if data.get("error"):
        return UNKNOWN
    parts = [_clean(data.get(k, "")) for k in ("city", "region", "country_name")]
    parts = [p for p in parts if p]
    return ", ".join(parts) if parts else UNKNOWN


def describe():
    """Return (location text, masked IP) for the current visitor."""
    ip = client_ip()
    return lookup(ip), mask_ip(ip)
