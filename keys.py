"""Reads secret keys from Streamlit Secrets, or from environment variables
(used by the automated tests and the CI pipeline). Keys never live in code."""
import os


def get_secret(section, name):
    try:
        import streamlit as st
        return str(st.secrets[section][name])
    except Exception:
        return os.environ.get(f"SPP_{section.upper()}_{name.upper()}")
