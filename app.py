import os
import secrets
import tempfile
import time
from datetime import datetime

import numpy as np
import pandas as pd
import streamlit as st

from analysis import load_data, summary, correlations
from anomaly import InputAnomalyDetector
from audit import AuditLog
from auth import (authenticate, load_users, normalize_username, verify_second_factor,
                  LoginThrottle, ROLES, ROLE_ADMIN, safe_for_log)
from database import Database
from guards import RateLimiter, new_captcha, captcha_ok
from logger_config import get_logger
from mfa import TOTPVerifier
from models import Student
from privacy import dp_mean, dp_histogram
from report import build_pdf
from secure_crypto import check_keys
import geo
import predictor
import ui

logger = get_logger("app")

_signed_in = st.session_state.get("role") in ROLES
st.set_page_config(page_title="Student Performance Predictor", page_icon="🎓",
                   layout="wide" if _signed_in else "centered")
ui.apply_style()

FRIENDLY_ERROR = "Something went wrong. Please try again later."
SESSION_TIMEOUT_SECONDS = 15 * 60
CAPTCHA_AFTER_FAILURES = 3
MAX_UPLOAD_BYTES = 1_000_000
EPSILON = 1.0
RANGES = {"study_hours": (0, 24), "attendance": (0, 100), "internal1": (0, 30),
          "internal2": (0, 30), "assignment": (0, 20), "semester_score": (0, 100)}

# ---------- Fail closed if the security keys are not configured ----------
missing_keys = check_keys()
if missing_keys:
    st.error("Security keys are not set up yet. Please contact the administrator.")
    logger.error("Missing or weak security keys: %s", ", ".join(missing_keys))
    st.stop()


# ---------- Shared security objects (one per app process) ----------
@st.cache_resource
def get_throttle():
    return LoginThrottle()


@st.cache_resource
def get_verifier():
    return TOTPVerifier()


@st.cache_resource
def get_rate_limiter():
    return RateLimiter(max_events=20, window_seconds=60)


@st.cache_resource
def get_audit():
    log = AuditLog()
    predictor.on_tamper = log.record
    return log


@st.cache_resource
def get_detector():
    return InputAnomalyDetector(load_data(), predictor.FEATURES)


@st.cache_resource
def get_dp_stats(row_count):
    # Noise is drawn ONCE and reused, so refreshing the page cannot be used
    # to average the noise away.
    df = load_data()
    means = {col: round(dp_mean(df[col], lo, hi, EPSILON), 1)
             for col, (lo, hi) in RANGES.items()}
    counts, edges = dp_histogram(df["semester_score"], bins=10, epsilon=EPSILON)
    return means, counts, edges


@st.cache_resource
def get_model_comparison():
    return predictor.compare_models()


def get_configured_users():
    try:
        raw = st.secrets.get("users", {})
        raw = {str(name): info for name, info in raw.items()}
    except Exception:
        logger.error("Account settings could not be read")
        return {}
    return load_users(raw)


def end_session():
    for key in list(st.session_state.keys()):
        del st.session_state[key]


audit = get_audit()


def log_event(action, detail=""):
    audit.record(st.session_state.get("username", "(anonymous)"), action, detail)


# ---------- Login (password, CAPTCHA, then two-factor code) ----------
def finish_login(username, role):
    location, masked_ip = geo.describe()
    previous = audit.last_location(username)
    end_session()
    st.session_state["username"] = username
    st.session_state["role"] = role
    st.session_state["last_active"] = time.time()
    st.session_state["sid"] = secrets.token_hex(8)
    audit.record(username, "login_success",
                 f"role {role}; loc={location}; ip={masked_ip}")
    if previous and location != geo.UNKNOWN and previous != location:
        audit.record(username, "new_location_login", f"loc={location}; was={previous}")
        st.session_state["new_location"] = (location, previous)
    st.session_state["login_location"] = location
    st.rerun()


def show_mfa_step(users):
    user = st.session_state["mfa_user"]
    ui.login_header("Two-factor verification")
    box = st.container(border=True)
    box.markdown("#### 🔑 Enter your code")
    box.caption(f"Open your authenticator app and enter the 6-digit code for {user}.")
    code = box.text_input("6-digit code", key="mfa_code", max_chars=6,
                          placeholder="123456")
    col1, col2 = box.columns(2)
    if col1.button("Verify", key="mfa_button", type="primary"):
        ok, message = verify_second_factor(user, code, users, get_verifier(),
                                           get_throttle())
        if ok:
            finish_login(user, st.session_state["mfa_role"])
        else:
            audit.record(user, "mfa_failed")
            st.error(message)
    if col2.button("Cancel", key="mfa_cancel"):
        end_session()
        st.rerun()
    st.stop()


def show_login_page(users):
    if "mfa_user" in st.session_state:
        show_mfa_step(users)

    ui.login_header()
    if st.session_state.pop("timed_out", False):
        st.warning("You were logged out after 15 minutes of inactivity.")
    if not users:
        st.error("Login is not set up yet. Please contact the administrator.")
        st.stop()

    box = st.container(border=True)
    box.markdown("#### Sign in")
    username = box.text_input("Username", key="login_username", max_chars=64,
                              placeholder="e.g. student1")
    password = box.text_input("Password", type="password",
                              key="login_password", max_chars=128)

    failures = st.session_state.get("failed_logins", 0)
    needs_captcha = failures >= CAPTCHA_AFTER_FAILURES
    if needs_captcha:
        if "captcha" not in st.session_state:
            st.session_state["captcha"] = new_captcha()
        question, _ = st.session_state["captcha"]
        captcha_answer = box.text_input(question, key="captcha_answer", max_chars=3)

    clicked = box.button("Log in", key="login_button", type="primary")
    ui.login_footer()
    if clicked:
        key = normalize_username(username)
        actor = key if key in users else "(unknown username)"
        if needs_captcha:
            _, expected = st.session_state.pop("captcha")
            if not captcha_ok(captcha_answer, expected):
                st.session_state["failed_logins"] = failures + 1
                audit.record(actor, "captcha_failed")
                st.error("Wrong answer to the security check. Try again.")
                st.stop()

        role, message = authenticate(username, password, users, get_throttle())
        if role is None:
            st.session_state["failed_logins"] = failures + 1
            st.session_state.pop("captcha", None)
            location, masked_ip = geo.describe()
            audit.record(actor, "lockout" if message.startswith("Too many")
                         else "login_failed", f"loc={location}; ip={masked_ip}")
            st.error(message)
        elif users[key].get("totp_secret"):
            st.session_state["mfa_user"] = key
            st.session_state["mfa_role"] = role
            st.rerun()
        else:
            finish_login(key, role)
    st.stop()


# ---------- Login check + session timeout on EVERY page run ----------
users = get_configured_users()
current_user = st.session_state.get("username")
current_role = st.session_state.get("role")

logged_in = (
    current_role in ROLES
    and current_user in users
    and users[current_user]["role"] == current_role
)
if logged_in:
    idle = time.time() - st.session_state.get("last_active", 0)
    if idle > SESSION_TIMEOUT_SECONDS:
        audit.record(current_user, "session_timeout")
        end_session()
        st.session_state["timed_out"] = True
        logged_in = False
    else:
        st.session_state["last_active"] = time.time()

if not logged_in:
    st.session_state.pop("username", None)
    st.session_state.pop("role", None)
    show_login_page(users)

is_admin = current_role == ROLE_ADMIN

with st.sidebar:
    ui.sidebar_user(current_user, is_admin, bool(users[current_user].get("totp_secret")))
    st.caption(f"📍 Signed in from {st.session_state.get('login_location', geo.UNKNOWN)}")
    st.divider()
    st.caption("ℹ️ Linear Regression trained on 300 synthetic student records. "
               "Predictions are guidance only.")
    if st.button("Log out", key="logout_button"):
        audit.record(current_user, "logout")
        logger.info("Logout for user '%s'", safe_for_log(current_user))
        end_session()
        st.rerun()

ui.hero("🛡️ Administrator view" if is_admin else "🎓 Student view")
if "new_location" in st.session_state:
    new_loc, old_loc = st.session_state["new_location"]
    st.warning(f"🌍 New sign-in location: {new_loc} (last time: {old_loc}). "
               "If this wasn't you, change your password and tell the administrator.")

try:
    df = load_data()
except Exception:
    logger.exception("Data could not be loaded")
    st.error(FRIENDLY_ERROR)
    st.stop()

# ---------- Dashboard cards ----------
if is_admin:
    at_risk_count = sum(p < 60 for p in predictor.predict_many(df))
    chain_ok = audit.verify()[0] and predictor.model_status() != "tampered"
    ui.kpi_cards([
        ("👩‍🎓", "Students", len(df), "records in database", ui.ACCENT),
        ("📈", "Class average", f"{df['semester_score'].mean():.1f}", "out of 100", ui.ACCENT_2),
        ("⚠️", "At risk", at_risk_count, "predicted below 60", ui.WARN),
        ("🛡️", "Security", "All OK" if chain_ok else "Check", "audit log + model",
         ui.GOOD if chain_ok else ui.BAD)])
else:
    dp_means, _, _ = get_dp_stats(len(df))
    last = st.session_state.get("last_prediction")
    ui.kpi_cards([
        ("👩‍🎓", "Students", len(df), "in the class", ui.ACCENT),
        ("📈", "Class average", f"≈ {dp_means['semester_score']}", "privacy-protected", ui.ACCENT_2),
        ("🔮", "Your prediction", last["score"] if last else "—", "out of 100", ui.GOOD),
        ("🔒", "Privacy", "Protected", "differential privacy", ui.WARN)])

tab_names = ["🔮 Predict", "📊 Insights"]
if is_admin:
    tab_names += ["📁 Data", "⚠️ At-risk", "➕ Manage data", "🛡️ Security"]
tabs = st.tabs(tab_names)

# ---------- Tab 1: Predict ----------
with tabs[0]:
    ui.section("Enter student details", "Move the sliders, then click Predict.")
    col1, col2 = st.columns(2)
    with col1:
        study_hours = st.slider("Study hours per day", 0.0, 24.0, 5.0, 0.5)
        attendance = st.slider("Attendance (%)", 0, 100, 75)
        assignment = st.slider("Assignment and project (out of 20)", 0.0, 20.0, 14.0, 0.5)
    with col2:
        internal1 = st.slider("Internal 1 (out of 30)", 0.0, 30.0, 18.0, 0.5)
        internal2 = st.slider("Internal 2 (out of 30)", 0.0, 30.0, 18.0, 0.5)
    inputs = {"study_hours": study_hours, "attendance": attendance,
              "internal1": internal1, "internal2": internal2,
              "assignment": assignment}

    if st.button("🔮 Predict semester score", key="Predict semester score", type="primary"):
        if not get_rate_limiter().allow(st.session_state.get("sid", current_user)):
            log_event("rate_limited")
            st.error("Too many predictions in a short time. Please wait a minute.")
        else:
            try:
                score = predictor.predict_score(**inputs)
                contributions, base = predictor.explain(**inputs)
                flagged, anomaly_score = get_detector().check(inputs)
                if flagged:
                    log_event("anomaly_flagged", f"score {anomaly_score}")
                log_event("prediction")
                st.session_state["last_prediction"] = {
                    "inputs": inputs, "score": score, "contributions": contributions,
                    "base": base, "flagged": flagged,
                    "at": datetime.now().strftime("%Y-%m-%d %H:%M")}
            except ValueError as error:
                st.error(str(error))
            except Exception:
                logger.exception("Prediction failed")
                st.error(FRIENDLY_ERROR)

    result = st.session_state.get("last_prediction")
    if result:
        if result["score"] < 40:
            hint = "Likely to fail without support. Focus on study hours and attendance."
        elif result["score"] < 60:
            hint = "Below average. More study hours and attendance would help most."
        else:
            hint = "On track. Keep the same routine through the semester."
        ui.score_card(result["score"], hint)
        st.success(f"Predicted semester score: {result['score']} / 100")
        if result["flagged"]:
            st.warning("⚠️ These inputs look unusual compared with real students. "
                       "The prediction may be unreliable, and this has been logged.")
        ui.section("Why this prediction?",
                   f"Marks added by each factor, starting from a base of {result['base']}.")
        items = result["contributions"]
        ui.bar_chart([ui.nice(k) for k in items], list(items.values()), "Marks added",
                     [ui.ACCENT if v >= 0 else ui.BAD for v in items.values()])
        pdf = build_pdf(result["inputs"], result["score"], result["contributions"],
                        current_user, result["at"])
        st.download_button("📄 Download PDF report", pdf,
                           file_name="prediction_report.pdf", mime="application/pdf",
                           on_click=log_event, args=("report_downloaded",))

# ---------- Tab 2: Insights ----------
with tabs[1]:
    ui.section("What affects the semester score?",
               "Correlation of each factor with the final score (1.0 = strongest).")
    corr = correlations(df)
    ui.bar_chart([ui.nice(k) for k in corr.index], list(corr.values),
                 "Correlation", height=220)

    if is_admin:
        counts, edges = np.histogram(df["semester_score"], bins=10)
        ui.section("Score distribution", "Exact figures (admin view).")
    else:
        means, counts, edges = get_dp_stats(len(df))
        ui.section("Score distribution", "Privacy-protected (approximate) figures.")
    ui.column_chart([f"{edges[i]:.0f}–{edges[i + 1]:.0f}" for i in range(len(counts))],
                    [int(c) for c in counts], "Semester score", "Students")

    if is_admin:
        ui.section("Class summary", "Exact statistics.")
        st.dataframe(summary(df))
    else:
        ui.section("Class averages", "Privacy-protected.")
        st.dataframe(pd.DataFrame({"Average (approx.)": {ui.nice(k): v
                                                          for k, v in means.items()}}))
        st.caption(f"Protected with differential privacy (ε = {EPSILON} per "
                   "statistic): small random noise hides any single student.")

    ui.section("Model comparison", "Accuracy on held-out test data.")
    st.dataframe(get_model_comparison())

# ---------- Admin-only tabs (checked in code; Users never receive this data) ----------
if is_admin:
    with tabs[2]:
        ui.section("All students", "Names are decrypted only for admins.")
        st.dataframe(df)
        st.download_button("Download data as CSV", df.to_csv(index=False),
                           file_name="students.csv",
                           on_click=log_event, args=("data_exported",))

    with tabs[3]:
        ui.section("Students at risk", "Predicted score below the chosen threshold.")
        threshold = st.slider("Flag students predicted below", 30, 90, 60)
        at_risk = df.assign(predicted=predictor.predict_many(df))
        at_risk = at_risk[at_risk["predicted"] < threshold].sort_values("predicted")
        st.metric("Students at risk", len(at_risk))
        st.dataframe(at_risk[["name", "predicted", "study_hours", "attendance",
                              "internal1", "internal2", "assignment"]])

    with tabs[4]:
        ui.section("Add one student", "Every field is validated; the name is stored encrypted.")
        with st.form("add_student", clear_on_submit=True):
            name = st.text_input("Name", max_chars=50)
            c1, c2, c3 = st.columns(3)
            f_hours = c1.number_input("Study hours", 0.0, 24.0, 5.0)
            f_att = c2.number_input("Attendance %", 0.0, 100.0, 75.0)
            f_assign = c3.number_input("Assignment /20", 0.0, 20.0, 14.0)
            f_i1 = c1.number_input("Internal 1 /30", 0.0, 30.0, 18.0)
            f_i2 = c2.number_input("Internal 2 /30", 0.0, 30.0, 18.0)
            f_sem = c3.number_input("Semester /100", 0.0, 100.0, 70.0)
            if st.form_submit_button("Add student"):
                try:
                    Database().add_student(Student(name, f_hours, f_att, f_i1,
                                                   f_i2, f_assign, f_sem))
                    log_event("student_added")
                    st.success("Student added (name stored encrypted).")
                except ValueError as error:
                    st.error(str(error))

        ui.section("Upload a CSV file", "One bad row rejects the whole file. Maximum 1 MB.")
        upload = st.file_uploader("CSV with the standard columns", type=["csv"])
        if upload is not None and st.button("Import file", key="import_csv"):
            if upload.size > MAX_UPLOAD_BYTES:
                st.error("File is too large (maximum 1 MB).")
            else:
                path = None
                try:
                    with tempfile.NamedTemporaryFile("wb", suffix=".csv",
                                                     delete=False) as tmp:
                        tmp.write(upload.getvalue())
                        path = tmp.name
                    added = Database().load_csv(path)
                    log_event("csv_imported", f"{added} rows")
                    st.success(f"Imported {added} validated rows.")
                except ValueError as error:
                    log_event("csv_rejected")
                    st.error(str(error))
                finally:
                    if path and os.path.exists(path):
                        os.remove(path)

    with tabs[5]:
        ui.section("Security dashboard", "Live security status and attack simulations.")
        counts = audit.counts()
        failed = (counts.get("login_failed", 0) + counts.get("mfa_failed", 0)
                  + counts.get("captcha_failed", 0))
        ui.kpi_cards([
            ("✅", "Successful logins", counts.get("login_success", 0), "since restart", ui.GOOD),
            ("❌", "Failed logins", failed, "password, 2FA, CAPTCHA", ui.BAD),
            ("🔒", "Lockouts", counts.get("lockout", 0), "5 failures = 60 s", ui.WARN),
            ("🧪", "Anomalies", counts.get("anomaly_flagged", 0), "unusual inputs", ui.ACCENT)])
        if counts:
            ui.section("Events by type")
            ui.bar_chart(list(counts.keys()), list(counts.values()), "Events",
                         height=max(160, 28 * len(counts)))

        ui.section("🌍 Sign-in locations",
                   "Approximate city from the IP address; IPs are partly masked.")
        new_logins = counts.get("new_location_login", 0)
        if new_logins:
            st.warning(f"{new_logins} sign-in(s) from a new location. Review below.")
        st.dataframe(audit.login_history(30))

        st.markdown("#### 🔗 Tamper-evident audit log")
        a1, a2 = st.columns(2)
        if a1.button("Verify audit chain", key="verify_chain"):
            ok, bad = audit.verify()
            if ok:
                st.success("Audit chain intact: no entry has been changed or removed.")
            else:
                st.error(f"Audit chain BROKEN at entry #{bad}: the log was tampered with.")
        if a2.button("Simulate attacker editing the log", key="tamper_log"):
            audit.simulate_tampering()
            st.warning("One entry was edited directly in the database. "
                       "Now click 'Verify audit chain'.")

        st.markdown("#### 🧠 Model integrity (HMAC-SHA256)")
        status = predictor.model_status()
        icon = {"verified": "✅", "missing": "⚪", "tampered": "❌"}[status]
        st.write(f"{icon} Model file status: **{status}**")
        if st.button("Simulate attacker replacing the model", key="tamper_model"):
            with open(predictor.MODEL_PATH, "ab") as f:
                f.write(b"malicious-bytes")
            log_event("model_tamper_simulated")
            st.warning("Model file changed. The next prediction will refuse it "
                       "and rebuild a clean, signed model.")

        st.markdown("#### 🔒 Encryption at rest")
        st.write("What an attacker who steals the database file would see:")
        st.dataframe(Database().get_raw(3))

        st.markdown("#### 👤 Accounts")
        st.dataframe(pd.DataFrame([
            {"username": u, "role": a["role"],
             "two-factor": "on" if a.get("totp_secret") else "off"}
            for u, a in users.items()]))

        st.markdown("#### 📜 Recent audit events")
        st.dataframe(audit.entries(25))
