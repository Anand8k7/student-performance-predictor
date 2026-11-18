import streamlit as st
import matplotlib.pyplot as plt

from analysis import load_data, summary, correlations
from predictor import predict_score
from auth import (authenticate, load_users, LoginThrottle,
                  ROLES, ROLE_ADMIN, safe_for_log)
from logger_config import get_logger

logger = get_logger("app")

st.set_page_config(page_title="Student Performance Predictor")
st.title("🎓 Student Performance Predictor")

FRIENDLY_ERROR = "Something went wrong. Please try again later."


# ---------- Login helpers ----------
@st.cache_resource
def get_throttle():
    # One shared counter for all visitors, so lockouts work across sessions.
    return LoginThrottle()


def get_configured_users():
    # Accounts come only from Streamlit Secrets. Any problem means no accounts.
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


def show_login_page(users):
    st.subheader("🔐 Please log in")
    if not users:
        st.error("Login is not set up yet. Please contact the administrator.")
        st.stop()

    username = st.text_input("Username", key="login_username", max_chars=64)
    password = st.text_input("Password", type="password",
                             key="login_password", max_chars=128)

    if st.button("Log in", key="login_button"):
        role, message = authenticate(username, password, users, get_throttle())
        if role is not None:
            end_session()
            st.session_state["username"] = username.strip().lower()
            st.session_state["role"] = role
            st.rerun()
        else:
            st.error(message)
    st.stop()


# ---------- Login check on EVERY page run ----------
users = get_configured_users()
current_user = st.session_state.get("username")
current_role = st.session_state.get("role")

logged_in = (
    current_role in ROLES
    and current_user in users
    and users[current_user]["role"] == current_role
)
if not logged_in:
    st.session_state.pop("username", None)
    st.session_state.pop("role", None)
    show_login_page(users)   # this stops the page here

is_admin = current_role == ROLE_ADMIN

# ---------- Sidebar: who is logged in, and logout ----------
with st.sidebar:
    st.markdown(f"Logged in as **{current_user}** ({current_role})")
    if st.button("Log out", key="logout_button"):
        logger.info("Logout for user '%s'", safe_for_log(current_user))
        end_session()
        st.rerun()

# ---------- The app (only reached after a successful login) ----------
st.write("Predict the **semester exam score (out of 100)** from internal marks, "
         "assignment, study hours and attendance.")

try:
    df = load_data()
except Exception:
    logger.exception("Data could not be loaded")   # details go to the private log only
    st.error(FRIENDLY_ERROR)
    st.stop()

tab_names = ["🔮 Predict", "📊 Insights"]
if is_admin:
    tab_names.append("📁 Data")
tabs = st.tabs(tab_names)

# ---------- Tab 1: Predict ----------
with tabs[0]:
    st.subheader("Enter student details")
    col1, col2 = st.columns(2)
    with col1:
        study_hours = st.slider("Study hours per day", 0.0, 24.0, 5.0, 0.5)
        attendance = st.slider("Attendance (%)", 0, 100, 75)
        assignment = st.slider("Assignment and project (out of 20)", 0.0, 20.0, 14.0, 0.5)
    with col2:
        internal1 = st.slider("Internal 1 (out of 30)", 0.0, 30.0, 18.0, 0.5)
        internal2 = st.slider("Internal 2 (out of 30)", 0.0, 30.0, 18.0, 0.5)

    if st.button("Predict semester score"):
        try:
            score = predict_score(study_hours, attendance,
                                  internal1, internal2, assignment)
            st.success(f"Predicted semester score: {score} / 100")
        except ValueError as error:
            st.error(str(error))            # our own clear validation message
        except Exception:
            logger.exception("Prediction failed")
            st.error(FRIENDLY_ERROR)

# ---------- Tab 2: Insights ----------
with tabs[1]:
    st.subheader("What affects the semester score?")
    corr = correlations(df)
    fig, ax = plt.subplots()
    corr.plot(kind="barh", ax=ax)
    ax.set_xlabel("Correlation with semester score")
    st.pyplot(fig)

    st.subheader("Score distribution")
    fig2, ax2 = plt.subplots()
    ax2.hist(df["semester_score"], bins=15)
    ax2.set_xlabel("Semester score")
    ax2.set_ylabel("Number of students")
    st.pyplot(fig2)

    st.subheader("Class summary")
    st.dataframe(summary(df))

# ---------- Tab 3: Data (Admin only, checked in code) ----------
if is_admin:
    with tabs[2]:
        st.subheader("All students")
        st.dataframe(df)
        st.download_button("Download data as CSV",
                           df.to_csv(index=False),
                           file_name="students.csv")
