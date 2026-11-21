"""Shared look and feel: colours, page styling, chart style, grades.
Only fixed CSS is injected; user data is never placed inside HTML."""
import matplotlib as mpl
import streamlit as st

PRIMARY = "#2563EB"
MUTED = "#64748B"
GRID = "#E5E9F2"
POSITIVE = "#2563EB"
NEGATIVE = "#EF4444"

LABELS = {"study_hours": "Study hours", "attendance": "Attendance",
          "internal1": "Internal 1", "internal2": "Internal 2",
          "assignment": "Assignment", "semester_score": "Semester score"}

CSS = """
<style>
.block-container {padding-top: 1.6rem; padding-bottom: 3rem;}
h1, h2, h3 {letter-spacing: -0.01em;}
div[data-testid="stMetric"] {
    background: #F3F6FB; border: 1px solid #E5E9F2; border-radius: 12px;
    padding: 14px 18px;
}
div[data-testid="stMetricLabel"] p {font-size: 0.85rem; color: #64748B;}
div[data-testid="stMetricValue"] {font-weight: 700;}
.stTabs [data-baseweb="tab-list"] {gap: 6px;}
.stTabs [data-baseweb="tab"] {font-weight: 600; padding: 8px 14px;}
section[data-testid="stSidebar"] {background: #F8FAFC; border-right: 1px solid #E5E9F2;}
.spp-hero {display: flex; align-items: center; gap: 14px; margin-bottom: 0.4rem;}
.spp-logo {font-size: 2.4rem; line-height: 1;}
.spp-title {font-size: 1.7rem; font-weight: 700; color: #0F172A; margin: 0;}
.spp-sub {color: #64748B; margin: 0; font-size: 0.95rem;}
.spp-login-head {text-align: center; margin: 1.2rem 0 0.6rem 0;}
.spp-login-head .spp-logo {font-size: 3rem;}
.spp-login-title {font-size: 1.6rem; font-weight: 700; color: #0F172A; margin: 0.3rem 0 0 0;}
.spp-login-sub {color: #64748B; margin: 0.2rem 0 0 0;}
.spp-foot {text-align: center; color: #94A3B8; font-size: 0.8rem; margin-top: 1rem;}
</style>
"""

HERO = """
<div class="spp-hero">
  <div class="spp-logo">🎓</div>
  <div>
    <p class="spp-title">Student Performance Predictor</p>
    <p class="spp-sub">Predict semester scores from internals, assignments, study hours and attendance</p>
  </div>
</div>
"""

LOGIN_HEAD = """
<div class="spp-login-head">
  <div class="spp-logo">🎓</div>
  <p class="spp-login-title">Student Performance Predictor</p>
  <p class="spp-login-sub">Secure sign-in</p>
</div>
"""

LOGIN_FOOT = ('<p class="spp-foot">🔒 Argon2id passwords · two-factor login for admins · '
              'encrypted data</p>')


def apply_style():
    st.markdown(CSS, unsafe_allow_html=True)   # fixed CSS only, never user data
    mpl.rcParams.update({
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.axisbelow": True, "xtick.color": MUTED, "ytick.color": MUTED,
        "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold",
        "axes.prop_cycle": mpl.cycler(color=[PRIMARY]),
        "figure.facecolor": "white", "axes.facecolor": "white",
    })


def hero():
    st.markdown(HERO, unsafe_allow_html=True)


def login_header():
    st.markdown(LOGIN_HEAD, unsafe_allow_html=True)


def login_footer():
    st.markdown(LOGIN_FOOT, unsafe_allow_html=True)


def grade_for(score):
    """College-style grade bands for a score out of 100."""
    for limit, grade, note in [(90, "A+", "Outstanding"), (75, "A", "Excellent"),
                               (60, "B", "Good"), (50, "C", "Average"),
                               (40, "D", "Needs improvement")]:
        if score >= limit:
            return grade, note
    return "F", "At risk of failing"


def nice(name):
    return LABELS.get(name, name)
