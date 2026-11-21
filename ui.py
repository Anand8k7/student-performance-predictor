"""Modern dark dashboard look. All text placed inside HTML is escaped first,
so user data can never inject markup (XSS-safe)."""
from html import escape

import pandas as pd
import streamlit as st

ACCENT = "#818CF8"
ACCENT_2 = "#22D3EE"
GOOD = "#34D399"
WARN = "#FBBF24"
BAD = "#F87171"
MUTED = "#94A3B8"

LABELS = {"study_hours": "Study hours", "attendance": "Attendance",
          "internal1": "Internal 1", "internal2": "Internal 2",
          "assignment": "Assignment", "semester_score": "Semester score"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"], .stMarkdown, .stText, button, input {font-family: 'Inter', sans-serif !important;}
.block-container {padding-top: 3.2rem; padding-bottom: 3rem; max-width: 1200px;}
#MainMenu, footer {visibility: hidden;}

/* gradient header */
.spp-hero {
  background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 45%, #0EA5E9 100%);
  border-radius: 20px; padding: 26px 30px; margin-bottom: 22px;
  box-shadow: 0 12px 40px rgba(79,70,229,0.25);
}
.spp-hero h1 {color: #fff; font-size: 1.85rem; font-weight: 800; margin: 0; padding: 0;}
.spp-hero p {color: rgba(255,255,255,0.85); margin: 6px 0 0 0; font-size: 0.98rem;}
.spp-chip {display: inline-block; margin-top: 12px; margin-right: 8px; padding: 4px 12px;
  border-radius: 999px; background: rgba(255,255,255,0.16); color: #fff; font-size: 0.78rem; font-weight: 600;}

/* KPI cards */
.spp-grid {display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 22px;}
@media (max-width: 900px) {.spp-grid {grid-template-columns: repeat(2, minmax(0, 1fr));}}
.spp-card {background: #131C31; border: 1px solid #1E2A47; border-radius: 16px; padding: 18px 20px;
  position: relative; overflow: hidden;}
.spp-card:before {content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--c);}
.spp-card .icon {font-size: 1.3rem;}
.spp-card .label {color: #94A3B8; font-size: 0.8rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.04em; margin-top: 6px;}
.spp-card .value {color: #F1F5F9; font-size: 1.55rem; font-weight: 800; margin-top: 2px; line-height: 1.2;}
.spp-card .sub {color: #64748B; font-size: 0.78rem; margin-top: 2px;}

/* score card */
.spp-score {background: linear-gradient(135deg, #131C31, #1A2442); border: 1px solid #1E2A47;
  border-radius: 20px; padding: 24px 28px; display: flex; align-items: center; gap: 28px; margin: 8px 0 16px 0;}
.spp-ring {width: 120px; height: 120px; border-radius: 50%; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;}
.spp-ring-inner {width: 94px; height: 94px; border-radius: 50%; background: #131C31;
  display: flex; flex-direction: column; align-items: center; justify-content: center;}
.spp-ring-inner b {font-size: 1.7rem; color: #F1F5F9; font-weight: 800;}
.spp-ring-inner span {font-size: 0.72rem; color: #94A3B8;}
.spp-grade {font-size: 2.6rem; font-weight: 800; line-height: 1;}
.spp-note {color: #CBD5E1; font-size: 1.05rem; font-weight: 600; margin-top: 6px;}
.spp-hint {color: #94A3B8; font-size: 0.9rem; margin-top: 6px;}

/* tabs as pills */
.stTabs [data-baseweb="tab-list"] {gap: 8px; background: #131C31; padding: 6px; border-radius: 14px;
  border: 1px solid #1E2A47;}
.stTabs [data-baseweb="tab"] {border-radius: 10px; padding: 8px 16px; font-weight: 600; height: auto;}
.stTabs [aria-selected="true"] {background: linear-gradient(135deg, #4F46E5, #7C3AED); color: #fff !important;}
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] {display: none;}

/* buttons */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
  border-radius: 12px; font-weight: 600; border: 1px solid #2A3A5F; padding: 0.55rem 1.1rem;}
.stButton > button[kind="primary"], .stFormSubmitButton > button {
  background: linear-gradient(135deg, #4F46E5, #7C3AED); border: none; color: #fff;}

/* inputs */
.stTextInput input, .stNumberInput input {border-radius: 10px !important;}
div[data-testid="stVerticalBlockBorderWrapper"] {border-radius: 18px;}

/* sidebar */
section[data-testid="stSidebar"] {background: #0E1528; border-right: 1px solid #1E2A47;}
.spp-user {display: flex; align-items: center; gap: 12px; margin: 6px 0 14px 0;}
.spp-avatar {width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-weight: 800; color: #fff; background: linear-gradient(135deg, #4F46E5, #0EA5E9);}
.spp-user b {color: #F1F5F9; font-size: 1rem;}
.spp-pill {display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 700;
  margin-top: 4px;}
.spp-side-item {color: #94A3B8; font-size: 0.85rem; margin: 6px 0;}

/* section titles */
.spp-section {font-size: 1.15rem; font-weight: 700; color: #F1F5F9; margin: 18px 0 2px 0;}
.spp-section-sub {color: #94A3B8; font-size: 0.88rem; margin-bottom: 10px;}

/* login */
.spp-login {text-align: center; margin: 1.5rem 0 1rem 0;}
.spp-login .logo {width: 68px; height: 68px; margin: 0 auto; border-radius: 20px; font-size: 2.1rem;
  display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #4F46E5, #7C3AED 50%, #0EA5E9); box-shadow: 0 10px 30px rgba(79,70,229,0.35);}
.spp-login h2 {color: #F1F5F9; font-weight: 800; font-size: 1.6rem; margin: 14px 0 0 0; padding: 0;}
.spp-login p {color: #94A3B8; margin: 4px 0 0 0;}
.spp-foot {text-align: center; color: #64748B; font-size: 0.78rem; margin-top: 14px;}
</style>
"""


def apply_style():
    st.markdown(CSS, unsafe_allow_html=True)   # fixed CSS only


def _html(markup):
    st.markdown(markup, unsafe_allow_html=True)


def hero(role_label):
    _html(f"""<div class="spp-hero"><h1>🎓 Student Performance Predictor</h1>
<p>Predict semester scores from internals, assignments, study hours and attendance.</p>
<span class="spp-chip">{escape(role_label)}</span><span class="spp-chip">🔒 Encrypted data</span>
<span class="spp-chip">🛡️ Audited</span></div>""")


def kpi_cards(cards):
    """cards = [(icon, label, value, sub, colour), ...] (4 items)."""
    body = "".join(
        f'<div class="spp-card" style="--c:{c}"><div class="icon">{escape(i)}</div>'
        f'<div class="label">{escape(l)}</div><div class="value">{escape(str(v))}</div>'
        f'<div class="sub">{escape(s)}</div></div>'
        for i, l, v, s, c in cards)
    _html(f'<div class="spp-grid">{body}</div>')


def section(title, sub=""):
    _html(f'<div class="spp-section">{escape(title)}</div>'
          + (f'<div class="spp-section-sub">{escape(sub)}</div>' if sub else ""))


def grade_for(score):
    for limit, grade, note, colour in [(90, "A+", "Outstanding", GOOD), (75, "A", "Excellent", GOOD),
                                       (60, "B", "Good", ACCENT_2), (50, "C", "Average", WARN),
                                       (40, "D", "Needs improvement", WARN)]:
        if score >= limit:
            return grade, note, colour
    return "F", "At risk of failing", BAD


def score_card(score, hint):
    grade, note, colour = grade_for(score)
    pct = max(0.0, min(float(score), 100.0))
    _html(f"""<div class="spp-score">
<div class="spp-ring" style="background: conic-gradient({colour} {pct * 3.6}deg, #1E2A47 0deg);">
<div class="spp-ring-inner"><b>{pct:.1f}</b><span>out of 100</span></div></div>
<div><div class="spp-grade" style="color:{colour}">Grade {escape(grade)}</div>
<div class="spp-note">{escape(note)}</div><div class="spp-hint">{escape(hint)}</div></div></div>""")


def sidebar_user(username, is_admin, mfa_on):
    pill = ('<span class="spp-pill" style="background:rgba(129,140,248,.18);color:#A5B4FC">ADMIN</span>'
            if is_admin else
            '<span class="spp-pill" style="background:rgba(34,211,238,.15);color:#67E8F9">STUDENT</span>')
    _html(f"""<div class="spp-user"><div class="spp-avatar">{escape(username[:1].upper())}</div>
<div><b>{escape(username)}</b><br>{pill}</div></div>""")
    items = ["⏱️ Auto-logout after 15 min idle"]
    if mfa_on:
        items.insert(0, "🔑 Two-factor login active")
    _html("".join(f'<div class="spp-side-item">{escape(t)}</div>' for t in items))


def login_header(subtitle="Sign in to continue"):
    _html(f"""<div class="spp-login"><div class="logo">🎓</div>
<h2>Student Performance Predictor</h2><p>{escape(subtitle)}</p></div>""")


def login_footer():
    _html('<p class="spp-foot">🔒 Argon2id passwords · two-factor login · encrypted data · audited<br>🌍 For security, your approximate sign-in location (city) is recorded.</p>')


def nice(name):
    return LABELS.get(name, name)


def bar_chart(labels, values, x_title, colours=None, height=240, sort=True):
    """Interactive horizontal bar chart (Altair) with rounded bars and hover."""
    data = pd.DataFrame({"label": labels, "value": values,
                         "colour": colours or [ACCENT] * len(labels)})
    try:
        import altair as alt
        y_sort = "-x" if sort else None
        chart = (alt.Chart(data)
                 .mark_bar(cornerRadiusEnd=6, height=22)
                 .encode(x=alt.X("value:Q", title=x_title),
                         y=alt.Y("label:N", sort=y_sort, title=None),
                         color=alt.Color("colour:N", scale=None),
                         tooltip=[alt.Tooltip("label:N", title=" "),
                                  alt.Tooltip("value:Q", title=x_title, format=".2f")])
                 .properties(height=height)
                 .configure_view(strokeWidth=0)
                 .configure_axis(grid=True, gridColor="#1E2A47", domain=False,
                                 labelColor=MUTED, titleColor=MUTED, labelFontSize=12))
        st.altair_chart(chart)
    except Exception:
        st.bar_chart(data.set_index("label")["value"], horizontal=True)


def column_chart(x_labels, values, x_title, y_title, height=240):
    """Interactive vertical bar chart (Altair) for distributions."""
    data = pd.DataFrame({"bin": x_labels, "count": values})
    try:
        import altair as alt
        chart = (alt.Chart(data)
                 .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6, color=ACCENT)
                 .encode(x=alt.X("bin:N", sort=None, title=x_title, axis=alt.Axis(labelAngle=0)),
                         y=alt.Y("count:Q", title=y_title),
                         tooltip=[alt.Tooltip("bin:N", title=x_title),
                                  alt.Tooltip("count:Q", title=y_title)])
                 .properties(height=height)
                 .configure_view(strokeWidth=0)
                 .configure_axis(gridColor="#1E2A47", domain=False,
                                 labelColor=MUTED, titleColor=MUTED, labelFontSize=12))
        st.altair_chart(chart)
    except Exception:
        st.bar_chart(data.set_index("bin")["count"])
