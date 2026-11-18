# Security Report

**Project:** Student Performance Predictor
**Course:** Secure Software Engineering
**Group:** [Group name] | **Members:** [Name 1], [Name 2], [Name 3], [Name 4]
**Date:** 18 November 2026 | **Branch:** secure-se-improvements

Related documents: `SRS.md`, `SECURITY_REQUIREMENTS.md`, `THREAT_MODEL.md`, `UML.md`, `DEMO.md`.

---

## 1. Summary

The original app was public: anyone with the link could use every feature, see all student records and download them as CSV. We added secure login, roles, stronger input validation, safe error handling, safe logging and secure configuration, and proved each control with tests. The dataset is synthetic (300 generated students); no real student data is used.

## 2. Before and after

| Area | Before | After |
|---|---|---|
| Access | Anyone with the link | Login required on every page run |
| Passwords | None | Argon2id hashes in Streamlit Secrets, never in GitHub |
| Password guessing | Unlimited | Username locked for 60 s after 5 failures |
| Login errors | n/a | One general message ("Incorrect username or password.") |
| Student records and CSV | Visible to everyone | Admin role only, checked in Python code |
| Names | Not checked | 1 to 50 characters, allow-list of characters |
| CSV import | Copied without checks | Every row validated; one bad row rejects the whole file |
| Prediction input | Trusted the sliders | Validated inside `predict_score` |
| SQL | Parameterized (already safe) | Still parameterized; proven with tests and a demo |
| Errors shown to users | Full traceback with file paths | Friendly message; tracebacks hidden (`showErrorDetails = "none"`) |
| Log file | Contained student names | No student names, passwords, hashes or unknown typed usernames |
| Dependencies | No versions | Pinned versions, scanned with pip-audit |
| .gitignore | 4 rules | Also blocks secrets, `.env`, keys, test leftovers |

## 3. Security controls implemented

| # | Technique | Where | Requirements |
|---|---|---|---|
| 1 | Secure authentication (Argon2id, lockout, generic message, logout) | `auth.py`, `app.py` | SR-AUTH-1 to 6 |
| 2 | Input validation (allow-list names, ranges, NaN, booleans, CSV rows, prediction) | `models.py`, `database.py`, `predictor.py` | SR-VAL-1 to 8 |
| 3 | SQL injection prevention (parameterized queries only) | `database.py`, `security_demo/sql_injection_demo.py` | SR-DB-1 to 4 |
| 4 | Authorization and roles (Admin, User; least privilege; server-side check) | `app.py` | SR-AUTHZ-1 to 6 |
| 5 | Data protection (secrets out of Git, role-limited data, synthetic data) | `.gitignore`, Streamlit Secrets, `app.py` | SR-DATA-1 to 5 |
| 6 | Secure error handling and logging | `app.py`, `.streamlit/config.toml`, `auth.py`, `database.py` | SR-ERR-1 to 4 |
| 7 | Secure configuration and dependencies | `requirements.txt`, Streamlit Secrets | SR-CFG-1 to 4 |
| 8 | Security testing | `tests/test_security.py` | SR-TEST-1, 2 |

### Roles

| Feature | Visitor (not logged in) | User | Admin |
|---|---|---|---|
| Predict score | No | Yes | Yes |
| Class insights (charts, summary) | No | Yes | Yes |
| Student record table | No | No | Yes |
| CSV download | No | No | Yes |

## 4. Findings fixed during the project

| ID | Finding | Severity | Status |
|---|---|---|---|
| F1 | No login; anyone could use the whole app | High | Fixed (login) |
| F2 | All student records and CSV download open to everyone | High | Fixed (Admin only) |
| F3 | Error pages showed tracebacks with file paths | Medium | Fixed |
| F4 | Unpinned dependencies | Medium | Fixed |
| F5 | `.gitignore` did not block secret files | Medium | Fixed |
| F6 | Names not validated; CSV rows and prediction inputs not validated | Medium | Fixed |
| F7 | Student names written to the log (`Added student: O'Brien`) | Low | Fixed |
| F8 | Text typed in the username box written to the log | Low | Fixed (only real account names are logged) |
| F9 | First error-hiding setting (`showErrorDetails = false`) still showed the traceback | Medium | Fixed with `"none"`; found by testing on the test app |
| F10 | Study-hours slider (0 to 12) did not match validation (0 to 24) | Low | Fixed |

## 5. Test results

| Test | Where run | Result |
|---|---|---|
| CSV and prediction validation | Google Colab | 19 of 19 passed |
| SQL injection demonstration (unsafe vs safe query) | Google Colab | 8 of 8 passed |
| Login logic (`auth.py`) | Google Colab | 30 of 30 passed |
| Automated pytest suite (`tests/test_security.py`) | Google Colab | [fill in: e.g. 35 passed] |
| Dependency scan (pip-audit, pinned packages) | Google Colab | No known vulnerabilities found (18 Nov 2026) |
| Manual test on test deployment | Streamlit Cloud (branch copy) | Login, logout, wrong password, Admin 3 tabs, User 2 tabs: passed |

Key evidence from the SQL demo: the attack text `' OR '1'='1` returned **all 3 rows** through the unsafe query and **0 rows** through the parameterized query.

## 6. Configuration and secrets

- Accounts (username, Argon2id hash, role) are stored only in **Streamlit Secrets**. The repository contains no passwords or hashes.
- If Secrets are missing or broken, the app shows "Login is not set up" and nobody can log in (fail closed).
- Pinned versions: pandas 3.1.1, numpy 2.5.5, scikit-learn 1.9.1, streamlit 1.67.0, matplotlib 3.11.2, joblib 1.6.0, argon2-cffi 25.1.0.
- GitHub account protected with two-factor authentication: [yes / no].

## 7. Backup and data retention

- The database is rebuilt from `data/students.csv` when the app starts fresh, so the CSV in Git is the backup.
- The data is synthetic. If real data is ever used, it must not be stored in the public repository, and this report and the threat model must be reviewed first.
- `app.log` exists only on the server and is lost on restart; it contains no personal data.
- Password hashes are kept only in Streamlit Secrets and a private note of the administrator. To reset a password, a new hash is generated and Secrets are updated.

## 8. Known limits (residual risk)

- The lockout counter is in memory; an app restart clears it. It is per username, not per visitor.
- An attacker can lock a real account for 60 seconds by failing on purpose (accepted).
- Only the six main packages and argon2-cffi are pinned; about 40 sub-packages still float. Pinning with hashes (pip-compile) is future work.
- The dependency scan only finds publicly reported vulnerabilities.
- `model.pkl` is loaded with joblib (pickle). Only repository owners can change it, and it is rebuilt from code if missing.
- Sessions rely on Streamlit Community Cloud's security.
- Demo passwords used during development were shared in screenshots and chat, so they were replaced with new ones before going live.

## 9. Future work

- Multi-factor login, password change from the app, per-visitor rate limiting.
- Hash-pinned dependencies and automatic scanning on every push (GitHub Actions).
- An audit log stored outside the app server.
