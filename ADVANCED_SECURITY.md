# Advanced Security Features (Version 2)

**Project:** Student Performance Predictor
**Group:** [Group name] | **Members:** [Name 1], [Name 2], [Name 3], [Name 4]

Version 2 adds 10 advanced security controls and 5 new features on top of the
Version 1 controls (`SECURITY_REPORT.md`). Every control has automated tests:
**74 pytest tests** in total, run on every push by a GitHub Actions pipeline.

## 1. Summary

| # | Control | Threat it answers | File | Tests |
|---|---|---|---|---|
| 1 | Two-factor login (TOTP, RFC 6238), mandatory for admins, with replay protection | Stolen or guessed admin password | `mfa.py`, `auth.py`, `app.py` | RFC test vectors, replay, wrong codes, lockout |
| 2 | Tamper-evident audit log (HMAC-SHA256 hash chain) | Attacker hides their actions (repudiation) | `audit.py` | Edit and delete detection |
| 3 | Encryption at rest (Fernet: AES-128-CBC + HMAC) for student names | Stolen database file | `secure_crypto.py`, `database.py` | Ciphertext on disk, wrong key unreadable |
| 4 | Model integrity: HMAC-signed model, verified before unpickling | Malicious pickle / model replacement (T11) | `predictor.py` | Tampered and unsigned models refused |
| 5 | Session timeout (15 minutes idle) | Unattended logged-in screen | `app.py` | App scenario test |
| 6 | CAPTCHA after 3 failed logins | Automated password guessing (bots) | `guards.py`, `app.py` | Wrong answer blocks login |
| 7 | Adversarial input detection (Isolation Forest) | Out-of-range or crafted inputs to the ML model | `anomaly.py` | Unusual input flagged, normal input not |
| 8 | Rate limiting (20 predictions per minute per session) | Flooding and model-extraction attacks | `guards.py` | Blocks then recovers |
| 9 | Differential privacy (Laplace mechanism, ε = 1.0 per statistic) for Users | Re-identifying a student from class statistics | `privacy.py` | Noise present, accuracy kept |
| 10b | Sign-in location tracking (city from IP, masked IP) with new-location alerts | Account takeover from a new place | `geo.py`, `audit.py`, `app.py` | IP parsing, masking, lookup failure, history |
| 10 | DevSecOps pipeline: pytest, Bandit, pip-audit, Gitleaks on every push | Insecure code, vulnerable libraries, leaked secrets | `.github/workflows/security.yml` | Runs in GitHub Actions |

### New features

| # | Feature | Who |
|---|---|---|
| 11 | Add a student, or import a CSV file (1 MB maximum), fully validated | Admin |
| 12 | At-risk students list with an adjustable threshold | Admin |
| 13 | Model comparison: Linear Regression vs Random Forest | Everyone |
| 14 | "Why this prediction?" chart (marks added by each factor) | Everyone |
| 15 | PDF prediction report | Everyone |
| + | Security dashboard: metrics, audit chain check, model check, encryption view, attack simulations | Admin |

## 2. How each control works

**Two-factor login.** After the password, admins enter a 6-digit code from an
authenticator app. Codes come from HMAC-SHA1 of the current 30-second time step
(RFC 6238). The code from the previous or next step is also accepted, to allow
for clock drift. A code that was already used is refused (replay protection).
Wrong codes count towards the same 5-try lockout as wrong passwords. An admin
account without a two-factor secret is not loaded at all (fail closed).

**Audit log hash chain.** Each entry stores `hash = HMAC(audit_key, previous hash
| time | actor | action | detail)`. Editing, deleting or reordering any entry
changes the hashes after it. Because the hash is keyed, an attacker cannot
recompute the chain without the secret key. Entries never contain passwords or
student names.

**Encryption at rest.** Names are encrypted with Fernet before they are stored.
The key lives only in Streamlit Secrets. A copy of the database file shows only
`gAAAA...` tokens.

**Model integrity.** When the model is trained, its bytes are signed with
HMAC-SHA256. Before every load, the signature is checked first. A tampered file
is never unpickled; it is replaced by a freshly trained, signed model, and the
event is written to the audit log.

**Differential privacy.** Users see class averages and a score histogram with
Laplace noise (sensitivity = range / n for means, 1 for counts). The noise is
drawn once per server process, so refreshing the page cannot average it away.
Admins see exact figures.

**Anomaly detection.** An Isolation Forest is trained on the 300 normal
records. Inputs far from them (for example 24 study hours with 2% attendance)
are answered with a warning and logged.

**Fail closed.** If any security key is missing or too short, the app shows
"Security keys are not set up" and nothing else.

## 3. Secrets set-up (one Colab cell)

```python
!pip install -q argon2-cffi "qrcode[pil]"
import base64, os, secrets, qrcode
from argon2 import PasswordHasher
from IPython.display import display
ph = PasswordHasher()
admin_pw = f"Admin-{secrets.randbelow(9000) + 1000}-Key"
student_pw = f"Student-{secrets.randbelow(9000) + 1000}-Key"
totp = base64.b32encode(os.urandom(20)).decode()
print("LOGIN -> admin:", admin_pw, "| student1:", student_pw)
print("\n----- PASTE BELOW INTO STREAMLIT SECRETS -----\n")
print(f'[security]\ndata_key = "{base64.urlsafe_b64encode(os.urandom(32)).decode()}"')
print(f'audit_key = "{secrets.token_hex(32)}"\nmodel_key = "{secrets.token_hex(32)}"\n')
print(f'[users."admin"]\npassword_hash = "{ph.hash(admin_pw)}"\nrole = "admin"\ntotp_secret = "{totp}"\n')
print(f'[users."student1"]\npassword_hash = "{ph.hash(student_pw)}"\nrole = "user"')
print("\nScan this QR code with Google Authenticator (admin two-factor):")
display(qrcode.make(f"otpauth://totp/StudentPredictor:admin?secret={totp}&issuer=StudentPredictor"))
```

Never commit the output. After setting up, clear the notebook output.

## 4. Demonstration (about 6 extra minutes)

| Step | Show | Say |
|---|---|---|
| 1 | Admin login: password, then the authenticator code | "Admins need two factors; a reused code is refused." |
| 2 | 3 wrong logins → CAPTCHA appears | "Bots are slowed down before the lockout." |
| 3 | Predict with 24 study hours and 2% attendance → warning | "Unusual inputs to the ML model are detected and logged." |
| 4 | "Why this prediction?" chart and PDF download | "Explainable, documented predictions." |
| 5 | Log in as User → Insights says "privacy-protected" | "Differential privacy hides any single student." |
| 6 | Security tab → Encryption: `gAAAA...` | "A stolen database shows no names." |
| 7 | Verify audit chain → intact; Simulate attacker edit → Verify → BROKEN at #1 | "Nobody can secretly change the log." |
| 8 | Simulate model replacement → status tampered → Predict → status verified | "A tampered model is never loaded." |
| 9 | GitHub → Actions tab → green pipeline | "Every push is tested and scanned automatically." |

## 5. Limits (honest)

- On free Streamlit hosting the database and audit log reset when the app restarts.
  A production version would store them in a managed database.
- The lockout, replay memory and rate limiter live in server memory and reset on restart.
- The CAPTCHA is a simple arithmetic check; it slows bots but does not stop advanced ones.
- Differential privacy covers the class averages and histogram; the correlation
  chart is shown exactly (it is an aggregate over 300 students).
- The training data is synthetic.
