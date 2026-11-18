# Demonstration Script (about 10 minutes)

**Group:** [Group name]

## Before the demo
- Open the app link and log out.
- Have the Admin and User passwords ready in a private note (never on screen).
- Open the Colab notebook with the SQL injection demo and pytest results.
- Clear any Colab output that shows hashes.

## Running order

| Time | Who | What to show | What to say |
|---|---|---|---|
| 0:00 | Member 1 | Old app screenshot (no login, Data tab open) | "Anyone with the link could see every student record." |
| 1:00 | Member 1 | `THREAT_MODEL.md` threat table | "We listed 14 threats; five were High risk." |
| 2:00 | Member 2 | Login page, wrong password | "Same message for wrong user or wrong password, so attackers learn nothing." |
| 3:00 | Member 2 | 5 wrong tries, then lockout message | "Password guessing is slowed down." |
| 4:00 | Member 2 | Log in as User: only 2 tabs | "Least privilege: Users cannot see records." |
| 5:00 | Member 3 | Log in as Admin: 3 tabs, CSV download, Log out | "Role is checked in Python on every page run." |
| 6:00 | Member 3 | SQL injection demo output (3 rows vs 0 rows) | "Placeholders keep typed text as data, never as commands." |
| 7:30 | Member 4 | pytest output (all passed) | "Every control is proven by automated tests." |
| 8:30 | Member 4 | `SECURITY_REPORT.md` before/after table and limits | "We also list what is still not perfect." |
| 9:30 | All | Questions | |

## Likely teacher questions

| Question | Short answer |
|---|---|
| Why Argon2id and not SHA-256? | Argon2id is slow and memory-hard on purpose, so guessing passwords is expensive. SHA-256 is fast, which helps attackers. |
| Where are the passwords stored? | Nowhere. Only Argon2id hashes, in Streamlit Secrets, not in GitHub. |
| Why the same error message? | So an attacker cannot find out which usernames exist (user enumeration). |
| Can a User reach the Data tab by changing the page? | No. The data is only sent when the server-side role check says Admin. A test fakes the role and is refused. |
| How do you stop SQL injection? | Parameterized queries everywhere, plus name validation as a second layer. |
| What happens if Secrets are missing? | The app fails closed: nobody can log in. |
| What are the weaknesses left? | In-memory lockout, sub-dependencies not pinned, synthetic data only. See the report, section 8. |

## Evidence checklist
- [ ] Login page and wrong-password screenshot
- [ ] Lockout message screenshot
- [ ] User view (2 tabs) and Admin view (3 tabs)
- [ ] Hidden error message screenshot ("redacted to prevent data leaks")
- [ ] SQL injection demo output
- [ ] pytest output
- [ ] pip-audit result
- [ ] GitHub two-factor authentication enabled (codes hidden)
