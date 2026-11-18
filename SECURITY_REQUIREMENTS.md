# Security Requirements

**Project:** Student Performance Predictor
**Course:** Secure Software Engineering
**Group:** [Group name] | **Members:** [Name 1], [Name 2], [Name 3], [Name 4]
**Version:** 1.0 (draft) | **Date:** 18 November 2026
**Branch:** secure-se-improvements

## How to read this document

Each requirement has a status:
- **Existing**: already present in the live application (verified by reading the code).
- **Planned**: will be built in this project and tested before it is called implemented.

The "How we verify" column says how each rule will be proven. Test names are plans and will be updated with real results in TESTING_REPORT.md.

---

## 1. Authentication (who are you?)

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-AUTH-1 | The app shall require a valid login before showing any feature. | Planned | Automated test: access without login is refused. Manual check in a private browser window. |
| SR-AUTH-2 | Passwords shall be stored only as hashes (bcrypt or Argon2id). Plain-text passwords shall never be stored or logged. | Planned | Automated test: stored value differs from the password and passes hash verification. Code review. |
| SR-AUTH-3 | A wrong username or password shall give one general message that does not say which part was wrong. | Planned | Automated test: both failures return the same message. |
| SR-AUTH-4 | After 5 failed login attempts, further attempts shall be delayed. | Planned | Automated test: the sixth attempt is refused during the delay. |
| SR-AUTH-5 | The user shall be able to log out, and logging out shall clear the session. | Planned | Automated test and manual check: protected pages are unavailable after logout. |
| SR-AUTH-6 | No password, key or secret shall appear in the source code or in the GitHub repository. | Partly existing (no secrets exist today) | Repository search for secrets. Review of .gitignore. |

## 2. Authorization (what may you do?)

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-AUTHZ-1 | The app shall have two roles: Admin and User. | Planned | Automated test: each role is assigned correctly. |
| SR-AUTHZ-2 | A User may predict scores and view class insights. | Planned | Automated test. |
| SR-AUTHZ-3 | Only an Admin may view the student record table. | Planned | Automated test: User role is refused. |
| SR-AUTHZ-4 | Only an Admin may download the CSV file. | Planned | Automated test: User role is refused. |
| SR-AUTHZ-5 | The role check shall happen in the Python code on every page run, not only by hiding buttons. | Planned | Automated test: changing session values without logging in does not grant access. |
| SR-AUTHZ-6 | Each role shall get only the access it needs (least privilege). | Planned | Review of the role table. |

## 3. Input validation (is this data acceptable?)

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-VAL-1 | Marks shall be numbers within range: Internal 1 and 2 from 0 to 30, assignment from 0 to 20. | Existing | Automated tests with valid, low and high values. |
| SR-VAL-2 | Attendance shall be from 0 to 100. | Existing | Automated tests. |
| SR-VAL-3 | Study hours shall be from 0 to 24 and never negative. | Existing | Automated tests including a negative value. |
| SR-VAL-4 | Text, empty values and "not a number" values shall be rejected. | Existing | Automated tests. |
| SR-VAL-5 | Student names shall be 1 to 50 characters and contain only letters, numbers, spaces and simple punctuation. | Planned | Automated tests with empty, long and unusual names. |
| SR-VAL-6 | Every row loaded from a CSV file shall be validated before it is stored. | Planned | Automated test with a CSV containing one bad row. |
| SR-VAL-7 | The prediction function shall validate its inputs and not depend only on the interface sliders. | Planned | Automated test calling the function directly with bad values. |
| SR-VAL-8 | The study-hours limit shall be the same in the interface and in the validation code. | Planned | Code review and test. |

## 4. Database security

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-DB-1 | Every SQL query that uses a value shall use parameterized queries (placeholders). | Existing | Code review of every query. Automated test. |
| SR-DB-2 | SQL shall never be built by joining user text into a string. | Existing | Code review. Harmless demonstration of unsafe versus safe SQL. |
| SR-DB-3 | Text such as a SQL command typed as a name shall be stored or rejected as plain text and shall never run. | Planned | Automated test using a harmless injection sample on a test database. |
| SR-DB-4 | Tests shall use a separate temporary database and sample data, never the real one. | Planned | Review of the test setup. |

## 5. Data protection

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-DATA-1 | The database file and log files shall not be uploaded to GitHub. | Existing | Check .gitignore and repository files. |
| SR-DATA-2 | Secret files (such as .streamlit/secrets.toml and .env) shall be listed in .gitignore. | Planned | Check .gitignore. |
| SR-DATA-3 | The app shall show only the personal information that a role needs. | Planned | Manual review of each page per role. |
| SR-DATA-4 | Only synthetic sample data shall be used in tests, demonstrations and the public repository. | Existing | Review of data files. |
| SR-DATA-5 | A backup and data-retention practice shall be documented. | Planned | Section in SECURITY_REPORT.md. |

## 6. Error handling and logging

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-ERR-1 | Users shall see a friendly message on errors and never a stack trace. | Planned | Manual test with a forced error. Review of the code. |
| SR-ERR-2 | Error messages shall not reveal file paths, database names, credentials or settings. | Planned | Manual test. |
| SR-ERR-3 | The log shall record logins, failed logins, access denials and errors with date and time. | Partly existing (adds and training are logged) | Review of log lines after tests. |
| SR-ERR-4 | The log shall never contain passwords, hashes or student names. | Planned | Review of the log file and code. |

## 7. Configuration and dependencies

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-CFG-1 | Secrets shall be stored in Streamlit Secrets or environment variables, never in code. | Planned | Review of code and repository. |
| SR-CFG-2 | requirements.txt shall list pinned versions. | Planned | Check the file. |
| SR-CFG-3 | Dependencies shall be scanned for known vulnerabilities with a scanning tool (for example pip-audit). | Planned | Scan report saved in SECURITY_REPORT.md. |
| SR-CFG-4 | The app shall use only the packages it needs. | Existing | Review of requirements.txt. |

## 8. Testing

| ID | Requirement | Status | How we verify |
|---|---|---|---|
| SR-TEST-1 | Automated pytest tests shall cover login success and failure, password hashing, invalid inputs, SQL injection, unauthorized access, role limits and database operations. | Planned | Test run results in TESTING_REPORT.md. |
| SR-TEST-2 | Existing features shall be checked again after each change. | Planned | Manual checklist and test results. |

---

## Summary

| Area | Existing | Planned |
|---|---|---|
| Authentication | 0 | 6 |
| Authorization | 0 | 6 |
| Input validation | 4 | 4 |
| Database security | 2 | 2 |
| Data protection | 2 | 3 |
| Error handling and logging | 0 | 4 |
| Configuration | 1 | 3 |
| Testing | 0 | 2 |
