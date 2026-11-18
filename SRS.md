# Software Requirements Specification (SRS)

**Project:** Student Performance Predictor
**Course:** Secure Software Engineering
**Group:** [Group] | **Members:** [Anand], [Rupesh]
**Version:** 1.0 (draft) | **Date:** 18 November 2026
**Branch:** secure-se-improvements

---

## 1. Introduction

### 1.1 Purpose
This document describes what the Student Performance Predictor must do, who will use it, and which security rules it must follow. It is written for the project group, the course teacher and future developers.

### 1.2 Scope
The Student Performance Predictor is a web application that predicts a student's semester exam score (out of 100) using internal marks, assignment marks, study hours and attendance. It also shows statistics and charts about a class. This project phase adds secure software engineering techniques to the existing live application without removing its current features.

### 1.3 Definitions
| Term | Meaning |
|---|---|
| Internal 1 / Internal 2 | Two internal exams, each out of 30 marks |
| Assignment | Assignment and project marks, out of 20 |
| Semester score | The final exam mark out of 100 (the value being predicted) |
| Authentication | Proving who you are (login) |
| Authorization | Deciding what you are allowed to do |
| Role | A group of permissions, such as Admin or User |
| Hashing | Turning a password into a scrambled value that cannot be reversed |
| SQL injection | An attack that sends malicious text into a database query |

### 1.3.1 Status labels used in this document
- **Existing**: already works in the current live application.
- **Planned**: will be built in this project. It is not available yet.

---

## 2. Overall Description

### 2.1 Product perspective
A web application written in Python using Streamlit for the user interface, SQLite for storage, pandas for analysis and scikit-learn (linear regression) for prediction. It is deployed on Streamlit Community Cloud from the `main` branch of the GitHub repository.

### 2.2 Users
| User type | Description | Status |
|---|---|---|
| Visitor | A person who opens the link without logging in | Existing (currently has full access) |
| User | A logged-in person who can predict scores and view class insights | Planned |
| Admin | A logged-in person who can also view student records and download data | Planned |

### 2.3 Operating environment
- Runs in a web browser (desktop or mobile).
- Server runs Python 3 on Streamlit Community Cloud.
- The database file is temporary on the hosting platform and is rebuilt from the CSV when the app starts fresh.

### 2.4 Constraints
- The existing live application must keep working during all changes.
- The dataset is synthetic (generated). No real student data is used in testing or demonstrations.
- Changes are made on a separate branch and tested before deployment.

### 2.5 Assumptions
- Users have a modern web browser and an internet connection.
- Secrets (such as password hashes) will be stored in Streamlit Secrets, not in the source code.

---

## 3. Functional Requirements

### 3.1 Prediction
| ID | Requirement | Status |
|---|---|---|
| FR-1 | The system shall accept study hours, attendance, Internal 1, Internal 2 and assignment marks. | Existing |
| FR-2 | The system shall predict the semester score out of 100 using a linear regression model. | Existing |
| FR-3 | The system shall show the predicted score between 0 and 100. | Existing |

### 3.2 Analysis and data
| ID | Requirement | Status |
|---|---|---|
| FR-4 | The system shall show summary statistics and the correlation of each factor with the semester score. | Existing |
| FR-5 | The system shall show a chart of the score distribution. | Existing |
| FR-6 | The system shall show a table of student records. | Existing |
| FR-7 | The system shall allow the student table to be downloaded as CSV. | Existing |

### 3.3 Storage and validation
| ID | Requirement | Status |
|---|---|---|
| FR-8 | The system shall store student records in an SQLite database. | Existing |
| FR-9 | The system shall reject marks, attendance and study hours outside their allowed ranges. | Existing |
| FR-10 | The system shall record important actions and errors in a log file. | Existing |

### 3.4 Security features
| ID | Requirement | Status |
|---|---|---|
| FR-11 | The system shall require login before any feature is used. | Planned |
| FR-12 | The system shall allow a logged-in person to log out. | Planned |
| FR-13 | The system shall store passwords only as secure hashes. | Planned |
| FR-14 | The system shall restrict student records and CSV download to the Admin role. | Planned |
| FR-15 | The system shall validate student names and every value before it reaches the database or model. | Planned |
| FR-16 | The system shall show friendly error messages and never show technical details to users. | Planned |
| FR-17 | The system shall have automated tests for its security features. | Planned |

---

## 4. Allowed Value Ranges

| Field | Allowed range |
|---|---|
| Study hours per day | 0 to 24 (the interface slider currently allows 0 to 12) |
| Attendance | 0 to 100 percent |
| Internal 1 | 0 to 30 |
| Internal 2 | 0 to 30 |
| Assignment | 0 to 20 |
| Semester score | 0 to 100 |
| Student name | Letters, numbers, spaces and basic punctuation, 1 to 50 characters (Planned) |

---

## 5. Non-Functional Requirements

| ID | Requirement | Status |
|---|---|---|
| NFR-1 | **Usability:** a new user can make a prediction in under one minute without training. | Existing |
| NFR-2 | **Performance:** a prediction appears within 3 seconds under normal load. | To be measured |
| NFR-3 | **Reliability:** the app shall keep working if the database or model file is missing, by rebuilding them. | Existing |
| NFR-4 | **Maintainability:** code is split into separate modules (database, model, analysis, interface). | Existing |
| NFR-5 | **Security:** see SECURITY_REQUIREMENTS.md. | Planned |
| NFR-6 | **Compatibility:** the app shall run on Streamlit Community Cloud without breaking changes. | Existing |

---

## 6. External Interfaces

- **User interface:** Streamlit web pages with tabs (Predict, Insights, Data).
- **Data files:** `data/students.csv` (input), `students.db` (SQLite), `saved_model/model.pkl` (trained model), `app.log` (log).
- **Hosting:** Streamlit Community Cloud, connected to the GitHub repository.

---

## 7. Out of Scope
- Using real student data.
- Predicting with models other than linear regression.
- Mobile app versions.

---

## 8. Traceability to Security Techniques

| Technique | Related requirements |
|---|---|
| Secure authentication | FR-11, FR-12, FR-13 |
| Input validation | FR-9, FR-15 |
| SQL injection prevention | FR-8, FR-15 |
| Authorization and roles | FR-14 |
| Data protection | FR-14, FR-16 |
| Secure error handling and logging | FR-10, FR-16 |
| Security testing | FR-17 |
| Secure configuration | NFR-5 |
