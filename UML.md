# UML Diagrams

**Project:** Student Performance Predictor (secure version)

GitHub draws these diagrams automatically from the Mermaid code.

## 1. Use case diagram

```mermaid
flowchart LR
    V(["Visitor"])
    U(["User"])
    A(["Admin"])
    subgraph App["Student Performance Predictor"]
        L(("Log in"))
        O(("Log out"))
        P(("Predict semester score"))
        I(("View class insights"))
        R(("View student records"))
        D(("Download CSV"))
    end
    V --> L
    U --> L
    U --> O
    U --> P
    U --> I
    A --> L
    A --> O
    A --> P
    A --> I
    A --> R
    A --> D
```

## 2. Class diagram

```mermaid
classDiagram
    class Student {
        +name
        +study_hours
        +attendance
        +internal1
        +internal2
        +assignment
        +semester_score
        +to_tuple()
        -_check_name(name)
        -_check(value, low, high, label)
    }
    class Database {
        +db_name
        +add_student(student)
        +load_csv(path)
        +get_all()
        -_validate_csv(df)
        -_create_table()
    }
    class LoginThrottle {
        +max_attempts
        +lockout_seconds
        +seconds_locked(key)
        +record_failure(key)
        +record_success(key)
    }
    class auth {
        <<module>>
        +hash_password(password)
        +verify_password(password, hash)
        +load_users(raw)
        +authenticate(username, password, users, throttle)
    }
    class predictor {
        <<module>>
        +train_model()
        +predict_score(...)
    }
    Database ..> Student : validates rows with
    predictor ..> Student : validates input with
    auth ..> LoginThrottle : uses
```

## 3. Activity diagram (login and access)

```mermaid
flowchart TD
    S([Open app]) --> C{Accounts in Secrets valid?}
    C -- No --> X[Show 'Login is not set up'] --> E([Stop: nobody gets in])
    C -- Yes --> Q{Already logged in and role still valid?}
    Q -- Yes --> APP[Show app]
    Q -- No --> F[Show login form]
    F --> K{Username locked?}
    K -- Yes --> W[Show 'Too many failed attempts'] --> F
    K -- No --> H{Password matches Argon2id hash?}
    H -- No --> G[Count failure, show general message] --> F
    H -- Yes --> APP
    APP --> RL{Role is Admin?}
    RL -- Yes --> T3[Predict, Insights, Data and CSV]
    RL -- No --> T2[Predict and Insights only]
```

## 4. Architecture diagram

```mermaid
flowchart LR
    B["Browser"] -->|HTTPS| ST["Streamlit app (app.py)"]
    SE["Streamlit Secrets: usernames, hashes, roles"] --> ST
    ST --> AU["auth.py: Argon2id, lockout"]
    ST --> AN["analysis.py"]
    ST --> PR["predictor.py + model.pkl"]
    AN --> DB[("SQLite students.db")]
    PR --> MO["models.py: validation"]
    DB --> MO
    ST --> LG["app.log (no personal data)"]
    GH["GitHub repository (no secrets)"] -->|deploys| ST
```
