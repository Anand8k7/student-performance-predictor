import io
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_absolute_error

from analysis import load_data
from logger_config import get_logger
from models import Student
from secure_crypto import hmac_sha256, hmac_matches

logger = get_logger("predictor")

FEATURES = ["study_hours", "attendance", "internal1",
            "internal2", "assignment"]
TARGET = "semester_score"
MODEL_PATH = "saved_model/model.pkl"
SIG_PATH = "saved_model/model.sig"

# Called with (actor, action, detail) when the model file fails its check.
on_tamper = None


def _split(df):
    return train_test_split(df[FEATURES], df[TARGET],
                            test_size=0.2, random_state=42)


def train_model():
    os.makedirs("saved_model", exist_ok=True)
    df = load_data()
    X_train, X_test, y_train, y_test = _split(df)

    model = LinearRegression()
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    r2 = r2_score(y_test, predictions)
    mae = mean_absolute_error(y_test, predictions)

    buffer = io.BytesIO()
    joblib.dump(model, buffer)
    data = buffer.getvalue()
    with open(MODEL_PATH, "wb") as f:
        f.write(data)
    with open(SIG_PATH, "w") as f:          # HMAC-SHA256 signature of the model
        f.write(hmac_sha256("model_key", data))
    logger.info(f"Model trained and signed. R2={r2:.3f}, MAE={mae:.2f}")
    return model, r2, mae


def model_status():
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SIG_PATH)):
        return "missing"
    with open(MODEL_PATH, "rb") as f:
        data = f.read()
    with open(SIG_PATH) as f:
        signature = f.read().strip()
    return "verified" if hmac_matches("model_key", data, signature) else "tampered"


def load_model():
    """Load the model ONLY after its signature is verified. A tampered file is
    never unpickled: it is replaced by a freshly trained, signed model."""
    status = model_status()
    if status == "tampered":
        logger.critical("Model integrity check FAILED: retraining from data")
        if on_tamper:
            on_tamper("system", "model_tampered", "signature mismatch, retrained")
    if status != "verified":
        train_model()
    with open(MODEL_PATH, "rb") as f:
        data = f.read()
    with open(SIG_PATH) as f:
        if not hmac_matches("model_key", data, f.read().strip()):
            raise RuntimeError("Model integrity check failed")
    return joblib.load(io.BytesIO(data))


def predict_score(study_hours, attendance, internal1, internal2, assignment):
    # Check every value with the same rules used everywhere else.
    checked = Student("prediction", study_hours, attendance,
                      internal1, internal2, assignment)
    model = load_model()
    values = pd.DataFrame(
        [[checked.study_hours, checked.attendance, checked.internal1,
          checked.internal2, checked.assignment]],
        columns=FEATURES
    )
    result = model.predict(values)[0]
    return round(min(max(result, 0), 100), 1)


def explain(study_hours, attendance, internal1, internal2, assignment):
    """How many marks each input adds (linear model: coefficient x value)."""
    model = load_model()
    values = [study_hours, attendance, internal1, internal2, assignment]
    contributions = {f: round(float(c) * float(v), 1)
                     for f, c, v in zip(FEATURES, model.coef_, values)}
    return contributions, round(float(model.intercept_), 1)


def predict_many(df):
    model = load_model()
    return [round(min(max(p, 0), 100), 1) for p in model.predict(df[FEATURES])]


def compare_models():
    df = load_data()
    X_train, X_test, y_train, y_test = _split(df)
    rows = []
    for name, model in [("Linear Regression", LinearRegression()),
                        ("Random Forest", RandomForestRegressor(
                            n_estimators=200, random_state=42))]:
        model.fit(X_train, y_train)
        p = model.predict(X_test)
        rows.append({"Model": name,
                     "R² (higher is better)": round(r2_score(y_test, p), 3),
                     "MAE in marks (lower is better)":
                         round(mean_absolute_error(y_test, p), 2)})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    model, r2, mae = train_model()
    print("R2 score:", round(r2, 3))
    print("Average error (MAE):", round(mae, 2), "marks")
    print()
    print("How much each thing adds to the score:")
    for name, coef in zip(FEATURES, model.coef_):
        print(f"  {name}: {coef:.2f}")
    print()
    print("Prediction for a new student:")
    print(predict_score(6, 85, 22, 25, 17), "out of 100")
