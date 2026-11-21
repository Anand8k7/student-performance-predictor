"""Adversarial / unusual input detection with an Isolation Forest trained on
the normal student data. Flagged inputs are still answered but logged."""
import pandas as pd
from sklearn.ensemble import IsolationForest


class InputAnomalyDetector:
    def __init__(self, df, features, contamination=0.02, random_state=42):
        self.features = list(features)
        self.model = IsolationForest(contamination=contamination,
                                     random_state=random_state)
        self.model.fit(df[self.features])

    def check(self, values):
        row = pd.DataFrame([[float(values[f]) for f in self.features]],
                           columns=self.features)
        score = float(self.model.decision_function(row)[0])
        return score < 0, round(score, 3)
