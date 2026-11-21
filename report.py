"""Builds a one-page PDF prediction report with matplotlib (no extra library)."""
import io

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                       # noqa: E402
from matplotlib.backends.backend_pdf import PdfPages  # noqa: E402

LABELS = {"study_hours": "Study hours / day", "attendance": "Attendance (%)",
          "internal1": "Internal 1 (/30)", "internal2": "Internal 2 (/30)",
          "assignment": "Assignment (/20)"}


def build_pdf(inputs, score, contributions, generated_by, generated_at):
    buffer = io.BytesIO()
    with PdfPages(buffer) as pdf:
        fig = plt.figure(figsize=(8.27, 11.69))
        fig.text(0.08, 0.94, "Student Performance Prediction Report",
                 fontsize=17, weight="bold")
        fig.text(0.08, 0.91, f"Generated {generated_at} by {generated_by}",
                 fontsize=9, color="gray")
        fig.text(0.08, 0.85, f"Predicted semester score: {score} / 100",
                 fontsize=14, weight="bold")
        y = 0.80
        for key, label in LABELS.items():
            fig.text(0.10, y, f"{label}: {inputs[key]}", fontsize=11)
            y -= 0.025
        ax = fig.add_axes([0.30, 0.12, 0.60, 0.40])
        names = [LABELS[k] for k in contributions]
        ax.barh(names, list(contributions.values()), color="#4C72B0")
        ax.set_xlabel("Marks added to the prediction")
        ax.set_title("Why this prediction?")
        fig.text(0.08, 0.05, "Synthetic training data. For guidance only.",
                 fontsize=8, color="gray")
        pdf.savefig(fig)
        plt.close(fig)
    return buffer.getvalue()
