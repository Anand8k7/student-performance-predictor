"""Differential privacy: statistics shown to Users get calibrated Laplace noise,
so no single student's marks can be worked out from them."""
import numpy as np


def dp_mean(values, lower, upper, epsilon, rng=None):
    rng = rng or np.random.default_rng()
    data = np.clip(np.asarray(values, dtype=float), lower, upper)
    if len(data) == 0:
        raise ValueError("No data")
    sensitivity = (upper - lower) / len(data)
    noisy = data.mean() + rng.laplace(0.0, sensitivity / epsilon)
    return float(np.clip(noisy, lower, upper))


def dp_histogram(values, bins, epsilon, rng=None):
    rng = rng or np.random.default_rng()
    counts, edges = np.histogram(np.asarray(values, dtype=float), bins=bins)
    noisy = counts + rng.laplace(0.0, 1.0 / epsilon, size=counts.shape)
    return np.clip(np.round(noisy), 0, None).astype(int), edges
