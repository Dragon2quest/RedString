"""
Red String Edge Anomaly Detection Engine (Isolation Forest)
Sub-millisecond Edge ML scoring for behavioral kinetics and zero-trust quarantine decisions.
"""

import os
import time

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

# Model storage path
DEFAULT_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "isolation_forest_boundary.joblib")

# Anomaly Scoring Thresholds
# IsolationForest decision_function returns float in approx [-0.5, 0.5] or normalized [-1.0, 1.0]
# Higher is more normal; negative indicates anomaly.
THRESHOLD_NOMINAL_BASELINE = 0.05    # Score >= 0.05 is safe green
THRESHOLD_WARNING = 0.0             # 0.0 to 0.05 is yellow monitoring
THRESHOLD_QUARANTINE = -0.05        # Score < -0.05 triggers immediate quarantine sever


class EdgeAnomalyEngine:
    """
    Sub-millisecond inference engine loaded via joblib.
    Evaluates 4D feature vectors: [delta_t_ms, shannon_entropy, frame_size, burst_ratio_5s]
    """

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.model: IsolationForest | None = None
        self._load_or_train()

    def _load_or_train(self):
        """Loads model from disk or trains a fresh baseline model if not found."""
        if os.path.exists(self.model_path):
            t0 = time.perf_counter()
            self.model = joblib.load(self.model_path)
            self._extract_tree_structures()
            t_load_ms = (time.perf_counter() - t0) * 1000.0
            print(f"[*] Edge Anomaly Engine cold-booted from {self.model_path} in {t_load_ms:.2f}ms")
        else:
            print("[*] Pre-fitted model not found. Generating baseline training dynamics...")
            self.train_baseline()

    def train_baseline(self, num_samples: int = 4000) -> float:
        """
        Trains an unsupervised IsolationForest on simulated human sync dynamics:
          - Human keystrokes: Delta t in [50, 400] ms, size 1-4 bytes, entropy ~2.0-4.0
          - Clipboard pushes: Delta t in [800, 15000] ms, size 15B-25KB, entropy ~3.8-4.8
          - Controlled file chunks: Delta t ~20-60 ms, size 64KB, entropy ~5.5-7.2
          - Normal sliding burst ratio: < 0.015 (<= 75 packets per 5s)
        """
        np.random.seed(42)

        # 1. Normal keystrokes (45% of baseline)
        n_keys = int(num_samples * 0.45)
        dt_keys = np.random.normal(loc=160.0, scale=60.0, size=n_keys).clip(30.0, 800.0)
        ent_keys = np.random.normal(loc=3.2, scale=0.6, size=n_keys).clip(1.5, 4.5)
        size_keys = np.random.choice([1.0, 2.0, 3.0, 4.0], size=n_keys)
        burst_keys = np.random.uniform(0.0002, 0.003, size=n_keys)
        keys_data = np.column_stack([dt_keys, ent_keys, size_keys, burst_keys])

        # 2. Normal clipboard sync (40% of baseline)
        n_clip = int(num_samples * 0.40)
        dt_clip = np.random.exponential(scale=2500.0, size=n_clip).clip(500.0, 30000.0)
        ent_clip = np.random.normal(loc=4.2, scale=0.3, size=n_clip).clip(3.5, 5.0)
        size_clip = np.random.exponential(scale=512.0, size=n_clip).clip(10.0, 32000.0)
        burst_clip = np.random.uniform(0.0002, 0.002, size=n_clip)
        clip_data = np.column_stack([dt_clip, ent_clip, size_clip, burst_clip])

        # 3. Legitimate controlled chunked transfer (15% of baseline)
        n_chunk = num_samples - n_keys - n_clip
        dt_chunk = np.random.normal(loc=35.0, scale=10.0, size=n_chunk).clip(15.0, 80.0)
        ent_chunk = np.random.normal(loc=6.2, scale=0.5, size=n_chunk).clip(4.8, 7.4)
        size_chunk = np.full(n_chunk, 65536.0) # 64 KB
        burst_chunk = np.random.uniform(0.005, 0.015, size=n_chunk)
        chunk_data = np.column_stack([dt_chunk, ent_chunk, size_chunk, burst_chunk])

        X_train = np.vstack([keys_data, clip_data, chunk_data])

        # Fit IsolationForest (optimized for edge memory & sub-ms latency)
        clf = IsolationForest(
            n_estimators=40,
            contamination=0.02, # 2% contamination allowance
            max_samples=128,
            random_state=42,
            n_jobs=1,
        )
        clf.fit(X_train)

        # Save model
        joblib.dump(clf, self.model_path)
        self.model = clf
        self._extract_tree_structures()
        print(f"[+] Trained & serialized baseline model to {self.model_path}")

        # Benchmark inference latency
        benchmark_sample = np.array([[150.0, 4.1, 128.0, 0.001]], dtype=np.float64)
        t_start = time.perf_counter()
        for _ in range(100):
            self._fast_decision_function(benchmark_sample)
        avg_latency_ms = ((time.perf_counter() - t_start) / 100.0) * 1000.0
        print(f"[+] Validated Edge Inference Latency: {avg_latency_ms:.3f} ms (Target < 1.4 ms)")
        return avg_latency_ms

    def _extract_tree_structures(self):
        """Pre-extracts raw tree structures for sub-millisecond traversal without Python wrapper overhead."""
        self._tree_data = []
        if self.model and hasattr(self.model, "estimators_"):
            for est in self.model.estimators_:
                t = est.tree_
                self._tree_data.append((
                    t.children_left,
                    t.children_right,
                    t.feature,
                    t.threshold,
                    t.n_node_samples,
                ))
            n_samples = getattr(self.model, "max_samples_", 128)
            self._c_factor = self._average_path_length(n_samples)
            self._offset = getattr(self.model, "offset_", -0.5)

    @staticmethod
    def _average_path_length(n: int) -> float:
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        return 2.0 * (np.log(n - 1.0) + 0.5772156649) - 2.0 * (n - 1.0) / n

    def _fast_decision_function(self, sample: np.ndarray) -> float:
        """Executes sub-ms decision scoring matching IsolationForest mathematically."""
        if not hasattr(self, "_tree_data") or not self._tree_data:
            self._extract_tree_structures()

        flat = sample.ravel()
        total_depth = 0.0
        for cl, cr, feat, th, n_samp in self._tree_data:
            node = 0
            d = 0
            while cl[node] != -1:
                if flat[feat[node]] <= th[node]:
                    node = cl[node]
                else:
                    node = cr[node]
                d += 1
            total_depth += d + self._average_path_length(n_samp[node])

        mean_depth = total_depth / len(self._tree_data)
        return - (2.0 ** (- (mean_depth / self._c_factor))) - self._offset

    def score(self, feature_vector: np.ndarray) -> tuple[float, dict[str, any]]:
        """
        Executes sub-ms decision scoring on a 4-dimensional feature vector.
        
        Returns:
            score: float decision value (normalized [-1.0, 1.0])
            details: dictionary containing quarantine verdicts and latency
        """
        if self.model is None or not hasattr(self, "_tree_data"):
            self._load_or_train()

        t0 = time.perf_counter()
        raw_score = float(self._fast_decision_function(feature_vector))
        inference_latency_ms = (time.perf_counter() - t0) * 1000.0

        # Normalization: map raw score into calibrated [-1.0, +1.0]
        normalized_score = float(np.tanh(raw_score * 3.5))

        # Quarantine determination
        if normalized_score >= THRESHOLD_NOMINAL_BASELINE:
            verdict = "NOMINAL_ALLOW"
            quarantine = False
            status_color = "#00F59B"  # Emerald
            reason = "Kinetics conform to verified human baseline dynamics."
        elif normalized_score >= THRESHOLD_WARNING:
            verdict = "MONITORED_FLEX"
            quarantine = False
            status_color = "#FFB703"  # Amber
            reason = "Minor kinetic deviation detected. Elevated telemetry monitoring."
        else:
            verdict = "QUARANTINE_SEVER"
            quarantine = True
            status_color = "#FF003C"  # Crimson
            reason = "Anomalous transmission kinetic deviation (exfiltration burst / unauthorized entropy)."

        details = {
            "score": round(normalized_score, 4),
            "raw_score": round(raw_score, 6),
            "verdict": verdict,
            "quarantine_triggered": quarantine,
            "status_color": status_color,
            "reason": reason,
            "inference_latency_ms": round(inference_latency_ms, 3),
        }
        return normalized_score, details
