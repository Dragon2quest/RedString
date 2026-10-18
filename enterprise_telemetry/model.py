"""
Red String Edge Anomaly Detection Engine (Native Isolation Forest)
Sub-millisecond Edge ML scoring for behavioral kinetics and zero-trust quarantine decisions.
Optimized for IBM LinuxONE (s390x) and edge enclaves with pure-NumPy native isolation trees.
"""
from __future__ import annotations

import math
import os
import time
import joblib
import numpy as np

# Model storage path
DEFAULT_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL_PATH = os.path.join(DEFAULT_MODEL_DIR, "isolation_forest_boundary.joblib")

# Anomaly Scoring Thresholds (per Red String Enterprise Specification & SKILL.md)
THRESHOLD_NOMINAL_BASELINE = 0.0     # Score >= 0.0 is safe green
THRESHOLD_WARNING = -0.10            # -0.10 to 0.0 is yellow monitoring
THRESHOLD_QUARANTINE = -0.15         # Score < -0.15 triggers immediate quarantine sever


class EdgeAnomalyEngine:
    """
    Sub-millisecond inference engine loaded via joblib.
    Evaluates 4D feature vectors: [delta_t_ms, shannon_entropy, frame_size, burst_ratio_5s]
    """

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self._tree_data = []
        self._c_factor = 1.0
        self._offset = -0.5
        self.model = None
        self._load_or_train()

    def _load_or_train(self):
        """Loads model from disk or trains a fresh baseline model if not found."""
        if os.path.exists(self.model_path):
            try:
                t0 = time.perf_counter()
                loaded = joblib.load(self.model_path)
                if isinstance(loaded, dict) and "trees" in loaded:
                    self._tree_data = loaded["trees"]
                    self._c_factor = loaded.get("c_factor", self._average_path_length(128))
                    self._offset = loaded.get("offset", -0.5)
                    self.model = loaded
                    t_load_ms = (time.perf_counter() - t0) * 1000.0
                    print(f"[*] Edge Anomaly Engine cold-booted from {self.model_path} in {t_load_ms:.2f}ms")
                    return
            except Exception as e:
                print(f"[!] Warning: Failed loading existing model ({e}). Re-training fresh baseline...")

        print("[*] Pre-fitted model not found. Generating baseline training dynamics...")
        self.train_baseline()

    def train_baseline(self, num_samples: int = 4000) -> float:
        """
        Trains an unsupervised IsolationForest on simulated human sync dynamics:
          - Human keystrokes: Delta t in [50, 400] ms, size 1-4 bytes, entropy 0.0-2.0
          - Clipboard pushes: Delta t in [800, 15000] ms, size 15B-25KB, entropy ~3.5-5.0
          - Controlled file chunks: Delta t ~20-60 ms, size 64KB, entropy ~5.5-7.2
          - Normal sliding burst ratio: < 0.015 (<= 75 packets per 5s)
        """
        np.random.seed(42)

        # 1. Normal keystrokes (45% of baseline)
        n_keys = int(num_samples * 0.45)
        dt_keys = np.random.normal(loc=160.0, scale=60.0, size=n_keys).clip(30.0, 800.0)
        # Keystrokes are 1-4 bytes; single-char has entropy 0.0, multi-byte has low entropy 0.0-2.0
        ent_keys = np.random.choice([0.0, 0.0, 0.0, 0.8, 1.0, 1.58, 2.0], size=n_keys)
        size_keys = np.random.choice([1.0, 1.0, 1.0, 2.0, 3.0, 4.0], size=n_keys)
        burst_keys = np.random.uniform(0.0002, 0.003, size=n_keys)
        keys_data = np.column_stack([dt_keys, ent_keys, size_keys, burst_keys])

        # 2. Normal clipboard sync (40% of baseline)
        n_clip = int(num_samples * 0.40)
        dt_clip = np.random.exponential(scale=2500.0, size=n_clip).clip(300.0, 30000.0)
        ent_clip = np.random.normal(loc=4.2, scale=0.4, size=n_clip).clip(3.2, 5.2)
        size_clip = np.random.exponential(scale=512.0, size=n_clip).clip(10.0, 32000.0)
        burst_clip = np.random.uniform(0.0002, 0.002, size=n_clip)
        clip_data = np.column_stack([dt_clip, ent_clip, size_clip, burst_clip])

        # 3. Legitimate controlled chunked transfer (15% of baseline)
        n_chunk = num_samples - n_keys - n_clip
        dt_chunk = np.random.normal(loc=35.0, scale=10.0, size=n_chunk).clip(15.0, 80.0)
        ent_chunk = np.random.normal(loc=6.2, scale=0.5, size=n_chunk).clip(4.8, 7.4)
        size_chunk = np.full(n_chunk, 65536.0)
        burst_chunk = np.random.uniform(0.005, 0.015, size=n_chunk)
        chunk_data = np.column_stack([dt_chunk, ent_chunk, size_chunk, burst_chunk])

        X_train = np.vstack([keys_data, clip_data, chunk_data])

        n_estimators = 40
        max_samples = 128
        max_depth = int(np.ceil(np.log2(max(max_samples, 2))))
        self._c_factor = self._average_path_length(max_samples)

        self._tree_data = []
        for _ in range(n_estimators):
            idx = np.random.choice(len(X_train), size=min(max_samples, len(X_train)), replace=False)
            tree_root = self._build_tree(X_train[idx], 0, max_depth)
            cl, cr, feat, th, ns = self._flatten_tree(tree_root)
            self._tree_data.append((cl, cr, feat, th, ns))

        # Set offset so baseline training dynamics are nominally positive
        train_scores = [self._raw_path_score(X_train[i]) for i in range(min(500, len(X_train)))]
        self._offset = float(np.percentile(train_scores, 2)) - 0.02

        model_dict = {
            "trees": self._tree_data,
            "c_factor": self._c_factor,
            "offset": self._offset,
            "max_samples": max_samples,
        }
        self.model = model_dict
        joblib.dump(model_dict, self.model_path)
        print(f"[+] Trained & serialized baseline model to {self.model_path}")

        # Benchmark inference latency
        benchmark_sample = np.array([[150.0, 4.1, 128.0, 0.001]], dtype=np.float64)
        t_start = time.perf_counter()
        for _ in range(100):
            self._fast_decision_function(benchmark_sample)
        avg_latency_ms = ((time.perf_counter() - t_start) / 100.0) * 1000.0
        print(f"[+] Validated Edge Inference Latency: {avg_latency_ms:.3f} ms (Target < 1.4 ms)")
        return avg_latency_ms

    def _build_tree(self, X: np.ndarray, depth: int, max_depth: int) -> dict:
        n_samples = len(X)
        if depth >= max_depth or n_samples <= 1:
            return {"leaf": True, "n_samples": n_samples}
        mins = X.min(axis=0)
        maxs = X.max(axis=0)
        valid = np.where(maxs > mins)[0]
        if len(valid) == 0:
            return {"leaf": True, "n_samples": n_samples}
        feat = int(np.random.choice(valid))
        th = float(np.random.uniform(mins[feat], maxs[feat]))
        l_idx = X[:, feat] <= th
        r_idx = ~l_idx
        if not np.any(l_idx) or not np.any(r_idx):
            return {"leaf": True, "n_samples": n_samples}
        return {
            "leaf": False,
            "feat": feat,
            "th": th,
            "n_samples": n_samples,
            "left": self._build_tree(X[l_idx], depth + 1, max_depth),
            "right": self._build_tree(X[r_idx], depth + 1, max_depth),
        }

    def _flatten_tree(self, root: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        cl, cr, feat, th, ns = [], [], [], [], []
        def traverse(node):
            idx = len(feat)
            feat.append(node.get("feat", -2))
            th.append(node.get("th", 0.0))
            ns.append(node.get("n_samples", 1))
            cl.append(-1)
            cr.append(-1)
            if not node["leaf"]:
                cl[idx] = traverse(node["left"])
                cr[idx] = traverse(node["right"])
            return idx
        traverse(root)
        return (
            np.array(cl, dtype=np.int32),
            np.array(cr, dtype=np.int32),
            np.array(feat, dtype=np.int32),
            np.array(th, dtype=np.float64),
            np.array(ns, dtype=np.int32),
        )

    @staticmethod
    def _average_path_length(n: int) -> float:
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        return 2.0 * (np.log(n - 1.0) + 0.5772156649) - 2.0 * (n - 1.0) / n

    def _raw_path_score(self, sample: np.ndarray) -> float:
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
        return - (2.0 ** (- (mean_depth / self._c_factor)))

    def _fast_decision_function(self, sample: np.ndarray) -> float:
        return self._raw_path_score(sample) - self._offset

    def score(self, feature_vector: np.ndarray) -> tuple[float, dict[str, any]]:
        if not self._tree_data:
            self._load_or_train()

        t0 = time.perf_counter()
        raw_score = float(self._fast_decision_function(feature_vector))
        inference_latency_ms = (time.perf_counter() - t0) * 1000.0

        normalized_score = float(np.tanh(raw_score * 3.5))

        if normalized_score >= THRESHOLD_NOMINAL_BASELINE:
            verdict = "NOMINAL_ALLOW"
            quarantine = False
            status_color = "#00F59B"
            reason = "Kinetics conform to verified human baseline dynamics."
        elif normalized_score >= THRESHOLD_WARNING:
            verdict = "MONITORED_FLEX"
            quarantine = False
            status_color = "#FFB703"
            reason = "Minor kinetic deviation detected. Elevated telemetry monitoring."
        else:
            verdict = "QUARANTINE_SEVER"
            quarantine = True
            status_color = "#FF003C"
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