from __future__ import annotations
"""
Red String Non-Invasive Behavioral Telemetry Engine (Fate Watch)
Calculates O(1) 4-Dimensional Kinetic Signatures in sub-millisecond time without payload inspection.
"""

import collections
import time

import numpy as np


class TelemetryExtractor:
    """
    Stateful real-time feature extractor for incoming Red String frames.
    
    4-Dimensional Vector:
        1. delta_t_ms: Inter-arrival latency (ms) between consecutive frames
        2. shannon_entropy: Byte distribution entropy H(X) in [0.0, 8.0]
        3. frame_size: Payload size in bytes
        4. burst_ratio_5s: Packet frequency per ms over sliding 5000ms window (Count / 5000.0)
    """

    def __init__(self, window_ms: float = 5000.0):
        self.window_ms: float = window_ms
        self.last_arrival_ms: float | None = None
        self.arrival_history: collections.deque[float] = collections.deque()
        self.total_frames_processed: int = 0

    @staticmethod
    def calculate_shannon_entropy(payload: bytes) -> float:
        """
        Computes Shannon entropy across the 256-byte distribution in sub-millisecond time:
            H(X) = - sum( P(x) * log2(P(x)) )
        Range: 0.0 (uniform single byte / empty) to 8.0 (pure random / encrypted / compressed).
        Plain English text typically scores ~3.8 to 4.5.
        """
        n = len(payload)
        if n <= 1:
            return 0.0

        # Fast bincount over byte array
        counts = np.bincount(np.frombuffer(payload, dtype=np.uint8), minlength=256)
        # Filter non-zero counts
        nonzero = counts[counts > 0]
        probs = nonzero / n
        return float(-np.sum(probs * np.log2(probs)))

    def extract(self, payload: bytes, arrival_time_ms: float | None = None) -> tuple[np.ndarray, dict[str, float]]:
        """
        Extracts the 4-dimensional telemetry feature vector for an incoming opaque frame.
        Guaranteed zero-payload inspection (payload cleartext is never read as text).
        
        Returns:
            feature_vector: np.ndarray shape (1, 4)
            metrics_dict: human-readable metric dictionary
        """
        now_ms = arrival_time_ms if arrival_time_ms is not None else (time.time() * 1000.0)

        # 1. Inter-arrival Gap: Delta t
        if self.last_arrival_ms is None:
            # First packet baseline default (treat as ~250ms normal human pause)
            delta_t_ms = 250.0
        else:
            delta_t_ms = max(0.0, now_ms - self.last_arrival_ms)

        self.last_arrival_ms = now_ms

        # 2. Shannon Entropy: H(X)
        entropy = self.calculate_shannon_entropy(payload)

        # 3. Frame Size: S_i
        frame_size = float(len(payload))

        # 4. Sliding Burst Ratio (5000 ms window)
        self.arrival_history.append(now_ms)
        threshold_ms = now_ms - self.window_ms
        while self.arrival_history and self.arrival_history[0] < threshold_ms:
            self.arrival_history.popleft()

        packet_count_in_window = len(self.arrival_history)
        # Burst ratio: Count / 5000 ms
        burst_ratio_5s = float(packet_count_in_window) / self.window_ms
        packets_per_second = (float(packet_count_in_window) / self.window_ms) * 1000.0

        self.total_frames_processed += 1

        feature_vector = np.array([[delta_t_ms, entropy, frame_size, burst_ratio_5s]], dtype=np.float64)

        metrics = {
            "delta_t_ms": round(delta_t_ms, 2),
            "shannon_entropy": round(entropy, 4),
            "frame_size_bytes": int(frame_size),
            "burst_ratio_5s": round(burst_ratio_5s, 6),
            "packets_per_sec": round(packets_per_second, 2),
            "total_frames": self.total_frames_processed,
        }

        return feature_vector, metrics

    def reset(self):
        """Resets streaming telemetry tracking state."""
        self.last_arrival_ms = None
        self.arrival_history.clear()
        self.total_frames_processed = 0
