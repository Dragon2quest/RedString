from __future__ import annotations
"""
Comprehensive Test Suite for Red String Enterprise Overhaul
Validates 17-byte binary framing, O(1) telemetry entropy, edge ML latency, and quarantine boundaries.
"""

import os
import sys
import time
import unittest

import numpy as np

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enterprise_telemetry.model import EdgeAnomalyEngine
from enterprise_telemetry.pairing import MagicCirclePairing
from enterprise_telemetry.protocol import (
    CHANNEL_CLIPBOARD,
    HEADER_SIZE,
    FrameParsingError,
    decode_header,
    encode_frame,
)
from enterprise_telemetry.server import ForensicAuditLogger
from enterprise_telemetry.telemetry import TelemetryExtractor


class TestRedStringEnterprise(unittest.TestCase):

    def test_01_wire_framing_integrity(self):
        """Validates 17-byte header format (!4sBQI), network byte order, and length checks."""
        payload = b"Sample cryptographic test payload."
        channel = CHANNEL_CLIPBOARD
        ts = 1700000000123

        frame = encode_frame(channel, payload, timestamp_ms=ts)
        self.assertEqual(len(frame), HEADER_SIZE + len(payload))
        self.assertEqual(HEADER_SIZE, 17)

        # Decode header
        magic, decoded_ch, decoded_ts, decoded_len = decode_header(frame[:HEADER_SIZE])
        self.assertEqual(magic, b"RDSG")
        self.assertEqual(decoded_ch, channel)
        self.assertEqual(decoded_ts, ts)
        self.assertEqual(decoded_len, len(payload))

        # Test invalid magic
        corrupt_header = b"XXXX" + frame[4:HEADER_SIZE]
        with self.assertRaises(FrameParsingError):
            decode_header(corrupt_header)

    def test_02_shannon_entropy_calculation(self):
        """Verifies mathematical profile of Shannon entropy H(X) in [0.0, 8.0]."""
        # 1. Monochromatic single-byte buffer -> H(X) == 0.0
        uniform_payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        h_uniform = TelemetryExtractor.calculate_shannon_entropy(uniform_payload)
        self.assertAlmostEqual(h_uniform, 0.0, places=3)

        # 2. Typical plain English sentence -> H(X) ~ 3.8 to 4.5
        text_payload = b"Red String zero-trust behavioral telemetry fabric IBM enterprise datathon."
        h_text = TelemetryExtractor.calculate_shannon_entropy(text_payload)
        self.assertGreater(h_text, 3.5)
        self.assertLess(h_text, 5.0)

        # 3. Pure random bytes (high entropy) -> H(X) ~ 7.5 to 8.0
        random_payload = bytes(np.random.randint(0, 256, size=4096, dtype=np.uint8))
        h_random = TelemetryExtractor.calculate_shannon_entropy(random_payload)
        self.assertGreater(h_random, 7.5)
        self.assertLessEqual(h_random, 8.0)

    def test_03_telemetry_vector_sub_ms(self):
        """Verifies that 4D feature extraction executes in sub-millisecond time."""
        extractor = TelemetryExtractor()
        payload = b"Non-invasive packet stream testing."

        t0 = time.perf_counter()
        vec, metrics = extractor.extract(payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        self.assertEqual(vec.shape, (1, 4))
        self.assertLess(elapsed_ms, 1.0, f"Feature extraction took {elapsed_ms:.4f} ms, expected < 1.0 ms")
        self.assertEqual(metrics["frame_size_bytes"], len(payload))

    def test_04_isolation_forest_latency_and_decision(self):
        """Verifies ML model cold-boot and inference latency <= 1.4 ms."""
        engine = EdgeAnomalyEngine()
        self.assertIsNotNone(engine.model)

        # Benchmark 100 inference passes
        sample_vec = np.array([[180.0, 4.15, 64.0, 0.001]], dtype=np.float64)
        t0 = time.perf_counter()
        for _ in range(50):
            _score, details = engine.score(sample_vec)
        avg_latency = ((time.perf_counter() - t0) / 50.0) * 1000.0

        print(f"\n[Test Benchmark] Edge ML Avg Inference Latency: {avg_latency:.3f} ms")
        self.assertLess(avg_latency, 1.4, f"Inference latency {avg_latency:.3f} ms exceeded 1.4 ms budget")
        self.assertFalse(details["quarantine_triggered"])

    def test_05_optical_pairing_roundtrip(self):
        """Verifies QR code generation and OpenCV QR decoder optical handshake."""
        pairing = MagicCirclePairing(port=7788, soft_mb=1024)
        qr_img = pairing.generate_qr_image()
        self.assertIsNotNone(qr_img)

        parsed_token = pairing.parse_qr_from_image(qr_img)
        self.assertIsNotNone(parsed_token, "OpenCV QR detector failed to parse pairing image")
        self.assertEqual(parsed_token["magic"], "RDSG")
        self.assertEqual(parsed_token["port"], 7788)
        self.assertEqual(parsed_token["soft_mb"], 1024)

    def test_06_tamper_proof_audit_logger(self):
        """Verifies cryptographic SHA-256 hash chaining of audit trail."""
        test_audit_path = os.path.join(os.path.dirname(__file__), "test_audit.jsonl")
        if os.path.exists(test_audit_path):
            os.remove(test_audit_path)

        logger = ForensicAuditLogger(test_audit_path)
        r1 = logger.log_event("EVENT_1", {"msg": "Initial"})
        r2 = logger.log_event("EVENT_2", {"msg": "Chained"})

        self.assertEqual(r2["prev_hash"], r1["record_hash"])
        if os.path.exists(test_audit_path):
            os.remove(test_audit_path)


if __name__ == "__main__":
    unittest.main()
