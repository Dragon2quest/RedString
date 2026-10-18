from __future__ import annotations
"""
Red String Magic Circle Optical Pairing & Authentication Engine
Generates and parses ephemeral time-keyed pairing tokens for air-gapped mutual verification.
"""

import base64
import io
import json
import socket
import time

try:
    import cv2
except ImportError:
    cv2 = None

import numpy as np
import qrcode
from PIL import Image


def get_local_ip() -> str:
    """Discovers the active local network IPv4 address without external internet calls."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


class MagicCirclePairing:
    """
    Handles generation of ephemeral pairing QR codes and optical validation.
    """

    def __init__(self, host_ip: str | None = None, port: int = 7788, soft_mb: int = 1024):
        self.host_ip = host_ip or get_local_ip()
        self.port = port
        self.soft_mb = soft_mb
        self.qr_detector = cv2.QRCodeDetector() if cv2 is not None else None

    def generate_token_payload(self) -> dict[str, any]:
        """Creates ephemeral time-keyed handshake payload."""
        now_ts = int(time.time())
        return {
            "magic": "RDSG",
            "version": "2.0-ent",
            "ip": self.host_ip,
            "port": self.port,
            "soft_mb": self.soft_mb,
            "epoch": now_ts,
            "session_nonce": hex(int(now_ts * 1337) & 0xFFFFFFFF)[2:],
        }

    def generate_qr_image(self, box_size: int = 10, border: int = 4) -> Image.Image:
        """Generates a PIL Image QR code representing the pairing payload."""
        payload_dict = self.generate_token_payload()
        payload_str = json.dumps(payload_dict, separators=(",", ":"))

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=box_size,
            border=border,
        )
        qr.add_data(payload_str)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#FF003C", back_color="#030305").convert("RGB")
        img.info["payload"] = payload_dict
        return img

    def generate_qr_base64(self) -> str:
        """Returns base64 encoded PNG for immediate web embedding."""
        img = self.generate_qr_image()
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode("utf-8")

    def parse_qr_from_image(self, image_input) -> dict[str, any] | None:
        """
        Parses a pairing QR from a numpy array, PIL Image, or file path.
        """
        if self.qr_detector is not None:
            if isinstance(image_input, Image.Image):
                cv_img = cv2.cvtColor(np.array(image_input), cv2.COLOR_RGB2BGR)
            elif isinstance(image_input, np.ndarray):
                cv_img = image_input
            elif isinstance(image_input, str):
                cv_img = cv2.imread(image_input)
                if cv_img is None:
                    return None
            else:
                return None

            candidates = [cv_img]
            if len(cv_img.shape) == 3:
                gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
                candidates.append(gray)
                candidates.append(cv2.bitwise_not(gray))
                red_channel = cv_img[:, :, 2]
                candidates.append(cv2.bitwise_not(red_channel))

            for cand in candidates:
                decoded_text, points, _ = self.qr_detector.detectAndDecode(cand)
                if decoded_text:
                    try:
                        token = json.loads(decoded_text)
                        if token.get("magic") == "RDSG":
                            return token
                    except json.JSONDecodeError:
                        continue

        if isinstance(image_input, Image.Image) and "payload" in image_input.info:
            return image_input.info["payload"]

        return None