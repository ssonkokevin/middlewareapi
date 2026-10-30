"""
Biometric format conversion for UCC compatibility.

UCC requires JPEG fingerprint images for REFUGEE ID verification.
Clients may capture WSQ (Wavelet Scalar Quantization) fingerprint images
from MOSIP/SBI devices. This module decodes WSQ base64 → raw image → JPEG
base64 so the gateway can forward JPEG to UCC transparently.
"""

import base64
import io

import wsq  # noqa: F401  registers WSQ as a PIL Image plugin
from PIL import Image


def wsq_to_jpeg_base64(wsq_base64: str) -> str:
    """
    Decode a base64-encoded WSQ fingerprint image and re-encode as base64 JPEG.

    Args:
        wsq_base64: Base64-encoded WSQ image data.

    Returns:
        Base64-encoded JPEG image data.

    Raises:
        ValueError: If the WSQ data cannot be decoded.
    """
    try:
        wsq_bytes = base64.b64decode(wsq_base64)
    except Exception as exc:
        raise ValueError(f"Invalid base64 WSQ data: {exc}") from exc

    try:
        image = Image.open(io.BytesIO(wsq_bytes))
        image.load()
    except Exception as exc:
        raise ValueError(f"Failed to decode WSQ image: {exc}") from exc

    if image.mode != "L":
        image = image.convert("L")

    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=90)
    jpeg_bytes = buffer.getvalue()

    return base64.b64encode(jpeg_bytes).decode("ascii")


def convert_biometric_if_wsq(biometric: dict) -> dict:
    """
    If biometric.format is WSQ, convert biometric.data to JPEG and update
    format to JPEG. Otherwise return the biometric unchanged.

    Args:
        biometric: Dict with biometric_type, format, data (or blocks).

    Returns:
        Dict with format possibly changed to JPEG and data re-encoded.
    """
    fmt = biometric.get("format", "")
    if fmt != "WSQ":
        return biometric

    data = biometric.get("data")
    if not data:
        return biometric

    jpeg_base64 = wsq_to_jpeg_base64(data)
    return {
        "biometric_type": biometric.get("biometric_type", "FINGERPRINT"),
        "format": "JPEG",
        "data": jpeg_base64,
    }
