"""
QR code decoding — extracts merchant/payment info from a photo.
Fully standalone. No dependency on any other teammate's module.
"""

from pyzbar.pyzbar import decode
from PIL import Image


def decode_qr(image_path: str) -> dict:
    """
    Returns:
      {"found": bool, "raw_data": str | None, "claimed_sender": str | None}
    """
    try:
        img = Image.open(image_path)
        results = decode(img)
    except Exception as e:
        return {"found": False, "raw_data": None, "claimed_sender": None, "error": str(e)}

    if not results:
        return {"found": False, "raw_data": None, "claimed_sender": None}

    raw_data = results[0].data.decode("utf-8")
    claimed_sender = _extract_merchant_hint(raw_data)

    return {"found": True, "raw_data": raw_data, "claimed_sender": claimed_sender}


def _extract_merchant_hint(raw_data: str) -> str:
    """
    Best-effort merchant name extraction from common QR payment formats
    (UPI-style, plain URLs, EMV merchant QR strings). Falls back to the raw
    string if nothing recognizable is found — the Explainer Agent still gets
    something useful either way.
    """
    if raw_data.startswith("upi://"):
        for part in raw_data.split("&"):
            if part.startswith("pn="):
                return part.split("=", 1)[1].replace("%20", " ")
    if "://" in raw_data:
        domain = raw_data.split("://", 1)[1].split("/", 1)[0]
        return domain
    return raw_data[:50]


if __name__ == "__main__":
    # Test with any locally generated QR image, e.g. from qr-code-generator.com
    result = decode_qr("test_qr.png")
    print(result)
