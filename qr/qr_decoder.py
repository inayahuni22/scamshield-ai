"""
QR code decoding — extracts merchant/payment info from a photo.
Fully standalone. No dependency on any other teammate's module.
"""

import cv2


def decode_qr(image_path: str) -> dict:
    """
    Returns:
      {"found": bool, "raw_data": str | None, "claimed_sender": str | None}
    """
    try:
        img = cv2.imread(image_path)

        if img is None:
            return {
                "found": False,
                "raw_data": None,
                "claimed_sender": None,
                "error": "Could not read image."
            }

        detector = cv2.QRCodeDetector()
        raw_data, points, _ = detector.detectAndDecode(img)

    except Exception as e:
        return {
            "found": False,
            "raw_data": None,
            "claimed_sender": None,
            "error": str(e)
        }

    if not raw_data:
        return {
            "found": False,
            "raw_data": None,
            "claimed_sender": None
        }

    claimed_sender = _extract_merchant_hint(raw_data)

    return {
        "found": True,
        "raw_data": raw_data,
        "claimed_sender": claimed_sender
    }


def _extract_merchant_hint(raw_data: str) -> str:
    """
    Best-effort merchant name extraction from common QR payment formats.
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
    result = decode_qr("test_qr.png")
    print(result)