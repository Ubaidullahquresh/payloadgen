import urllib.parse
import base64

def encode_payload(payload, method):
    if method == "url":
        return urllib.parse.quote(payload)
    elif method == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif method == "hex":
        return ''.join(f"\\x{ord(c):02x}" for c in payload)
    elif method == "unicode":
        return ''.join(f"\\u{ord(c):04x}" for c in payload)
    return payload
