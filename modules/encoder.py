import urllib.parse
import base64

def encode_payload(payload, method):
    try:
        if method == "url":
            return urllib.parse.quote(payload, safe='')
        elif method == "base64":
            return base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        elif method == "hex":
            # Format: \x68\x65\x6c\x6c\x6f
            return ''.join([f"\\x{ord(c):02x}" for c in payload])
        elif method == "unicode":
            # Format: \u0041\u0062
            return ''.join([f"\\u{ord(c):04X}" for c in payload])
    except Exception as e:
        print(f"[!] Encoding error: {e}")
        return payload

    return payload
