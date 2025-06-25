import requests
import urllib3
import html
import urllib.parse
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def clean_payload(payload):
    """
    Remove HTML tags and decode for comparison in DOM-based or JS-executed reflection.
    """
    no_tags = re.sub(r'<.*?>', '', payload)
    return html.unescape(no_tags).lower()

def send_payloads(url, payloads, param_name="input"):
    results = []
    headers = {
        "User-Agent": "PayloadGen-Scanner"
    }

    for item in payloads:
        payload = item["payload"]
        try:
            response = requests.get(
                url,
                params={param_name: payload},
                headers=headers,
                timeout=5,
                verify=False
            )

            response_text = response.text.lower()
            decoded = html.unescape(response_text)
            cleaned = re.sub(r'<.*?>', '', decoded)

            # Check against various payload formats
            variants = {
                "original": payload.lower(),
                "url_encoded": urllib.parse.quote(payload).lower(),
                "url_decoded": urllib.parse.unquote(payload).lower(),
                "html_escaped": html.escape(payload).lower(),
                "html_unescaped": html.unescape(payload).lower(),
                "tag_stripped": clean_payload(payload),
            }

            reflected = any(variant in decoded or variant in cleaned for variant in variants.values())

            results.append({
                "payload": payload,
                "status_code": response.status_code,
                "length": len(response.text),
                "reflected": reflected
            })

        except Exception as e:
            results.append({
                "payload": payload,
                "error": str(e)
            })

    return results
