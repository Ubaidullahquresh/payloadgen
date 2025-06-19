def get_cmd_payloads(platform="linux"):
    return [
        {"type": "Basic", "payload": "; ls" if platform == "linux" else "& dir"},
        {"type": "Chained", "payload": "&& whoami" if platform == "linux" else "&& whoami"},
        {"type": "Pipe", "payload": "| id" if platform == "linux" else "| whoami"},
    ]
