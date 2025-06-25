def obfuscate_payload(payload):
    # Example basic obfuscation:
    return (
        payload.replace("script", "scr<!-- -->ipt")
               .replace("alert", "al<!-- -->ert")
               .replace("onerror", "on<!-- -->error")
               .replace("SELECT", "SE<!-- -->LECT")
               .replace("UNION", "UN<!-- -->ION")
    )

