import argparse
from modules import xss, sqli, cmd_injection, utils

def export(payloads):
    with open("output/payloads.json", "w") as f:
        import json
        json.dump(payloads, f, indent=4)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xss', action='store_true')
    parser.add_argument('--sqli', action='store_true')
    parser.add_argument('--cmd', action='store_true')
    parser.add_argument('--platform', choices=["linux", "windows"], default="linux")
    parser.add_argument('--encode', choices=["base64", "url", "hex", "unicode"])
    parser.add_argument('--copy', action='store_true')

    args = parser.parse_args()
    all_payloads = []

    if args.xss:
        for p in xss.get_xss_payloads():
            p["encoded"] = utils.encode_payload(p["payload"], args.encode) if args.encode else p["payload"]
            all_payloads.append(p)

    if args.sqli:
        for p in sqli.get_sqli_payloads():
            p["encoded"] = utils.encode_payload(p["payload"], args.encode) if args.encode else p["payload"]
            all_payloads.append(p)

    if args.cmd:
        for p in cmd_injection.get_cmd_payloads(args.platform):
            p["encoded"] = utils.encode_payload(p["payload"], args.encode) if args.encode else p["payload"]
            all_payloads.append(p)

    for p in all_payloads:
        print(f"[{p['type']}] {p['encoded']}")

    export(all_payloads)

    if args.copy:
        import pyperclip
        if all_payloads:
            pyperclip.copy(all_payloads[0]["encoded"])
            print("First payload copied to clipboard.")

if __name__ == "__main__":
    main()
