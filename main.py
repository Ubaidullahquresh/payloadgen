import argparse
import json
import pyperclip

from modules import xss, sqli, command_injection, encoder
from utils import obfuscator  # Assumes utils/obfuscator.py exists

parser = argparse.ArgumentParser(description="PayloadGen - Web Payload Generator")

parser.add_argument('--xss', action='store_true', help='Generate XSS payloads')
parser.add_argument('--sqli', action='store_true', help='Generate SQLi payloads')
parser.add_argument('--cmd', action='store_true', help='Generate Command Injection payloads')
parser.add_argument('--encode', choices=["url", "base64", "hex", "unicode"], help='Apply encoding to payloads')
parser.add_argument('--obfuscate', action='store_true', help='Obfuscate the payloads')
parser.add_argument('--export', metavar='FILENAME', help='Export payloads to the given file (e.g., payloads.txt or .json)')
parser.add_argument('--clip', action='store_true', help='Copy first payload to clipboard')
parser.add_argument('--send', metavar='URL', help='Send payloads to target URL via GET')
parser.add_argument('--param', default='input', help='GET parameter name to inject payload (default: input)')

args = parser.parse_args()
payloads = []

# ✅ Ensure at least one module is selected
if not (args.xss or args.sqli or args.cmd):
    parser.error("You must specify at least one payload type: --xss, --sqli, or --cmd")

# ✅ Select module
if args.xss:
    payloads = xss.get_xss_payloads()
elif args.sqli:
    payloads = sqli.get_sqli_payloads()
elif args.cmd:
    payloads = command_injection.get_command_injection_payloads()

# ✅ Exit if no payloads were returned
if not payloads:
    print("[!] No payloads generated. Check your module.")
    exit(1)

output_list = []

# ✅ Process payloads
for p in payloads:
    payload = p["payload"]
    ptype = p.get("type") or p.get("os") or "Unknown"

    if args.obfuscate:
        payload = obfuscator.obfuscate_payload(payload)

    if args.encode:
        payload = encoder.encode_payload(payload, args.encode)

    print(f"[{ptype}] {payload}")
    output_list.append({"type": ptype, "payload": payload})

# ✅ Copy to clipboard
if args.clip and output_list:
    pyperclip.copy(output_list[0]["payload"])
    print("\n[+] Copied first payload to clipboard.")

# ✅ Export to file
if args.export:
    try:
        if args.export.endswith('.json'):
            with open(args.export, "w") as f:
                json.dump(output_list, f, indent=4)
        else:
            with open(args.export, "w") as f:
                for item in output_list:
                    f.write(f"[{item['type']}] {item['payload']}\n")
        print(f"[+] Payloads saved to {args.export}")
    except Exception as e:
        print(f"[!] Failed to export payloads: {e}")

# ✅ Send to target URL via GET
if args.send:
    from modules import burp_api
    print(f"\n[+] Sending payloads to: {args.send}")
    result = burp_api.send_payloads(args.send, output_list, param_name=args.param)

    for r in result:
        if 'error' in r:
            print(f"[!] {r['payload']} => Error: {r['error']}")
        else:
            status = "✓ Reflected" if r.get("reflected") else "✗ Not Reflected"
            print(f"[{status}] {r['payload']} => {r['status_code']} ({r['length']} bytes)")
