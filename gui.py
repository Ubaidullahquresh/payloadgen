import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from modules import xss, sqli, command_injection, encoder
from utils import obfuscator
import json

# Store last generated payloads for export
last_payloads = []

def generate_payload():
    selected = attack_type.get()
    encode_type = encode_option.get()
    obfuscate = obfuscate_var.get()

    if not selected:
        messagebox.showwarning("Missing Selection", "Please select an attack type.")
        return

    if selected == "XSS":
        payloads = xss.get_xss_payloads()
    elif selected == "SQLi":
        payloads = sqli.get_sqli_payloads()
    elif selected == "Command Injection":
        payloads = command_injection.get_command_injection_payloads()
    else:
        messagebox.showerror("Error", "Invalid attack type selected.")
        return

    output_box.delete('1.0', tk.END)
    global last_payloads
    last_payloads = []

    for p in payloads:
        out = p["payload"]
        if obfuscate:
            out = obfuscator.obfuscate_payload(out)
        if encode_type != "None":
            out = encoder.encode_payload(out, encode_type.lower())
        tag = p.get("type") or p.get("os") or "Generic"
        output_line = f"[{tag}] {out}"
        last_payloads.append({"type": tag, "payload": out})
        output_box.insert(tk.END, output_line + "\n")

def export_payloads():
    if not last_payloads:
        messagebox.showwarning("Nothing to Export", "Generate payloads first.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON Files", "*.json")])
    if file_path:
        with open(file_path, 'w') as f:
            json.dump(last_payloads, f, indent=4)
        messagebox.showinfo("Export Complete", f"Payloads saved to {file_path}")

def copy_first_payload():
    if not last_payloads:
        messagebox.showwarning("Clipboard Error", "No payloads to copy.")
        return
    window.clipboard_clear()
    window.clipboard_append(last_payloads[0]["payload"])
    messagebox.showinfo("Copied", "First payload copied to clipboard.")

def clear_output():
    output_box.delete('1.0', tk.END)
    last_payloads.clear()

# GUI Setup
window = tk.Tk()
window.title("PayloadGen GUI")
window.geometry("720x520")

# Layout Grid
window.columnconfigure(1, weight=1)

# Attack Type
ttk.Label(window, text="Attack Type:").grid(column=0, row=0, padx=10, pady=5, sticky="w")
attack_type = ttk.Combobox(window, values=["XSS", "SQLi", "Command Injection"], state="readonly")
attack_type.grid(column=1, row=0, padx=10, pady=5, sticky="ew")

# Encoding
ttk.Label(window, text="Encoding:").grid(column=0, row=1, padx=10, pady=5, sticky="w")
encode_option = ttk.Combobox(window, values=["None", "URL", "Base64", "Hex", "Unicode"], state="readonly")
encode_option.set("None")
encode_option.grid(column=1, row=1, padx=10, pady=5, sticky="ew")

# Obfuscation
obfuscate_var = tk.BooleanVar()
ttk.Checkbutton(window, text="Apply Obfuscation", variable=obfuscate_var).grid(column=1, row=2, padx=10, pady=5, sticky="w")

# Buttons
ttk.Button(window, text="Generate Payloads", command=generate_payload).grid(column=0, row=3, padx=10, pady=10, sticky="ew")
ttk.Button(window, text="Export JSON", command=export_payloads).grid(column=1, row=3, padx=10, pady=10, sticky="w")
ttk.Button(window, text="Copy First to Clipboard", command=copy_first_payload).grid(column=0, row=4, padx=10, pady=5, sticky="ew")
ttk.Button(window, text="Clear Output", command=clear_output).grid(column=1, row=4, padx=10, pady=5, sticky="w")

# Output Box
output_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=85, height=20)
output_box.grid(column=0, row=5, columnspan=2, padx=10, pady=10, sticky="nsew")

# Run App
window.mainloop()
