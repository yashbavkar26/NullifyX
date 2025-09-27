#!/usr/bin/env python3
"""
gui_app_tkinter.py - simple Tkinter wrapper for Secure Wipe Prototype
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess, os

class SecureWipeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Wipe Prototype")

        # --- Title ---
        title = tk.Label(root, text="Secure Wipe Prototype", font=("Helvetica", 16))
        title.grid(row=0, column=0, columnspan=3, pady=10)

        # --- Device input ---
        tk.Label(root, text="Device (Linux):").grid(row=1, column=0, sticky="e")
        self.device_var = tk.StringVar(value="/dev/sdX")
        tk.Entry(root, textvariable=self.device_var, width=30).grid(row=1, column=1, columnspan=2, sticky="w")

        # --- Method combobox ---
        tk.Label(root, text="Method:").grid(row=2, column=0, sticky="e")
        self.method_var = tk.StringVar(value="auto")
        method_combo = ttk.Combobox(root, textvariable=self.method_var,
                                    values=["auto","nvme_format","ata_secure_erase","overwrite_shred","zero"],
                                    state="readonly", width=27)
        method_combo.grid(row=2, column=1, columnspan=2, sticky="w")

        # --- Dry run checkbox ---
        self.dry_var = tk.BooleanVar(value=True)
        tk.Checkbutton(root, text="Dry run (safe)", variable=self.dry_var).grid(row=3, column=0, columnspan=3, sticky="w", padx=5)

        # --- Buttons ---
        tk.Button(root, text="One-Click Wipe", command=self.wipe).grid(row=4, column=0, pady=5)
        tk.Button(root, text="Verify Certificate", command=self.verify).grid(row=4, column=1, pady=5)

        # --- Output console ---
        self.output = scrolledtext.ScrolledText(root, width=80, height=15)
        self.output.grid(row=5, column=0, columnspan=3, pady=10, padx=5)

    def append(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def wipe(self):
        device = self.device_var.get()
        method = self.method_var.get()
        dry = self.dry_var.get()
        outdir = os.path.abspath("./out_gui")
        os.makedirs(outdir, exist_ok=True)

        cmd = ["python3", "wipe_tool.py", "--device", device, "--method", method, "--out", outdir]
        cmd.append("--dry-run" if dry else "--confirm")
        cmd.extend(["--private-key", os.path.expanduser("~/private.pem")])

        self.append("Running: " + " ".join(cmd))
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in p.stdout:
                self.append(line.strip())
            p.wait()
            self.append("Wipe finished. Check out dir: " + outdir)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify(self):
        certs = os.listdir("./out_gui") if os.path.exists("./out_gui") else []
        cert_path = None
        for f in certs:
            if f.endswith(".json"):
                cert_path = os.path.join("./out_gui", f)
                break
        if not cert_path:
            self.append("No certificate found in ./out_gui")
            return

        self.append("Verifying: " + cert_path)
        try:
            p = subprocess.Popen(["python3", "verify_cert.py", cert_path],
                                 stdout=subprocess.PIPE, text=True)
            for line in p.stdout:
                self.append(line.strip())
            p.wait()
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureWipeApp(root)
    root.mainloop()
