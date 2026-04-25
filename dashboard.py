import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import os
import hashlib
from risk_engine import RiskEngine
from policy_engine import PolicyEngine
from logger_setup import setup_logger

class ZTDashboard:
    ATTACK_KILL_CHAIN = {
        "Insider Threat": [
            ("Recon", "T1082 - System Info Discovery", 12, "Monitor"),
            ("Access", "T1078 - Valid Accounts", 28, "Allow"),
            ("Lateral", "T1021 - Remote Services", 45, "MFA"),
            ("Collect", "T1005 - Data from Local System", 62, "Block"),
            ("Exfil", "T1041 - Exfiltration Over C2", 85, "Block")
        ],
        "Suspicious Device": [
            ("Scan", "T1046 - Network Service Scan", 15, "Monitor"),
            ("Auth", "T1110 - Brute Force", 38, "MFA"),
            ("Escalate", "T1068 - Privilege Escalation", 55, "MFA"),
            ("Violate", "T1059 - Command Execution", 78, "Block")
        ],
        "Bot Behavior": [
            ("Probe", "T1595 - Active Scanning", 8, "Monitor"),
            ("Stuff", "T1110.004 - Credential Stuffing", 32, "MFA"),
            ("Flood", "T1499 - Endpoint DoS", 58, "MFA"),
            ("Block", "T1562 - Impair Defenses", 92, "Block")
        ],
        "Sensitive Resource": [
            ("Access", "T1078 - Valid Accounts", 22, "Allow"),
            ("Verify", "T1078 - MFA Challenge", 41, "MFA"),
            ("Check", "Policy Engine Eval", 54, "MFA"),
            ("Decision", "Dynamic Enforcement", 68, "Block")
        ]
    }

    IOC_DATABASE = {
        "Insider Threat": [
            ("File Hash", "a1b2c3d4...e5f67890", "98%", "Local AV", "Malicious"),
            ("Process", "svchost.exe (PID 4812)", "High", "EDR", "Suspicious"),
            ("Registry", "HKLM\\Run\\MalwareUpdate", "Critical", "Registry Monitor", "Malicious")
        ],
        "Suspicious Device": [
            ("MAC Address", "00:1A:2B:3C:4D:5E", "High", "NAC", "Unknown"),
            ("IP Address", "192.168.1.105", "Low", "Firewall", "Internal"),
            ("Device ID", "DESKTOP-JD8922", "Medium", "Intune", "Non-Compliant")
        ],
        "Bot Behavior": [
            ("IP Address", "185.220.101.42", "100%", "VirusTotal", "Blocklisted"),
            ("User-Agent", "Python-urllib/3.9", "High", "WAF", "Bot Signature"),
            ("Domain", "c2-command.ru", "Critical", "Threat Intel", "Malicious")
        ],
        "Sensitive Resource": [
            ("File Hash", "f1e2d3c4...b5a69870", "Low", "DLP", "Clean"),
            ("Resource", "DB_Financial_Records", "Medium", "IAM", "Restricted"),
            ("Query", "SELECT * FROM Users", "High", "Database Firewall", "Anomalous")
        ]
    }

    def __init__(self, root):
        self.root = root
        self.root.title("ZT Cyber-Range Simulator")
        self.root.geometry("1250x750")
        self.root.minsize(1000, 650)
        self.root.config(bg="#e8e8e8")

        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.logger = setup_logger()

        self.user_count = 12
        self.device_count = 8
        self.resource_count = 5

        self.timeline_events = []
        self.ioc_data = []
        self.evidence_log = []

        self._setup_styles()
        self._create_layout()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#e8e8e8")
        style.configure("TLabel", background="#e8e8e8", font=("Segoe UI", 11), foreground="#1a1a1a")
        style.configure("TLabelframe", background="#e8e8e8", borderwidth=1)
        style.configure("TLabelframe.Label", background="#e8e8e8", foreground="#222222", font=("Segoe UI", 12, "bold"))
        style.configure("TButton", font=("Segoe UI", 11), padding=(10, 5))
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#111111")
        style.configure("Status.TLabel", font=("Segoe UI", 10), foreground="#444444")
        style.configure("Treeview", font=("Consolas", 10), rowheight=24)
        style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"), background="#d9d9d9")

    def _create_layout(self):
        self.header_frame = ttk.Frame(self.root)
        self.header_frame.pack(fill=tk.X, padx=15, pady=(15, 5))
        ttk.Label(self.header_frame, text="Zero Trust Cyber-Range Simulator", style="Header.TLabel").pack(side=tk.LEFT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=15, pady=2)

        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        self.main_container.columnconfigure(0, weight=0, minsize=150)
        self.main_container.columnconfigure(1, weight=1)
        self.main_container.columnconfigure(2, weight=2)
        self.main_container.rowconfigure(0, weight=1)

        self.network_frame = ttk.LabelFrame(self.main_container, text="Network Entities")
        self.network_frame.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        self._build_network_panel()

        self.center_frame = ttk.LabelFrame(self.main_container, text="Risk Engine & Controls")
        self.center_frame.grid(row=0, column=1, sticky="nsew", padx=6, pady=6)
        self._build_center_panel()

        self.right_notebook = ttk.Notebook(self.main_container)
        self.right_notebook.grid(row=0, column=2, sticky="nsew", padx=6, pady=6)
        self._build_log_tab()
        self._build_timeline_tab()
        self._build_ioc_tab()
        self._build_evidence_tab()

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=15, pady=2)

        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        self.status_label = ttk.Label(self.status_frame, text="Status: Ready | Waiting for requests...", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT)

    def _build_network_panel(self):
        self.net_labels = []
        items = [f"Users: {self.user_count}", f"Devices: {self.device_count}", f"Resources: {self.resource_count}"]
        for item in items:
            lbl = ttk.Label(self.network_frame, text=item, font=("Segoe UI", 11, "bold"))
            lbl.pack(anchor="w", padx=12, pady=6)
            self.net_labels.append(lbl)

    def _update_network_panel(self, change_type):
        if change_type == "user": self.user_count += 1
        elif change_type == "device": self.device_count += 1
        elif change_type == "resource": self.resource_count += 1
        updates = [f"Users: {self.user_count}", f"Devices: {self.device_count}", f"Resources: {self.resource_count}"]
        for lbl, txt in zip(self.net_labels, updates):
            lbl.config(text=txt)

    def _build_center_panel(self):
        self.risk_label = ttk.Label(self.center_frame, text="Risk Score: 0/100", font=("Segoe UI", 15, "bold"))
        self.risk_label.pack(pady=(20, 5))

        self.decision_label = ttk.Label(self.center_frame, text="Decision: Idle", font=("Segoe UI", 16, "bold"), foreground="#555555")
        self.decision_label.pack(pady=10)

        btn_container = ttk.Frame(self.center_frame)
        btn_container.pack(fill=tk.X, padx=12, pady=12)

        attacks = [
            ("Insider Threat", self._on_insider_threat),
            ("Suspicious Device", self._on_suspicious_device),
            ("Bot Behavior", self._on_bot_behavior),
            ("Sensitive Resource", self._on_sensitive_resource)
        ]

        for i, (text, command) in enumerate(attacks):
            ttk.Button(btn_container, text=text, command=command).grid(row=0, column=i, padx=5, sticky="ew")
            btn_container.columnconfigure(i, weight=1)

        ctrl_frame = ttk.Frame(self.center_frame)
        ctrl_frame.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Button(ctrl_frame, text="Export Logs", command=self._export_logs).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)
        ttk.Button(ctrl_frame, text="Reset Dashboard", command=self._reset_dashboard).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)

    def _build_log_tab(self):
        log_frame = ttk.Frame(self.right_notebook)
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, state=tk.DISABLED, bg="#f5f5f5", fg="#222222", font=("Consolas", 10), relief=tk.FLAT)
        self.log_text.tag_configure("allow", foreground="#2e7d32")
        self.log_text.tag_configure("mfa", foreground="#f57c00")
        self.log_text.tag_configure("block", foreground="#c62828")
        self.log_text.tag_configure("info", foreground="#555555")
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.right_notebook.add(log_frame, text="Live Logs")

    def _build_timeline_tab(self):
        tl_frame = ttk.Frame(self.right_notebook)
        cols = ("Time", "Phase", "Technique", "Risk", "Action")
        self.timeline_tree = ttk.Treeview(tl_frame, columns=cols, show="headings", height=18)
        for col in cols:
            self.timeline_tree.heading(col, text=col)
            self.timeline_tree.column(col, width=100, anchor="center")
        self.timeline_tree.column("Technique", width=150)
        self.timeline_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.right_notebook.add(tl_frame, text="Attack Timeline")

    def _build_ioc_tab(self):
        ioc_frame = ttk.Frame(self.right_notebook)
        cols = ("Type", "Value", "Confidence", "Source", "Status")
        self.ioc_tree = ttk.Treeview(ioc_frame, columns=cols, show="headings", height=18)
        for col in cols:
            self.ioc_tree.heading(col, text=col)
            self.ioc_tree.column(col, width=100, anchor="center")
        self.ioc_tree.column("Value", width=180)
        self.ioc_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.right_notebook.add(ioc_frame, text="IOC Extractor")

    def _build_evidence_tab(self):
        ev_frame = ttk.Frame(self.right_notebook)
        cols = ("Artifact", "Hash", "Collected", "Handler", "Status")
        self.evidence_tree = ttk.Treeview(ev_frame, columns=cols, show="headings", height=18)
        for col in cols:
            self.evidence_tree.heading(col, text=col)
            self.evidence_tree.column(col, width=100, anchor="center")
        self.evidence_tree.column("Hash", width=180)
        self.evidence_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.right_notebook.add(ev_frame, text="Evidence Locker")

    def _append_log(self, message, tag="info"):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _generate_timeline(self, attack_name):
        chain = self.ATTACK_KILL_CHAIN.get(attack_name, [])
        base_time = datetime.now()
        for i, (phase, technique, risk, action) in enumerate(chain):
            ts = (base_time + timedelta(seconds=i*2)).strftime('%H:%M:%S')
            self.timeline_tree.insert("", tk.END, values=(ts, phase, technique, risk, action))

    def _extract_iocs(self, attack_name):
        data = self.IOC_DATABASE.get(attack_name, [])
        for ioc in data:
            self.ioc_tree.insert("", tk.END, values=ioc)

    def _add_evidence(self, attack_name):
        artifact_id = f"{attack_name}_{datetime.now().strftime('%H%M%S')}"
        raw_hash = hashlib.sha256(artifact_id.encode()).hexdigest()
        ts = datetime.now().strftime('%H:%M:%S')
        self.evidence_tree.insert("", tk.END, values=(
            f"Mem_Dump_{artifact_id}.raw",
            raw_hash[:20] + "...",
            ts,
            "Auto_Collection",
            "Secured"
        ))

    def _evaluate_request(self, name, trust, behavior, freq, sensitivity, net_change):
        score = self.risk_engine.calculate_score(trust, behavior, freq, sensitivity)
        decision, color = self.policy_engine.evaluate(score)

        self.risk_label.config(text=f"Risk Score: {score}/100")
        self.decision_label.config(text=f"Decision: {decision}", foreground=color)
        self._update_network_panel(net_change)
        self.status_label.config(text=f"Last: {name} | Score: {score} | {datetime.now().strftime('%H:%M:%S')}")

        log_msg = f"[{name}] Score={score} | Action={decision}"
        self.logger.info(log_msg)

        tag_map = {"Allow": "allow", "Require MFA": "mfa", "Block": "block"}
        self._append_log(log_msg, tag_map.get(decision, "info"))
        self._generate_timeline(name)
        self._extract_iocs(name)
        self._add_evidence(name)

    def _on_insider_threat(self):
        self._evaluate_request("Insider Threat", 0.8, 0.7, 0.3, 0.8, "user")

    def _on_suspicious_device(self):
        self._evaluate_request("Suspicious Device", 0.2, 0.5, 0.4, 0.5, "device")

    def _on_bot_behavior(self):
        self._evaluate_request("Bot Behavior", 0.6, 0.8, 0.95, 0.4, "device")

    def _on_sensitive_resource(self):
        self._evaluate_request("Sensitive Resource", 0.7, 0.4, 0.2, 0.95, "resource")

    def _export_logs(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"logs/activity_export_{timestamp}.txt"
        try:
            with open("logs/activity.log", "r", encoding="utf-8") as src, open(filepath, "w", encoding="utf-8") as dst:
                dst.write(src.read())
            self._append_log(f"Logs exported to {filepath}", "info")
        except FileNotFoundError:
            self._append_log("No log file found to export", "info")

    def _reset_dashboard(self):
        self.user_count = 12
        self.device_count = 8
        self.resource_count = 5
        updates = [f"Users: {self.user_count}", f"Devices: {self.device_count}", f"Resources: {self.resource_count}"]
        for lbl, txt in zip(self.net_labels, updates):
            lbl.config(text=txt)

        self.risk_label.config(text="Risk Score: 0/100")
        self.decision_label.config(text="Decision: Idle", foreground="#555555")
        self.status_label.config(text="Status: Ready | Waiting for requests...")

        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)
        for item in self.timeline_tree.get_children():
            self.timeline_tree.delete(item)
        for item in self.ioc_tree.get_children():
            self.ioc_tree.delete(item)
        for item in self.evidence_tree.get_children():
            self.evidence_tree.delete(item)
        self.timeline_events.clear()
        self.ioc_data.clear()
        self.evidence_log.clear()
        self._append_log("Dashboard reset successfully", "info")