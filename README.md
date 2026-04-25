
# Zero Trust Cyber-Range Simulator

An interactive, GUI-based Python application that simulates Zero Trust Architecture (ZTA) through real-time risk assessment, dynamic access control, and digital forensics artifact generation. Designed as a lightweight **Cyber Range as a Service (CRaaS)** environment for attack-defense training.

##  Overview
Modern enterprise security has shifted from perimeter-based trust to continuous verification. This project operationalizes that shift by simulating an **attack-defense pipeline** where every access request is evaluated against contextual telemetry before enforcement. 

Instead of relying on network boundaries, the system applies the core ZTA principle: **"Never trust, always verify."** It calculates dynamic risk scores, enforces adaptive policies (`Allow` / `Require MFA` / `Block`), and automatically generates forensic artifacts aligned with industry frameworks (MITRE ATT&CK, NIST SP 800-86).

##  Key Features
-  **Dynamic Risk Scoring** – Weighted evaluation of device trust, behavior anomaly, request frequency, and resource sensitivity (0–100 scale)
-  **Adaptive Policy Engine** – Threshold-based access decisions that mirror enterprise Zero Trust enforcement points
-  **MITRE ATT&CK Timeline** – Chronological attack progression visualization with technique mapping
-  **IOC Extraction** – Automated surfacing of indicators (IPs, hashes, registry keys, processes) with confidence scoring
-  **Evidence Integrity** – SHA-256 cryptographic hashing with chain-of-custody metadata logging
-  **Responsive GUI** – Tkinter-based interface with real-time updates, color-coded severity, and multi-panel synchronization
-  **Zero External Dependencies** – Built entirely with Python standard library modules for maximum portability

## How It Works
The simulator operates as a closed-loop defense pipeline:

1. **Attack Injection** – User triggers a predefined threat scenario (Insider, Suspicious Device, Bot Behavior, or Sensitive Resource)
2. **Risk Calculation** – Engine applies:  
   `Score = (1.0 − Device_Trust)×30 + Behavior×25 + Frequency×20 + Sensitivity×25`
3. **Policy Enforcement** – Score is mapped to thresholds:  
   `< 30` → Allow | `30–60` → Require MFA | `> 60` → Block
4. **Forensic Capture** – System populates timeline, extracts IOCs, hashes evidence, and logs events to GUI + persistent file
5. **Real-Time Visualization** – All panels update synchronously, mimicking SOC telemetry dashboards

##  Quick Start
No installation or package managers required. The project uses only Python's built-in standard library.

```bash
# Clone the repository
git clone https://github.com/[YOUR_USERNAME]/zero-trust-cyber-range-simulator.git
cd zero-trust-cyber-range-simulator

# Run the application
python main.py
