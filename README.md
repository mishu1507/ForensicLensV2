# 🔐 ForensicLens – Automated Digital Forensics & Incident Reconstruction System

ForensicLens is a web-based digital forensics platform designed to automate post-incident investigations. The system analyzes authentication, system, USB, and network logs to reconstruct incident timelines, detect attacks, assess severity, and generate professional forensic reports.


## 🚀 Features

- 🔍 Multi-log analysis (authentication, system, USB, network logs)
- 🧠 Brute force attack detection
- 🕒 Incident timeline reconstruction
- 📊 Risk scoring and severity classification
- 🧾 Dynamic, evidence-driven attack narrative generation
- 📄 Automated PDF forensic report generation
- 📊 Advanced SIEM Investigation Workspace (Visual Hunt, AI Copilot, Rule Engine)


## 🛠️ Technology Stack

| Component       | Technology            |
|-----------------|-----------------------|
| Backend         | Python                |
| Web Framework   | Flask                 |
| Frontend        | HTML, CSS, JavaScript |
| Visualization   | Chart.js              |
| PDF Reports     | ReportLab             |
| Security        | SHA-256 hashing       |



## 📁 Project Structure
FORENSICLENS/
│
├── app.py                     # Main Flask application entry point
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
│
├── modules/                   # Core forensic analysis logic
│   ├── __pycache__/            # Compiled Python cache files
│   │
│   ├── auth_detector.py        # Authentication anomaly detection
│   ├── hash_integrity.py       # File hash validation & integrity checks
│   ├── incident_analyzer.py   # Central incident correlation engine
│   ├── mitre_mapper.py        # MITRE ATT&CK technique mapping
│   ├── narrative_generator.py # Human-readable investigation narrative
│   ├── parser.py              # Log & evidence parsing logic
│   ├── report_generator.py    # PDF/HTML forensic report generation
│   ├── risk_engine.py         # Risk scoring & threat prioritization
│   ├── severity_explainer.py  # Severity justification & explanation
│   ├── timeline.py            # Event timeline reconstruction
│   └── workspace_manager.py   # Case/workspace handling & isolation
│
├── static/                    # Static frontend assets
│   └── style.css              # Global UI styling
│
└── templates/                 # HTML templates (Jinja2)
    ├── index.html             # Landing & upload page
    ├── dashboard.html         # Advanced SIEM workspace
    └── chain_of_custody.html  # Evidence custody tracking




## ⚙️ Installation & Setup

 Clone or download the project

git clone https://github.com/mishu1507/ForensicLens
cd ForensicLens

pip install -r requirements.txt
Run the application

python app.py
Open the application in your browser

http://127.0.0.1:5000