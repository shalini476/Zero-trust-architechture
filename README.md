# Zero Trust Network Architecture with ML-Based Threat Detection
### Zerofox Corporate Security Platform (Working Prototype)

This is a full-stack cybersecurity prototype built as a final-year undergraduate project. It implements a **Zero Trust Network Architecture (ZTNA)** integrated with **Machine Learning (ML)-based anomaly and threat classification** (using scikit-learn).

---

## Key Features

1. **Multi-Layer Authentication**: Credentials verification followed by a 6-digit email OTP challenge.
2. **Developer OTP Fallback**: If SMTP email credentials are not set in `.env`, the OTP code is printed directly to the command-line console and displayed in a secure fallback window in the UI for easy copy-pasting during demonstrations.
3. **Adaptive Two-Step Verification**: Users logging in from new devices, at unusual times, or with degraded trust scores are challenged with a secondary Security Question.
4. **Adaptive Trust Score Engine**: Starts at 100 and changes dynamically based on behaviors (failed logins: -10, new device: -20, out-of-office hours: -15, honeypot accesses: -50).
5. **Honeypot Resource Traps**: Injects decoy files (e.g., `Salary_Data_2026.xlsx`) inside a restricted folder. Accessing them immediately drops trust scores by 50, blocks access, and alerts admins.
6. **Insider Threat Velocity Detection**: Triggers alerts if an account exceeds 10 file downloads within an hour.
7. **ML Engine Anomaly Classifier**: Uses **Isolation Forest** (unsupervised outlier detection) and **Random Forest** (supervised classification) to categorize requests into Normal, Suspicious, or High Risk.
8. **Explainable AI (XAI)**: Demystifies AI outcomes by listing concrete behavioral indicators (e.g., midnight logins, failed attempts) on dashboards.
9. **Interactive Threat Simulator**: Allows administrators to inject live attacks (Brute Force, Credential Theft, Insider Threats, Honeypot access) and see how the PDP/PEP gates react in real-time.
10. **Compliance Export Reports**: Exposes routes to generate styled audit summaries in **PDF** (via ReportLab) and raw data sheets in **CSV**.

---

## Seed Accounts (Password: `password123`)

Upon first run, the SQLite database is automatically created and seeded with these demo profiles:

| Username | Role | Security Question Answer |
|---|---|---|
| **admin** | Administrator | `fluffy` |
| **alice** | HR | `new york` |
| **bob** | Finance | `smith` |
| **charlie** | Employee | `lincoln` |

---

## Setup & Deployment Guide

### Prerequisites
- Python 3.12+ (managed automatically if you use `uv`)
- `uv` Python package manager (highly recommended for speed)

### Step 1: Install `uv` (if not already installed)
In a Windows PowerShell:
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Step 2: Initialize Virtual Environment & Install Dependencies
Navigate to the project directory and run:
```bash
# Create virtual environment
uv venv --python 3.12

# Install dependencies from requirements.txt
uv pip install -r requirements.txt
```

### Step 3: Train Machine Learning Models
Generate synthetic logs and train the Isolation Forest and Random Forest models:
```bash
# Generate CSV logs dataset
.venv\Scripts\python.exe data/generate_dataset.py

# Train ML models and export serial pickles (.pkl)
.venv\Scripts\python.exe app/ml/train_model.py
```

### Step 4: Launch Flask Security Gateway Server
```bash
.venv\Scripts\python.exe run.py
```
Open your web browser and go to `http://127.0.0.1:5000`.

---

## Project Directory Tree

```
zero-threat/
├── app/
│   ├── __init__.py               # Flask app factory & DB Seeding
│   ├── config.py                 # App configurations
│   ├── extensions.py             # SQLAlchemy, LoginManager, Mail, Session
│   ├── models.py                 # SQLite database tables schema
│   ├── api/                      # REST endpoints for charts (JSON feeds)
│   ├── auth/                     # MFA & Adaptive Verification controller
│   ├── dashboard/                # Admin & User dashboards controllers
│   ├── honeypot/                 # Decoy files traps controllers
│   ├── ml/                       # Trust engine, UBA & Scikit-learn inference
│   ├── monitoring/               # Alerts resolver & activity logs controllers
│   ├── reports/                  # CSV & PDF exporter (ReportLab)
│   ├── simulation/               # Threat simulation controls
│   └── templates/                # Bootstrap 5 dark glassmorphic layouts
├── data/
│   └── generate_dataset.py       # Generates sample dataset
├── ml_models/                    # Serialized models folder
│   ├── isolation_forest.pkl
│   ├── random_forest.pkl
│   └── scaler.pkl
├── requirements.txt              # Project requirements
├── run.py                        # Entry point
└── README.md                     # Setup guide
```
