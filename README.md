# CyberSentry AI

AI-assisted digital forensics and incident-response prototype.

## Setup (Windows PowerShell)

```powershell
cd "$HOME\Documents\CyberSentry-AI"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m pytest -v
python -m streamlit run app.py
```

Upload only log files you are authorized to examine. Detection and anomaly results are investigative leads, not proof of malicious activity. The application is a local prototype and does not automatically contain or remediate real systems.
