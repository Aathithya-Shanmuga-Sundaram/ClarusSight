# ClarusSight CTI Dashboard
[![Python 3.6+](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/)
[![Seven Dependencies](https://img.shields.io/badge/Dependencies-5-green.svg)](https://www.python.org/)
[![Cybersecurity Lab](https://img.shields.io/badge/%23MakeEveryoneCyberSafe-orange.svg)](https://github.com/Aathithya-Shanmuga-Sundaram)

A production-ready Cyber Threat Intelligence (CTI) Dashboard with AI-powered anomaly detection, incident response playbooks, and professional PDF reporting.

---

## 🚀 Features

### Real-time Threat Monitoring

* 5 Threat Categories: **Malware**, **Phishing**, **DoS**, **Reconnaissance**, **Insider Threats**
* Live Data Simulation: Generates realistic minute-by-minute threat data
* Interactive Plotly Charts: Switch between threat types with anomaly overlays

### AI/ML Powered Detection

* **Isolation Forest**: Global multivariate anomaly detection
* **Z-Score Contextual**: Category-specific spike detection
* **Random Forest Forecasting**: 10-minute ahead predictions

### Incident Response Playbook

* Automated Incident Tracking: Anomalies → Trackable Incidents
* One-Click Actions: Mitigate / Dismiss with audit trail
* Response Status Dashboard: Open / Resolved incident metrics

### Professional Reporting

* PDF Export: Executive summaries, threat distributions, active incidents
* Real Data Integration: Pulls live stats from your operations
* Print-ready: Stakeholder briefings and lab demonstrations

### AdminLTE Enterprise UI

* Dark cybersecurity theme
* Responsive design (mobile/desktop)
* Profile page with real performance metrics

---

## 🛠️ Tech Stack

* **Backend**: Flask + Pandas + Scikit-learn
* **Frontend**: AdminLTE 3.2 + Plotly.js + Bootstrap 5
* **AI/ML**: RandomForestRegressor, IsolationForest, StandardScaler
* **PDF**: ReportLab
* **Data**: CSV + JSON persistence

---

## 📦 Installation

```bash
# Clone & Install
git clone https://github.com/Aathithya-Shanmuga-Sundaram/ClarusSight
cd ClarusSight
pip install -r requirements.txt

# Run
python app.py
```

## 🎮 Usage

* **Start Dashboard:** `python app.py`
* **Login Password:** `admin` (change in `config.json`)
* **Monitor Threats:** Dashboard auto-generates data + detects anomalies
* **Respond:** Alerts → Mitigate/Dismiss incidents
* **Export Report:** Profile → "Professional Report" → PDF download

---

## 📊 Sample Report Output

**ClarusSight CTI Report**
*Generated: December 12, 2025 08:47 UTC*

**Executive Summary:**

* Total Events: 12,450
* Open Incidents: 23
* Resolved: 187
* Response Rate: 89%

**Threat Landscape:**

* PHISHING (42.3%)
* MALWARE (31.7%)
* RECON (15.2%)
* ...

---
## 🔧 Configuration

```json
// config.json (auto-generated)
{
  "admin_password": "admin",
  "preserve_history": true,
  "webhook_url": ""
}
```

---

## 📈 Data Flow

```
Synthetic Data → Pivot Table → ML Models →
Anomaly Detection → Incident DB → Dashboard → PDF Report
```

---

*#MakeEveryoneCyberSafe* - Built for cybersecurity education & real-world SOC operations 🚀
