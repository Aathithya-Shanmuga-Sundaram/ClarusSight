# Cyber Threat Intelligence Dashboard

[![Python 3.6+](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/)
[![Seven Dependencies](https://img.shields.io/badge/Dependencies-7-green.svg)](https://www.python.org/)
[![Cybersecurity Lab](https://img.shields.io/badge/%23MakeEveryoneCyberSafe-orange.svg)](https://github.com/Aathithya-Shanmuga-Sundaram)

An **AI-enhanced cybersecurity analytics platform** built with **Streamlit**, designed to help security teams visualize, analyze, and forecast global cyber threat trends. The dashboard combines **interactive data visualization** with **machine learning models** for **threat prediction** and **anomaly detection**, turning raw incident data into actionable intelligence.

---

## 🚀 Features

### 📊 **Data Visualization**

* Interactive line charts for threat trends over time
* Severity-based classification with bar charts
* Real-time geolocation mapping of threat sources
* Search and filter by specific threat types

### 🤖 **AI-Powered Insights**

* **Threat Prediction (Prophet Model):**
  Uses time-series forecasting to predict future cyber threat trends and potential surges.

* **Anomaly Detection (Isolation Forest):**
  Detects unusual activity spikes that may indicate zero-day attacks or targeted campaigns.

### 🗂️ **Data Management**

* Upload your own CSV dataset or use the built-in demo data
* Filter and explore threats by type, severity, or description
* Export filtered results as CSV
* Integrated alert feed for recent critical vulnerabilities

### 🧠 **Tech Stack**

* **Frontend:** Streamlit
* **Visualization:** Plotly
* **Data Handling:** Pandas, NumPy
* **Machine Learning:** Prophet, Scikit-learn
* **Language:** Python

---

## ⚙️ Installation

### Prerequisites

* Python 3.8 or higher
* pip (Python package manager)

### Steps to Install

```bash
# 1. Clone the repository
git clone https://github.com/Aathithya-Shanmuga-Sundaram/Cyber-Threat-Intelligence-Dashboard

# 2. Navigate to the project directory
cd Cyber-Threat-Intelligence-Dashboard

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the application with:

```bash
streamlit run app.py
```

Then open the automatically launched browser tab.

### Upload Options

* **Upload your own threat dataset** (`.csv` format)
* Or use the **auto-generated demo dataset**

---

## Example Dataset (CSV Format)

| publishedDate | description                               | severity | latitude | longitude | type     |
| ------------- | ----------------------------------------- | -------- | -------- | --------- | -------- |
| 2024-10-15    | DDoS attack on cloud infrastructure       | Critical | 37.77    | -122.41   | DDoS     |
| 2024-10-16    | Phishing attempt targeting banking sector | High     | 48.85    | 2.35      | Phishing |

---

## 📈 Modules Overview

### 1. **Threat Trend Visualization**

Shows monthly variation in global cyber incidents using interactive charts.

### 2. **Threat Prediction**

Predicts upcoming threat spikes using Facebook Prophet time-series modeling.

### 3. **Anomaly Detection**

Identifies irregular spikes using Isolation Forest, flagging abnormal threat counts.

### 4. **Geolocation Map**

Displays threats on a global map with color-coded severity levels.

### 5. **Data Filtering & Export**

Allows filtering by threat type and downloading refined results.

---

## 🗾 Results & Findings

* AI models enhance the accuracy of early warning systems for threat surges.
* Anomaly detection supports proactive response to irregular activity.
* Visualization aids in quick assessment and reporting for cybersecurity teams.

---

## 🧱 Future Enhancements

* Integration with real-time threat intelligence APIs
* User authentication and role-based dashboards
* Email alerts for anomalies
* Multi-language support and customizable UI themes

---

## 🤝 Contribution

Contributions are welcome!
Fork this repository, make your changes, and submit a pull request.

---

## 🧉 License

MIT License © 2025 Aathithya Shanmuga Sundaram

---

**Short Repo Description:**

> AI-powered Cyber Threat Intelligence Dashboard built with Streamlit — visualize, predict, and detect anomalies in global cyber threat data using Prophet forecasting and Isolation Forest models.
