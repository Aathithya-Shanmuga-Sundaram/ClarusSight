# Cyber Threat Intelligence Dashboard

An interactive **cybersecurity analytics dashboard** built with Streamlit, designed to visualize and interpret live or mock threat data in real time.
It helps analysts understand **attack patterns, severity levels, and global threat distribution** through intuitive visuals and user-driven filtering.

---

## ⚙️ Features

* **📈 Threat Trends:**
  Visualize how threats evolve over time using responsive line charts.
* **🧾 Threat Database:**
  View, filter, and search through recent threat records in an interactive table.
* **🌍 Geolocation Mapping:**
  See where cyber threats originate using a dynamic, color-coded world map.
* **🚨 Alerts Panel:**
  Displays recent security alerts and critical vulnerability notifications.
* **📊 Severity Breakdown:**
  Analyze the distribution of threats by severity level using bar charts.
* **🔍 User Controls:**
  Filter threats by type, search for specific indicators, or export filtered results.
* **📂 Data Input Options:**
  Upload your own threat dataset in `.csv` format — or fall back to auto-generated demo data.

---

## 🧩 Technologies Used

* **Python**
* **Streamlit**
* **Pandas**
* **Plotly**
* **NumPy**

---

## 💻 Installation

### **Prerequisites**

* Python **3.8+**
* `pip` (Python package manager)

### **Steps to Install**

```bash
# Clone the repository
git clone https://github.com/Aathithya-Shanmuga-Sundaram/Cyber-Threat-Intelligence-Dashboard

# Navigate into the project directory
cd Cyber-Threat-Intelligence-Dashboard

# Install dependencies
pip install streamlit pandas plotly numpy
```

---

## 🚀 Usage

To launch the dashboard, run:

```bash
streamlit run app.py
```

After starting, a new tab will open in your default browser showing the **Cyber Threat Intelligence Dashboard**.

---

## 📁 Data Input

You can **upload your own threat data** (`.csv`) to replace the demo dataset.

### Expected CSV Format:

| publishedDate | description                                                           | severity | latitude | longitude | type    |
| ------------- | --------------------------------------------------------------------- | -------- | -------- | --------- | ------- |
| 2024-11-01    | Multiple SYN packets from a single IP — possible SYN flood attack.    | High     | 48.8566  | 2.3522    | DDoS    |
| 2024-11-02    | Outbound traffic spike to unknown region — data exfiltration attempt. | Critical | 34.0522  | -118.2437 | Malware |

If no file is uploaded, the app automatically generates **realistic mock data** for demonstration.

---

## Contributing

Contributions are always welcome.
Fork the repository, create a new branch, make your changes, and submit a pull request.

---

## Author

**Aathithya Shanmuga Sundaram**
Cybersecurity Enthusiast • Researcher • Developer

[LinkedIn](https://www.linkedin.com/in/aathithya-shanmuga-sundaram) | [GitHub](https://github.com/Aathithya-Shanmuga-Sundaram)
