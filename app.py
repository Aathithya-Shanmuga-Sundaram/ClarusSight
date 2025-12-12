import atexit
import json
import os
import uuid
from datetime import datetime, timedelta
from io import StringIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from flask import (
    Flask, request, session, redirect, url_for, send_file,
    render_template_string, jsonify, flash
)
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------------------
# CONFIG
# ---------------------------
APP_SECRET_KEY = "super-secret-key-change-me"
CONFIG_PATH = "config.json"
HISTORY_CSV = "history.csv"
INCIDENTS_JSON = "incidents.json"
RANDOM_SEED = 42

# Synthetic data params
CATEGORIES = ["malware", "phishing", "dos", "recon", "insider"]
CAT_COLORS = {
    "malware": "#e74c3c", "phishing": "#f39c12", "dos": "#9b59b6",
    "recon": "#3498db", "insider": "#2ecc71"
}

BASE_RATE = {"malware": 5, "phishing": 8, "dos": 2, "recon": 4, "insider": 1}
DEFAULT_GENERATE_MINUTES = 120

LAGS = 6
FORECAST_HORIZON = 10
ISO_N_ESTIMATORS = 100
ROLLING_WINDOW = 30
INITIAL_ADMIN_PASSWORD = "admin"

np.random.seed(RANDOM_SEED)

# ---------------------------
# App setup
# ---------------------------
app = Flask(__name__)
app.secret_key = APP_SECRET_KEY

def create_runtime_config():
    cfg = {"admin_password": INITIAL_ADMIN_PASSWORD, "webhook_url": "", "preserve_history": True}
    with open(CONFIG_PATH, "w") as f: json.dump(cfg, f)
    return cfg

def read_runtime_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f: return json.load(f)
    return None

def update_runtime_config(updates: dict):
    cfg = read_runtime_config() or {}
    cfg.update(updates)
    with open(CONFIG_PATH, "w") as f: json.dump(cfg, f)
    return cfg

def destroy_runtime_config():
    if os.path.exists(CONFIG_PATH):
        try: os.remove(CONFIG_PATH)
        except: pass

create_runtime_config()
atexit.register(destroy_runtime_config)

# ---------------------------
# Data & Incident Management
# ---------------------------
def ensure_files_exist():
    if not os.path.exists(HISTORY_CSV):
        pd.DataFrame(columns=["timestamp", "category", "count"]).to_csv(HISTORY_CSV, index=False)
    if not os.path.exists(INCIDENTS_JSON):
        with open(INCIDENTS_JSON, "w") as f: json.dump({}, f)

def read_history():
    ensure_files_exist()
    df = pd.read_csv(HISTORY_CSV, parse_dates=["timestamp"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

def append_rows_to_history(rows):
    pd.DataFrame(rows).to_csv(HISTORY_CSV, mode="a", index=False, header=not os.path.exists(HISTORY_CSV))

def reset_history():
    if os.path.exists(HISTORY_CSV): os.remove(HISTORY_CSV)
    if os.path.exists(INCIDENTS_JSON): os.remove(INCIDENTS_JSON)
    ensure_files_exist()

# --- INCIDENT DB FUNCTIONS ---
def load_incidents():
    ensure_files_exist()
    with open(INCIDENTS_JSON, "r") as f: return json.load(f)

def save_incidents(db):
    with open(INCIDENTS_JSON, "w") as f: json.dump(db, f, indent=2)

def update_incident_status(incident_id, status, action_note=""):
    db = load_incidents()
    if incident_id in db:
        db[incident_id]["status"] = status
        db[incident_id]["history"].append({
            "timestamp": str(datetime.utcnow()),
            "action": status,
            "note": action_note,
            "user": "Admin"
        })
        save_incidents(db)

def sync_anomalies_to_incidents(alerts_list):
    db = load_incidents()
    new_count = 0
    for a in alerts_list:
        key = f"{a['ts']}_{a['type']}_{a.get('cat','ALL')}"
        found = False
        for i_id, i_data in db.items():
            if i_data.get("key") == key:
                found = True
                break
        
        if not found:
            new_id = str(uuid.uuid4())[:8]
            db[new_id] = {
                "id": new_id,
                "key": key,
                "timestamp": str(a['ts']),
                "severity": a['severity'],
                "type": a['type'],
                "details": a['details'],
                "status": "OPEN",
                "history": []
            }
            new_count += 1
    
    if new_count > 0:
        save_incidents(db)
    return db

# ---------------------------
# REPORT GENERATION
# ---------------------------
def generate_professional_report():
    """Generate comprehensive cybersecurity report PDF"""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"ClarusSight_Report_{timestamp}.pdf"
    
    doc = SimpleDocTemplate(filename, pagesize=A4,
                          rightMargin=72, leftMargin=72,
                          topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.darkblue
    )
    
    story = []
    
    # Title Page
    story.append(Paragraph("ClarusSight CTI", title_style))
    story.append(Paragraph("Cyber Threat Intelligence Report", title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%B %d, %Y %H:%M UTC')}", styles['Normal']))
    story.append(Spacer(1, 100))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    history = read_history()
    incidents = load_incidents()
    
    total_events = len(history)
    open_incidents = len([i for i in incidents.values() if i["status"] == "OPEN"])
    resolved_incidents = len([i for i in incidents.values() if i["status"] == "RESOLVED"])
    
    summary_data = [
        ['Metric', 'Value'],
        ['Total Events', f'{total_events:,}'],
        ['Open Incidents', open_incidents],
        ['Resolved Incidents', resolved_incidents],
        ['Response Rate', f'{int((resolved_incidents/(open_incidents+resolved_incidents+1))*100)}%']
    ]
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Threat Distribution
    story.append(Paragraph("Threat Landscape", heading_style))
    pivot = pivot_counts(history.tail(1000))
    cat_totals = pivot.sum().to_dict()
    
    threats_data = [['Threat Type', 'Events', 'Percentage']]
    total = sum(cat_totals.values())
    for cat in CATEGORIES:
        count = cat_totals.get(cat, 0)
        pct = (count/total)*100 if total > 0 else 0
        threats_data.append([cat.upper(), f'{int(count)}', f'{pct:.1f}%'])
    
    threats_table = Table(threats_data)
    threats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(threats_table)
    story.append(Spacer(1, 20))
    
    # Recent Incidents
    story.append(Paragraph("Active Incidents", heading_style))
    recent_incidents = sorted(incidents.values(), key=lambda x: x["timestamp"], reverse=True)[:10]
    
    if recent_incidents:
        inc_data = [['ID', 'Type', 'Severity', 'Status', 'Time']]
        for inc in recent_incidents:
            inc_data.append([
                inc['id'][:8],
                inc['type'][:20],
                inc['severity'],
                inc['status'],
                pd.to_datetime(inc['timestamp']).strftime('%Y-%m-%d %H:%M')
            ])
        
        inc_table = Table(inc_data, colWidths=[1*inch, 2*inch, 1*inch, 1*inch, 1.5*inch])
        inc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        story.append(inc_table)
    
    story.append(Spacer(1, 30))
    story.append(Paragraph("Report generated by ClarusSight MECS v1.0", styles['Normal']))
    
    doc.build(story)
    return filename

# ---------------------------
# Simulation & Modeling
# ---------------------------
def simulate_minute_counts(start_ts, minutes=120):
    rows = []
    for minute in range(minutes):
        ts = start_ts + timedelta(minutes=minute)
        hour = ts.hour + ts.minute/60.0
        day_factor = 1 + 0.3 * np.sin((hour / 24.0) * 2 * np.pi * 3)
        for cat in CATEGORIES:
            base = BASE_RATE.get(cat, 2)
            noise = np.random.poisson(max(0.5, base * 0.4))
            trend = max(0, np.random.normal(loc=0.1 * (minute/60.0), scale=0.1))
            count = max(0, int(base * day_factor + noise + trend))
            if np.random.rand() < 0.005: count += int(base * np.random.randint(8, 25))
            rows.append({"timestamp": ts, "category": cat, "count": count})
    return rows

def pivot_counts(df):
    df2 = df.copy()
    grouped = df2.groupby(["timestamp", "category"])["count"].sum().unstack(fill_value=0)
    for c in CATEGORIES:
        if c not in grouped.columns: grouped[c] = 0
    return grouped[CATEGORIES].sort_index()

def make_lag_features(series, lags=LAGS):
    df = pd.DataFrame({"y": series})
    for lag in range(1, lags+1):
        df[f"lag_{lag}"] = df["y"].shift(lag)
    return df.dropna()

def train_forecaster(series, lags=LAGS):
    df = make_lag_features(series, lags)
    if df.shape[0] < 10: return None, float(series.mean() if len(series) else 0)
    X = df[[f"lag_{i}" for i in range(1, lags+1)]].values
    y = df["y"].values
    model = RandomForestRegressor(n_estimators=50, max_depth=10, random_state=RANDOM_SEED)
    model.fit(X, y)
    last_lags = series.values[-lags:] if len(series) >= lags else np.concatenate([np.repeat(series.mean(), lags - len(series)), series.values])
    return model, last_lags

def forecast_series(model, last_lags, horizon=FORECAST_HORIZON, lags=LAGS):
    preds, lags_list = [], list(last_lags)
    for _ in range(horizon):
        X = np.array(lags_list[-lags:]).reshape(1, -1)
        p = float(max(0, model.predict(X)[0])) if model else float(np.mean(lags_list))
        preds.append(p)
        lags_list.append(p)
    return preds

def detect_point_anomalies(pivot_df):
    if pivot_df.shape[0] < 10: return pd.Series([False]*pivot_df.shape[0], index=pivot_df.index)
    iso = IsolationForest(n_estimators=ISO_N_ESTIMATORS, contamination=0.01, random_state=RANDOM_SEED)
    scaled = StandardScaler().fit_transform(pivot_df.values)
    return pd.Series(iso.fit_predict(scaled) == -1, index=pivot_df.index)

def detect_contextual_anomalies(series, window=ROLLING_WINDOW, z_thresh=3.0):
    if len(series) < window+2: return pd.Series([False]*len(series), index=series.index)
    rolling_mean = series.rolling(window=window, min_periods=3).mean()
    rolling_std = series.rolling(window=window, min_periods=3).std().replace(0, 1e-6)
    return (((series - rolling_mean) / rolling_std).abs() > z_thresh).fillna(False)

# ---------------------------
# Auth
# ---------------------------
def is_logged_in(): return session.get("logged_in", False)
def check_password(pw):
    cfg = read_runtime_config()
    return pw == cfg.get("admin_password", "") if cfg else False

# ---------------------------
# HTML TEMPLATES
# ---------------------------
BASE_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ClarusSight | CTI Dashboard</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/css/adminlte.min.css">
  <style>
    body { font-family: 'Source Sans Pro', sans-serif; }
    .content-wrapper { background-color: #343a40 !important; }
    .card { background-color: #2c3136; color: #fff; box-shadow: 0 0 10px rgba(0,0,0,0.3); border: 1px solid #454d55; }
    .form-control, .form-select { background-color: #1f2429; border: 1px solid #6c757d; color: #fff; }
    .form-control:focus { background-color: #2b3035; color: #fff; border-color: #3498db; }
    .login-page { background-color: #1a1d21 !important; }
    .login-box { width: 400px; }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: #1f2429; }
    ::-webkit-scrollbar-thumb { background: #6c757d; border-radius: 4px; }
    pre { color: #2ecc71; background: #111; padding: 10px; border-radius: 4px; border: 1px solid #333; }
    .badge-open { background-color: #e74c3c; color: white; }
    .badge-resolved { background-color: #2ecc71; color: white; }
    .badge-dismissed { background-color: #7f8c8d; color: white; }
  </style>
  <script src="https://cdn.plot.ly/plotly-2.22.0.min.js"></script>
  <script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/js/adminlte.min.js"></script>
</head>
<body class="hold-transition dark-mode {% if active == 'login' %}login-page{% else %}sidebar-mini layout-fixed layout-navbar-fixed layout-footer-fixed{% endif %}">
{% if active == 'login' %}
    <div class="login-box">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible">
                {{ message }}
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {{ body | safe }}
    </div>
{% else %}
<div class="wrapper">
  <nav class="main-header navbar navbar-expand navbar-dark">
    <ul class="navbar-nav">
      <li class="nav-item"><a class="nav-link" data-widget="pushmenu" href="#" role="button"><i class="fas fa-bars"></i></a></li>
      <li class="nav-item d-none d-sm-inline-block"><span class="nav-link text-muted">RESPONSE STATUS: <span class="text-success fw-bold">ACTIVE</span></span></li>
    </ul>
    <ul class="navbar-nav ms-auto">
      {% if logged_in %}
      <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
      {% endif %}
    </ul>
  </nav>

  <aside class="main-sidebar sidebar-dark-primary elevation-4">
    <a href="{{ url_for('dashboard') }}" class="brand-link">
      <span class="brand-text font-weight-light ps-3"><i class="fas fa-shield-alt text-danger"></i> &nbsp;ClarusSight <strong>Dashboard</strong></span>
    </a>
    <div class="sidebar">
      <div class="user-panel mt-3 pb-3 mb-3 d-flex">
        <div class="image"><img src="https://ui-avatars.com/api/?name=Admin&background=random" class="img-circle elevation-2" alt="User"></div>
        <div class="info">
          <a href="{{ url_for('profile') }}" class="d-block text-white text-decoration-none fw-bold">
            Administrator
          </a>
          <small class="text-muted">Cyber Threat Analyst</small>
        </div>
      </div>
      <nav class="mt-2">
        <ul class="nav nav-pills nav-sidebar flex-column" data-widget="treeview" role="menu">
          <li class="nav-item"><a href="{{ url_for('dashboard') }}" class="nav-link {% if active=='dashboard' %}active{% endif %}"><i class="nav-icon fas fa-tachometer-alt"></i><p>Dashboard</p></a></li>
          <li class="nav-item"><a href="{{ url_for('profile') }}" class="nav-link {% if active=='profile' %}active{% endif %}"><i class="nav-icon fas fa-user"></i><p>Profile</p></a></li>
          <li class="nav-item"><a href="{{ url_for('alerts') }}" class="nav-link {% if active=='alerts' %}active{% endif %}"><i class="nav-icon fas fa-bell"></i><p>Incidents & Response</p></a></li>
          <li class="nav-header">SYSTEM</li>
          <li class="nav-item"><a href="{{ url_for('settings') }}" class="nav-link {% if active=='settings' %}active{% endif %}"><i class="nav-icon fas fa-cogs"></i><p>Settings</p></a></li>
        </ul>
      </nav>
    </div>
  </aside>

  <div class="content-wrapper">
    <div class="content-header">
      <div class="container-fluid">
        <div class="row mb-2">
          <div class="col-sm-6"><h1 class="m-0">{{ title }}</h1></div>
        </div>
      </div>
    </div>
    
    <section class="content">
      <div class="container-fluid">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        {{ body | safe }}
      </div>
    </section>
  </div>
  <footer class="main-footer">
    <div class="float-end d-none d-sm-inline">Engine: <b>MECS v1.0</b></div>
    <strong>Copyright &copy; {{ year }} <a href="#">ClarusSight</a>.</strong>
  </footer>
</div>
{% endif %}
</body>
</html>
"""

# [Previous templates remain the same - DASHBOARD_TEMPLATE, PROFILE_TEMPLATE unchanged]
PROFILE_TEMPLATE = """
<div class="row">
    <div class="col-md-4">
        <div class="card card-widget widget-user shadow">
            <div class="widget-user-header bg-info" style="height: 200px;">
                <h3 class="widget-user-username text-white">Administrator</h3>
                <h5 class="widget-user-desc text-white">Cyber Threat Analyst</h5>
            </div>
            <div class="widget-user-image">
                <img src="https://ui-avatars.com/api/?name=Admin&background=3498db&color=fff&size=128&bold=true" class="img-circle elevation-2" alt="User Avatar">
            </div>
            <div class="card-footer">
                <div class="row">
                    <div class="col-sm-4 border-right">
                        <div class="description-block">
                            <h4 class="description-header">{{ incidents_handled }}</h4>
                            <span class="description-text">Incidents Handled</span>
                        </div>
                    </div>
                    <div class="col-sm-4 border-right">
                        <div class="description-block">
                            <h4 class="description-header">{{ response_rate }}%</h4>
                            <span class="description-text">Response Rate</span>
                        </div>
                    </div>
                    <div class="col-sm-4">
                        <div class="description-block">
                            <h4 class="description-header">{{ active_hours }}h</h4>
                            <span class="description-text">Active Session</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">Recent Activity</h3>
            </div>
            <div class="card-body">
                <ul class="timeline">
                    {% if recent_activities %}
                        {% for activity in recent_activities %}
                        <li>
                            <i class="fas fa-{{ 'shield-alt' if activity.action == 'RESOLVED' else 'exclamation-triangle' }} bg-{{ 'success' if activity.action == 'RESOLVED' else 'warning' }}"></i>
                            <div class="timeline-item">
                                <span class="time"><i class="fas fa-clock"></i> {{ activity.time }}</span>
                                <h3 class="timeline-header">{{ activity.description }}</h3>
                            </div>
                        </li>
                        {% endfor %}
                    {% else %}
                        <li class="text-center text-muted py-4">No recent activity</li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </div>
</div>
<div class="row mt-4">
    <div class="col-12">
        <div class="card">
            <div class="card-body">
                <h5>Quick Actions</h5>
                <div class="row">
                    <div class="col-md-2">
                        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-primary btn-block mb-2">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </div>
                    <div class="col-md-2">
                        <a href="{{ url_for('alerts') }}" class="btn btn-outline-warning btn-block mb-2">
                            <i class="fas fa-bell"></i> Incidents
                        </a>
                    </div>
                    <div class="col-md-2">
                        <a href="{{ url_for('settings') }}" class="btn btn-outline-info btn-block mb-2">
                            <i class="fas fa-cogs"></i> Settings
                        </a>
                    </div>
                    <div class="col-md-3">
                        <a href="{{ url_for('download_history') }}" class="btn btn-outline-success btn-block mb-2">
                            <i class="fas fa-download"></i> Export Data
                        </a>
                    </div>
                    <div class="col-md-3">
                        <a href="{{ url_for('download_report') }}" class="btn btn-success btn-block mb-2">
                            <i class="fas fa-file-pdf"></i> Professional Report
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
"""

# Continue from DASHBOARD_TEMPLATE (rest of the full app.py)

DASHBOARD_TEMPLATE = """
    <div class="row">
      <div class="col-12 col-sm-6 col-md-3">
        <div class="info-box mb-3 bg-dark">
          <span class="info-box-icon bg-info elevation-1"><i class="fas fa-wave-square"></i></span>
          <div class="info-box-content">
            <span class="info-box-text">Total Events</span>
            <span class="info-box-number">{{ total_events }}</span>
          </div>
        </div>
      </div>
      <div class="col-12 col-sm-6 col-md-3">
        <div class="info-box mb-3 bg-dark">
          <span class="info-box-icon bg-danger elevation-1"><i class="fas fa-exclamation-triangle"></i></span>
          <div class="info-box-content">
            <span class="info-box-text">Open Incidents</span>
            <span class="info-box-number">{{ open_incidents }}</span>
          </div>
        </div>
      </div>
      <div class="col-12 col-sm-6 col-md-3">
        <div class="info-box mb-3 bg-dark">
          <span class="info-box-icon bg-success elevation-1"><i class="fas fa-check-circle"></i></span>
          <div class="info-box-content">
            <span class="info-box-text">Resolved</span>
            <span class="info-box-number">{{ resolved_incidents }}</span>
          </div>
        </div>
      </div>
      <div class="col-12 col-sm-6 col-md-3">
        <div class="info-box mb-3 bg-dark">
          <span class="info-box-icon elevation-1" style="background-color: {{ cat_colors[top_cat] }}"><i class="fas fa-skull"></i></span>
          <div class="info-box-content">
            <span class="info-box-text">Top Threat</span>
            <span class="info-box-number">{{ top_cat|upper }} ({{ top_cat_count }})</span>
          </div>
        </div>
      </div>
    </div>

    <div class="row">
      <div class="col-lg-8">
        <div class="card">
          <div class="card-header border-0">
            <div class="d-flex justify-content-between">
              <h3 class="card-title">Real-time Threat Monitoring</h3>
              <div class="card-tools">
                 <select id="category_select" class="form-select form-select-sm" style="width: 150px; display:inline-block;">
                    {% for cat in categories %}
                      <option value="{{cat}}">{{cat|upper}}</option>
                    {% endfor %}
                  </select>
              </div>
            </div>
          </div>
          <div class="card-body">
            <div id="chart-error" class="text-danger" style="display:none;">Error loading chart engine.</div>
            <div id="main_chart" style="height: 400px; min-height: 400px;"></div>
          </div>
        </div>
      </div>

      <div class="col-lg-4">
        <div class="card">
          <div class="card-header border-0"><h3 class="card-title">Action Required (Open)</h3></div>
          <div class="card-body p-0">
            <div class="table-responsive" style="max-height: 400px;">
              <table class="table table-striped table-valign-middle">
                <thead><tr><th>Time</th><th>Alert</th><th>Action</th></tr></thead>
                <tbody>
                {% if recent_alerts %}
                  {% for a in recent_alerts %}
                  <tr>
                    <td><small>{{ a.time_str }}</small></td>
                    <td>
                      <span class="badge" style="background-color: {{ cat_colors.get(a.cat, '#6c757d') }};">
                        {{ a.type }}
                      </span>
                    </td>
                    <td><a href="{{ url_for('alerts') }}" class="btn btn-xs btn-outline-danger">Response</a></td>
                  </tr>
                  {% endfor %}
                {% else %}
                  <tr><td colspan="3" class="text-center text-muted">All systems green.</td></tr>
                {% endif %}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <div class="card">
            <div class="card-body">
                <div class="d-grid gap-2">
                    <a href="{{ url_for('dashboard') }}" class="btn btn-primary"><i class="fas fa-sync"></i> Refresh & Generate Data</a>
                    <a href="{{ url_for('alerts') }}" class="btn btn-warning"><i class="fas fa-clipboard-check"></i> Open Playbook</a>
                </div>
            </div>
        </div>
      </div>
    </div>

    <script>
      const pivot_index = {{ pivot_index|tojson }};
      const pivot_data = {{ pivot_data|tojson }};
      const forecast_results = {{ forecast_results|tojson }};
      const point_anoms_idx = {{ point_anoms_idx|tojson }};
      const context_anoms_idx = {{ context_anoms_idx|tojson }};
      const categories = {{ categories|tojson }};
      const cat_colors = {{ cat_colors|tojson }};
      const forecast_horizon = {{ forecast_horizon }};

      const plotly_config = {responsive: true, displayModeBar: false};
      const layout_base = {
        template: 'plotly_dark', paper_bgcolor: 'rgba(0,0,0,0)', plot_bgcolor: 'rgba(0,0,0,0)',
        font: { family: 'Source Sans Pro', color: '#ccc' }, margin: { t: 30, l: 40, r: 20, b: 40 },
        xaxis: { gridcolor: '#444' }, yaxis: { gridcolor: '#444' }
      };

      function plotMain(cat) {
        try {
            const x = pivot_index.map(s => new Date(s));
            const y = pivot_data.map(r => r[cat]);
            const color = cat_colors[cat] || '#ccc';
            const trace_obs = { x: x, y: y, mode: 'lines', name: 'Observed', line: {color: color, width: 2}, fill: 'tozeroy', fillcolor: color + '33' };

            const pa_x = point_anoms_idx.filter(t => pivot_index.includes(t)).map(t => new Date(t));
            const pa_y = pa_x.map(dt => { const row = pivot_data.find(r => r.timestamp === dt.toISOString()); return row ? row[cat] : null; });
            const trace_pa = { x: pa_x, y: pa_y, mode: 'markers', marker: {size:12, symbol:'x-open', color: '#fff', line:{width:2}}, name: 'Global Anomaly' };

            const ca_idx = context_anoms_idx[cat] || [];
            const ca_x = ca_idx.map(t => new Date(t));
            const ca_y = ca_x.map(dt => { const row = pivot_data.find(r => r.timestamp === dt.toISOString()); return row ? row[cat] : null; });
            const trace_ca = { x: ca_x, y: ca_y, mode: 'markers', marker:{size:10, symbol:'circle-open', color: '#f39c12', line:{width:2}}, name: 'Context Spike' };

            const last_ts = new Date(pivot_index[pivot_index.length-1]);
            const f_x = Array.from({length: forecast_horizon}, (_, i) => new Date(last_ts.getTime() + (i+1)*60000));
            const trace_fc = { x: f_x, y: forecast_results[cat], mode: 'lines', name: 'AI Forecast', line: {dash:'dot', color: '#fff'} };

            Plotly.newPlot('main_chart', [trace_obs, trace_pa, trace_ca, trace_fc], 
                {...layout_base, title: {text: cat.toUpperCase() + ' ACTIVITY', font:{size:14}}}, plotly_config);
        } catch (e) { document.getElementById('chart-error').style.display = 'block'; }
      }

      document.addEventListener('DOMContentLoaded', () => {
        const sel = document.getElementById('category_select');
        if (sel) {
            plotMain(sel.value);
            sel.addEventListener('change', function(){ plotMain(this.value); });
        }
      });
    </script>
"""

# ---------------------------
# Routes (Complete)
# ---------------------------
@app.route("/")
def root(): return redirect(url_for("dashboard") if is_logged_in() else url_for("login"))

@app.route("/download_report")
def download_report():
    """Export professional PDF report"""
    if not is_logged_in(): return redirect(url_for("login"))
    
    try:
        filename = generate_professional_report()
        flash("Professional report generated successfully!", "success")
        return send_file(filename, as_attachment=True, download_name="ClarusSight_Threat_Report.pdf")
    except Exception as e:
        flash(f"Report generation failed: {str(e)}", "error")
        return redirect(url_for("profile"))

@app.route("/profile")
def profile():
    if not is_logged_in(): return redirect(url_for("login"))
    
    # Get real stats from incidents
    db = load_incidents()
    all_incidents = list(db.values())
    incidents_handled = len([i for i in all_incidents if i["status"] in ["RESOLVED", "DISMISSED"]])
    total_incidents = len(all_incidents)
    response_rate = int((incidents_handled / max(total_incidents, 1)) * 100) if total_incidents > 0 else 97
    active_hours = "15"
    
    # Recent activities
    recent_activities = []
    for incident in sorted(all_incidents, key=lambda x: x["timestamp"], reverse=True)[:5]:
        if incident["history"]:
            last_action = incident["history"][-1]
            recent_activities.append({
                "time": pd.to_datetime(last_action["timestamp"]).strftime('%H:%M'),
                "action": last_action["action"],
                "description": f'{last_action["action"]} {incident["type"]} incident #{incident["id"]}'
            })
    
    profile_content = render_template_string(
        PROFILE_TEMPLATE,
        incidents_handled=incidents_handled,
        response_rate=response_rate,
        active_hours=active_hours,
        recent_activities=recent_activities
    )
    
    return render_template_string(
        BASE_LAYOUT, 
        body=profile_content, 
        active="profile", 
        logged_in=True, 
        year=datetime.utcnow().year, 
        title="Profile"
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if check_password(request.form.get("password", "")):
            session["logged_in"] = True
            flash("Welcome back, Sir.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Access Denied: Invalid credentials.", "error")
    body = """
    <div class="login-logo"><a href="#"><b>ClarusSight</b> | CTI DASHBOARD</a></div>
    <div class="card">
      <div class="card-body login-card-body">
        <p class="login-box-msg">Sign in to access threat intelligence</p>
        <form method="post">
          <div class="input-group mb-3"><input type="password" name="password" class="form-control" placeholder="Password"><div class="input-group-text"><span class="fas fa-lock"></span></div></div>
          <div class="row"><div class="col-12"><button type="submit" class="btn btn-primary btn-block w-100">Authenticate</button></div></div>
        </form>
      </div>
    </div>
    """
    return render_template_string(BASE_LAYOUT, body=body, active="login", logged_in=False, year=datetime.utcnow().year, title="Login")

@app.route("/logout")
def logout():
    session.clear()
    flash("Session terminated.", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not is_logged_in(): return redirect(url_for("login"))

    # 1. Config & Data Gen
    cfg = read_runtime_config() or {}
    preserve = cfg.get("preserve_history", True)
    history = read_history() if preserve else pd.DataFrame(columns=["timestamp", "category", "count"])
    
    last_ts = pd.to_datetime(history["timestamp"].max()) if not history.empty else (datetime.utcnow() - timedelta(minutes=DEFAULT_GENERATE_MINUTES))
    start_ts = last_ts + timedelta(minutes=1)
    rows = simulate_minute_counts(start_ts, DEFAULT_GENERATE_MINUTES)
    
    if preserve: append_rows_to_history(rows)
    else: history = pd.DataFrame(rows)
    
    if preserve: history = read_history()
    
    pivot = pivot_counts(history)
    pivot = pivot.tail(int(request.args.get("display_minutes", 240)))

    # 2. AI Analysis
    forecast_results = {}
    for cat in CATEGORIES:
        model, ll = train_forecaster(pivot[cat].astype(float))
        forecast_results[cat] = forecast_series(model, ll)
    
    point_anoms = detect_point_anomalies(pivot)
    context_anoms = pd.DataFrame({cat: detect_contextual_anomalies(pivot[cat]) for cat in CATEGORIES})

    # 3. Detect & Sync Incidents
    detected_alerts = []
    for ts in pivot.index:
        is_pt = point_anoms.loc[ts]
        cats = [cat for cat in CATEGORIES if context_anoms.loc[ts, cat]]
        if is_pt or cats:
            detected_alerts.append({
                "ts": ts,
                "type": "Global Anomaly" if is_pt else "Context Spike",
                "details": f"Spike in {', '.join(cats)}" if cats else "Pattern Deviation",
                "cat": cats[0] if cats else "all",
                "severity": "CRITICAL" if is_pt else "WARNING"
            })
    
    incident_db = sync_anomalies_to_incidents(detected_alerts)

    # 4. Prepare UI Data
    total_events = pivot.sum().sum()
    open_incidents = len([i for i in incident_db.values() if i["status"] == "OPEN"])
    resolved_incidents = len([i for i in incident_db.values() if i["status"] == "RESOLVED"])
    top_cat = pivot.sum().idxmax()
    
    recent_display = []
    for i in sorted(incident_db.values(), key=lambda x: x["timestamp"], reverse=True)[:8]:
        if i["status"] == "OPEN":
            dt = pd.to_datetime(i["timestamp"])
            recent_display.append({"time_str": dt.strftime('%H:%M'), "type": i["type"], "cat": i.get("cat","all")})

    pivot_json = pivot.reset_index().to_dict(orient="records")
    for r in pivot_json: r["timestamp"] = pd.to_datetime(r["timestamp"]).isoformat()
    
    dashboard_content = render_template_string(
        DASHBOARD_TEMPLATE,
        categories=CATEGORIES, cat_colors=CAT_COLORS,
        pivot_index=[ts.isoformat() for ts in pivot.index],
        pivot_data=pivot_json,
        forecast_results=forecast_results,
        point_anoms_idx=[ts.isoformat() for ts, v in point_anoms.items() if v],
        context_anoms_idx={cat: [ts.isoformat() for ts, v in context_anoms[cat].items() if v] for cat in CATEGORIES},
        forecast_horizon=FORECAST_HORIZON,
        total_events=total_events, open_incidents=open_incidents, resolved_incidents=resolved_incidents,
        top_cat=top_cat, top_cat_count=int(pivot.sum().max()), recent_alerts=recent_display
    )

    return render_template_string(BASE_LAYOUT, body=dashboard_content, active="dashboard", logged_in=True, year=datetime.utcnow().year, title="Dashboard")

@app.route("/alerts", methods=["GET", "POST"])
def alerts():
    if not is_logged_in(): return redirect(url_for("login"))
    
    if request.method == "POST":
        inc_id = request.form.get("incident_id")
        action = request.form.get("action")
        if action == "mitigate":
            update_incident_status(inc_id, "RESOLVED", "Automated Playbook: Blocked IP Source & Reset Credentials.")
            flash("Threat mitigated successfully. Incident closed.", "success")
        elif action == "dismiss":
            update_incident_status(inc_id, "DISMISSED", "Marked as False Positive by Analyst.")
            flash("Alert dismissed.", "info")
        return redirect(url_for("alerts"))

    db = load_incidents()
    incidents = sorted(db.values(), key=lambda x: x["timestamp"], reverse=True)
    
    alerts_body = """
    <div class="row">
        <div class="col-12">
            <div class="card card-outline card-danger">
                <div class="card-header">
                    <h3 class="card-title">Incident Response Queue</h3>
                </div>
                <div class="card-body table-responsive p-0">
                    <table class="table table-hover text-nowrap">
                        <thead><tr><th>Time</th><th>Status</th><th>Severity</th><th>Threat Type</th><th>Details</th><th>Playbook Actions</th></tr></thead>
                        <tbody>
                        {% for i in incidents %}
                            <tr>
                                <td>{{ i.timestamp }}</td>
                                <td><span class="badge badge-{{ i.status|lower }}">{{ i.status }}</span></td>
                                <td><span class="text-{{ 'danger' if i.severity=='CRITICAL' else 'warning' }} font-weight-bold">{{ i.severity }}</span></td>
                                <td>{{ i.type }}</td>
                                <td>{{ i.details }}</td>
                                <td>
                                    {% if i.status == 'OPEN' %}
                                    <form method="post" style="display:inline-block;">
                                        <input type="hidden" name="incident_id" value="{{ i.id }}">
                                        <input type="hidden" name="action" value="mitigate">
                                        <button class="btn btn-xs btn-success"><i class="fas fa-shield-alt"></i> Mitigate</button>
                                    </form>
                                    <form method="post" style="display:inline-block;">
                                        <input type="hidden" name="incident_id" value="{{ i.id }}">
                                        <input type="hidden" name="action" value="dismiss">
                                        <button class="btn btn-xs btn-secondary">Dismiss</button>
                                    </form>
                                    {% else %}
                                        <small class="text-muted">No actions available</small>
                                    {% endif %}
                                </td>
                            </tr>
                        {% else %}
                            <tr><td colspan="6" class="text-center">No incidents recorded.</td></tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div class="row">
        <div class="col-12">
             <div class="card">
                <div class="card-header"><h3 class="card-title">Response Audit Log</h3></div>
                <div class="card-body">
                    <ul>
                    {% for i in incidents if i.history|length > 0 %}
                        {% for h in i.history %}
                            <li><b>[{{ h.timestamp }}]</b> Incident {{ i.id }} changed to {{ h.action }} by {{ h.user }} — <i>{{ h.note }}</i></li>
                        {% endfor %}
                    {% endfor %}
                    </ul>
                </div>
             </div>
        </div>
    </div>
    """
    content = render_template_string(alerts_body, incidents=incidents)
    return render_template_string(BASE_LAYOUT, body=content, active="alerts", logged_in=True, year=datetime.utcnow().year, title="Incidents")

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not is_logged_in(): return redirect(url_for("login"))
    cfg = read_runtime_config() or {}
    if request.method == "POST":
        action = request.form.get("action")
        if action == "reset_history":
            reset_history()
            flash("Database purged.", "success")
        elif action == "toggle_preserve":
            update_runtime_config({"preserve_history": request.form.get("preserve") == "on"})
            flash("Settings saved.", "success")
        return redirect(url_for("settings"))

    settings_body = """
    <div class="card card-danger">
        <div class="card-header"><h3 class="card-title">Reset Environment</h3></div>
        <div class="card-body">
             <form method="post" onsubmit="return confirm('Purge ALL history and incidents?');">
                <input type="hidden" name="action" value="reset_history">
                <button class="btn btn-danger"><i class="fas fa-trash"></i> Purge All Data</button>
            </form>
        </div>
    </div>
    """
    content = render_template_string(settings_body)
    return render_template_string(BASE_LAYOUT, body=content, active="settings", logged_in=True, year=datetime.utcnow().year, title="Settings")

@app.route("/download/history")
def download_history(): return send_file(HISTORY_CSV, as_attachment=True) if is_logged_in() else redirect(url_for("login"))

@app.route("/download/pivot")
def download_pivot():
    if not is_logged_in(): return redirect(url_for("login"))
    return send_file(StringIO(pivot_counts(read_history()).reset_index().to_csv(index=False)), as_attachment=True, download_name="pivot.csv", mimetype="text/csv")

if __name__ == "__main__":
    ensure_files_exist()
    app.run(debug=True, host="0.0.0.0", port=5000)
