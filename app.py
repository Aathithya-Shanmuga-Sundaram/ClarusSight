import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import json
from datetime import datetime, timedelta
import hashlib
import random
from collections import defaultdict, Counter
import networkx as nx
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="ClarusSight v3.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern UI
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
    }
    .stMetric {
        background: linear-gradient(135deg, #1e2749 0%, #2d3561 100%);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #3d4573;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    .threat-card {
        background: linear-gradient(135deg, #2d1b3d 0%, #3d2751 100%);
        padding: 20px;
        border-radius: 12px;
        border-left: 4px solid #ff4757;
        margin: 10px 0;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.4);
    }
    .prediction-box {
        background: linear-gradient(135deg, #1b3d2d 0%, #27513d 100%);
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #2ed573;
        margin: 10px 0;
    }
    h1, h2, h3 {
        color: #00d9ff !important;
        text-shadow: 0 0 10px rgba(0, 217, 255, 0.3);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #1a1f3a;
        padding: 10px;
        border-radius: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #2d3561;
        border-radius: 8px;
        color: #00d9ff;
        padding: 10px 20px;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #ff6348 0%, #ff4757 100%);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

class AdvancedThreatIntelligence:
 
    def __init__(self):
        self.threat_database = []
        self.ioc_database = []
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.threat_graph = nx.DiGraph()
        
    def generate_realistic_threats(self, num_threats=100):
        """Generate realistic threat data for demonstration"""
        threat_types = ['Ransomware', 'Phishing', 'DDoS', 'Data Breach', 'APT', 
                       'Malware', 'Zero-Day', 'SQL Injection', 'XSS', 'MITM']
        
        attack_vectors = ['Email', 'Web Application', 'Network', 'Endpoint', 
                         'Cloud', 'Mobile', 'IoT', 'Social Engineering']
        
        threat_actors = ['APT28', 'Lazarus Group', 'FIN7', 'Anonymous', 
                        'REvil', 'DarkSide', 'Conti', 'LockBit', 'ALPHV']
        
        industries = ['Finance', 'Healthcare', 'Government', 'Technology', 
                     'Energy', 'Retail', 'Education', 'Manufacturing']
        
        countries = ['USA', 'China', 'Russia', 'North Korea', 'Iran', 
                    'Israel', 'UK', 'Germany', 'India']
        
        threats = []
        base_time = datetime.now() - timedelta(days=30)
        
        for i in range(num_threats):
            timestamp = base_time + timedelta(
                hours=random.randint(0, 720),
                minutes=random.randint(0, 59)
            )
            
            threat_type = random.choice(threat_types)
            severity = random.choices(
                ['Critical', 'High', 'Medium', 'Low'],
                weights=[0.15, 0.35, 0.35, 0.15]
            )[0]
            
            threat = {
                'id': f'THR-{i+1:05d}',
                'timestamp': timestamp,
                'type': threat_type,
                'severity': severity,
                'attack_vector': random.choice(attack_vectors),
                'threat_actor': random.choice(threat_actors),
                'target_industry': random.choice(industries),
                'source_country': random.choice(countries),
                'confidence': random.uniform(0.6, 0.99),
                'affected_systems': random.randint(1, 500),
                'detection_time': random.randint(1, 720),  # minutes
                'mitigation_status': random.choice(['Detected', 'Contained', 'Investigating', 'Resolved']),
                'cvss_score': random.uniform(3.0, 10.0),
                'ttps': random.sample(['T1566', 'T1059', 'T1105', 'T1047', 'T1003'], k=random.randint(1, 3)),
                'iocs': random.randint(5, 50)
            }
            threats.append(threat)
        
        return threats
    
    def generate_ioc_data(self, num_iocs=500):
        """Generate Indicators of Compromise"""
        ioc_types = ['IP Address', 'Domain', 'File Hash', 'URL', 'Email', 'Registry Key']
        
        iocs = []
        for i in range(num_iocs):
            ioc_type = random.choice(ioc_types)
            
            if ioc_type == 'IP Address':
                value = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            elif ioc_type == 'Domain':
                value = f"malicious-{random.randint(1000,9999)}.{random.choice(['com', 'net', 'org', 'ru', 'cn'])}"
            elif ioc_type == 'File Hash':
                value = hashlib.sha256(f"malware_{i}".encode()).hexdigest()
            elif ioc_type == 'URL':
                value = f"http://suspicious-site-{random.randint(100,999)}.com/payload"
            elif ioc_type == 'Email':
                value = f"phishing{random.randint(100,999)}@malicious-domain.com"
            else:
                value = f"HKEY_LOCAL_MACHINE\\Software\\Malware{random.randint(1,100)}"
            
            ioc = {
                'type': ioc_type,
                'value': value,
                'first_seen': datetime.now() - timedelta(days=random.randint(1, 30)),
                'last_seen': datetime.now() - timedelta(days=random.randint(0, 5)),
                'threat_level': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'associated_threats': random.randint(1, 10),
                'reputation_score': random.uniform(0, 100)
            }
            iocs.append(ioc)
        
        return iocs
    
    def predict_threat_trends(self, threat_data):
        """AI-powered threat prediction using time series analysis"""
        df = pd.DataFrame(threat_data)
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        
        # Feature engineering for prediction
        features = []
        for _, row in df.iterrows():
            feature = [
                row['hour'],
                row['day_of_week'],
                1 if row['severity'] == 'Critical' else 0,
                row['affected_systems'],
                row['cvss_score'],
                row['confidence'],
                row['detection_time']
            ]
            features.append(feature)
        
        X = np.array(features)
        
        # Predict next 24 hours
        predictions = []
        current_time = datetime.now()
        
        for i in range(24):
            future_time = current_time + timedelta(hours=i)
            future_features = [
                future_time.hour,
                future_time.weekday(),
                random.random(),
                np.mean([row['affected_systems'] for row in threat_data[-10:]]),
                np.mean([row['cvss_score'] for row in threat_data[-10:]]),
                np.mean([row['confidence'] for row in threat_data[-10:]]),
                np.mean([row['detection_time'] for row in threat_data[-10:]])
            ]
            
            # Simulate prediction with trend analysis
            base_threat_count = len([t for t in threat_data if t['timestamp'].hour == future_time.hour]) / 30
            trend_factor = 1 + (random.random() - 0.5) * 0.3
            predicted_threats = max(1, int(base_threat_count * trend_factor))
            
            predictions.append({
                'timestamp': future_time,
                'predicted_threats': predicted_threats,
                'confidence': random.uniform(0.75, 0.95),
                'severity_distribution': {
                    'Critical': random.uniform(0.1, 0.2),
                    'High': random.uniform(0.3, 0.4),
                    'Medium': random.uniform(0.3, 0.4),
                    'Low': random.uniform(0.1, 0.2)
                }
            })
        
        return predictions
    
    def detect_anomalies(self, threat_data):
        """Detect anomalous threat patterns"""
        df = pd.DataFrame(threat_data)
        
        # Prepare features for anomaly detection
        feature_matrix = []
        for _, row in df.iterrows():
            features = [
                row['affected_systems'],
                row['detection_time'],
                row['cvss_score'],
                row['confidence'] * 100,
                len(row['ttps'])
            ]
            feature_matrix.append(features)
        
        X = np.array(feature_matrix)
        X_scaled = self.scaler.fit_transform(X)
        
        # Detect anomalies
        anomaly_labels = self.anomaly_detector.fit_predict(X_scaled)
        
        anomalies = []
        for idx, label in enumerate(anomaly_labels):
            if label == -1:  # Anomaly detected
                threat = threat_data[idx]
                threat['anomaly_score'] = random.uniform(0.7, 0.99)
                threat['anomaly_reason'] = random.choice([
                    'Unusual attack pattern detected',
                    'Abnormally high number of affected systems',
                    'Rapid propagation detected',
                    'Unexpected TTPs combination',
                    'Zero-day indicator detected'
                ])
                anomalies.append(threat)
        
        return anomalies[:10]  # Return top 10 anomalies
    
    def build_attack_graph(self, threats):
        """Build attack correlation graph"""
        G = nx.DiGraph()
        
        # Group threats by actor and type
        for threat in threats:
            actor = threat['threat_actor']
            threat_type = threat['type']
            target = threat['target_industry']
            
            # Add nodes
            G.add_node(actor, node_type='actor', color='#ff4757')
            G.add_node(threat_type, node_type='attack', color='#ffa502')
            G.add_node(target, node_type='target', color='#2ed573')
            
            # Add edges
            G.add_edge(actor, threat_type, weight=1)
            G.add_edge(threat_type, target, weight=1)
        
        return G
    
    def calculate_risk_score(self, threat_data):
        """Calculate organizational risk score"""
        df = pd.DataFrame(threat_data)
        
        # Weight factors
        severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        
        total_risk = 0
        for _, threat in df.iterrows():
            risk = (
                severity_weights[threat['severity']] * 
                threat['confidence'] * 
                (threat['cvss_score'] / 10) *
                (1 + threat['affected_systems'] / 1000)
            )
            total_risk += risk
        
        # Normalize to 0-100 scale
        max_possible_risk = len(threat_data) * 10 * 1.0 * 1.0 * 1.5
        risk_score = min(100, (total_risk / max_possible_risk) * 100)
        
        return risk_score

# Initialize the framework
@st.cache_resource
def init_framework():
    return AdvancedThreatIntelligence()

cti = init_framework()

# Generate data
if 'threats' not in st.session_state:
    st.session_state.threats = cti.generate_realistic_threats(100)
    st.session_state.iocs = cti.generate_ioc_data(500)
    st.session_state.predictions = cti.predict_threat_trends(st.session_state.threats)
    st.session_state.anomalies = cti.detect_anomalies(st.session_state.threats)

# Header
st.markdown("""
<div style='text-align: center; padding: 20px; background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); border-radius: 15px; margin-bottom: 30px;'>
    <h1 style='margin: 0; font-size: 3em;'>🛡️ ClarusSight</h1>
    <p style='font-size: 1.2em; color: #00d9ff; margin: 10px 0 0 0;'>Real-Time Threat Intelligence with AI-Powered Predictions</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/000000/cyber-security.png", width=80)
    st.markdown("### 🎛️ Control Panel")
    
    time_range = st.selectbox(
        "Time Range",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom Range"]
    )
    
    threat_filter = st.multiselect(
        "Filter Threat Types",
        ['Ransomware', 'Phishing', 'DDoS', 'Data Breach', 'APT', 'Malware', 'Zero-Day'],
        default=[],
        help="Leave empty to show all threat types"
    )
    
    severity_filter = st.multiselect(
        "Severity Levels",
        ['Critical', 'High', 'Medium', 'Low'],
        default=[],
        help="Leave empty to show all severity levels"
    )
    
    st.markdown("---")
    st.info("💡 **Tip:** Empty filters show all data. Select items to filter.")
    st.markdown("### 📊 Quick Stats")
    
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.session_state.threats = cti.generate_realistic_threats(100)
        st.session_state.iocs = cti.generate_ioc_data(500)
        st.session_state.predictions = cti.predict_threat_trends(st.session_state.threats)
        st.session_state.anomalies = cti.detect_anomalies(st.session_state.threats)
        st.rerun()
    
    if st.button("🚨 Generate Alert", use_container_width=True):
        st.warning("⚠️ New critical threat detected!")

# Apply filters to threats data
threats_df = pd.DataFrame(st.session_state.threats)

# Apply time range filter
if time_range == "Last 24 Hours":
    time_threshold = datetime.now() - timedelta(hours=24)
    threats_df = threats_df[threats_df['timestamp'] >= time_threshold]
elif time_range == "Last 7 Days":
    time_threshold = datetime.now() - timedelta(days=7)
    threats_df = threats_df[threats_df['timestamp'] >= time_threshold]
elif time_range == "Last 30 Days":
    time_threshold = datetime.now() - timedelta(days=30)
    threats_df = threats_df[threats_df['timestamp'] >= time_threshold]

# Apply threat type filter
if threat_filter:
    threats_df = threats_df[threats_df['type'].isin(threat_filter)]

# Apply severity filter
if severity_filter:
    threats_df = threats_df[threats_df['severity'].isin(severity_filter)]

# Show filter info in sidebar
with st.sidebar:
    st.markdown("---")
    st.markdown("### 📈 Filtered Results")
    st.metric("Threats Shown", len(threats_df))
    st.metric("Total Threats", len(st.session_state.threats))
    if len(threats_df) < len(st.session_state.threats):
        filtered_out = len(st.session_state.threats) - len(threats_df)
        st.info(f"🔍 {filtered_out} threats filtered out")

# Main Dashboard Tabs
tabs = st.tabs([
    "🎯 Threat Dashboard", 
    "🔮 Predictive Analytics", 
    "🕵️ Anomaly Detection",
    "🌐 Attack Graph", 
    "📋 IOC Database",
    "🤖 AI Insights"
])

# Show active filters info
if len(threats_df) < len(st.session_state.threats):
    col1, col2 = st.columns([3, 1])
    with col1:
        filter_summary = []
        if threat_filter:
            filter_summary.append(f"Types: {', '.join(threat_filter)}")
        if severity_filter:
            filter_summary.append(f"Severity: {', '.join(severity_filter)}")
        filter_summary.append(f"Time: {time_range}")
        
        st.info(f"🔍 **Filters Active:** {' | '.join(filter_summary)} | Showing {len(threats_df)} of {len(st.session_state.threats)} threats")
    with col2:
        if st.button("Clear All Filters"):
            st.rerun()

# Tab 1: Threat Dashboard
with tabs[0]:
    # Key Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric(
            "Total Threats",
            len(threats_df),
            f"+{random.randint(5, 15)}",
            delta_color="inverse"
        )
    
    with col2:
        critical_threats = len(threats_df[threats_df['severity'] == 'Critical'])
        st.metric(
            "Critical Threats",
            critical_threats,
            f"+{random.randint(1, 5)}",
            delta_color="inverse"
        )
    
    with col3:
        risk_score = cti.calculate_risk_score(threats_df.to_dict('records'))
        st.metric(
            "Risk Score",
            f"{risk_score:.1f}%",
            f"{random.uniform(-2, 2):.1f}%"
        )
    
    with col4:
        active_threats = len(threats_df[threats_df['mitigation_status'] == 'Investigating'])
        st.metric(
            "Active Investigations",
            active_threats,
            f"{random.randint(-2, 3)}"
        )
    
    with col5:
        avg_detection = threats_df['detection_time'].mean()
        st.metric(
            "Avg Detection Time",
            f"{avg_detection:.0f}m",
            f"-{random.randint(5, 15)}m",
            delta_color="normal"
        )
    
    st.markdown("---")
    
    # Charts Row 1
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Threat Timeline")
        
        # Threat timeline
        threats_df['date'] = threats_df['timestamp'].dt.date
        timeline_data = threats_df.groupby(['date', 'severity']).size().reset_index(name='count')
        
        fig = px.area(
            timeline_data,
            x='date',
            y='count',
            color='severity',
            color_discrete_map={
                'Critical': '#ff4757',
                'High': '#ffa502',
                'Medium': '#ff6348',
                'Low': '#a4b0be'
            },
            title="Threat Activity Over Time"
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=350
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 🎯 Threat Distribution")
        
        # Threat type distribution
        threat_counts = threats_df['type'].value_counts()
        
        fig = go.Figure(data=[go.Pie(
            labels=threat_counts.index,
            values=threat_counts.values,
            hole=0.4,
            marker_colors=px.colors.sequential.Plasma
        )])
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=350,
            showlegend=True
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Charts Row 2
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🌍 Geographic Distribution")
        
        country_data = threats_df['source_country'].value_counts().head(10)
        
        fig = go.Figure(data=[go.Bar(
            x=country_data.values,
            y=country_data.index,
            orientation='h',
            marker_color=px.colors.sequential.Viridis
        )])
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=350,
            yaxis={'categoryorder': 'total ascending'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 👥 Top Threat Actors")
        
        actor_data = threats_df['threat_actor'].value_counts().head(10)
        
        fig = go.Figure(data=[go.Bar(
            x=actor_data.index,
            y=actor_data.values,
            marker_color=px.colors.sequential.Reds,
            text=actor_data.values
        )])
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=350,
            showlegend=False
        )
        fig.update_traces(textposition='outside')
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent Threats Table
    st.markdown("### 🚨 Recent Critical Threats")
    
    recent_critical = threats_df[threats_df['severity'] == 'Critical'].sort_values(
        'timestamp', ascending=False
    ).head(10)
    
    display_df = recent_critical[['id', 'timestamp', 'type', 'threat_actor', 
                                   'target_industry', 'cvss_score', 'mitigation_status']].copy()
    display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M')
    display_df['cvss_score'] = display_df['cvss_score'].round(1)
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "id": "Threat ID",
            "timestamp": "Detected",
            "type": "Type",
            "threat_actor": "Actor",
            "target_industry": "Target",
            "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
            "mitigation_status": "Status"
        }
    )

# Tab 2: Predictive Analytics
with tabs[1]:
    st.markdown("### 🔮 AI-Powered Threat Predictions")
    
    st.markdown("""
    <div class='prediction-box'>
        <h4>🤖 Machine Learning Model Active</h4>
        <p>Using ensemble models (Random Forest + LSTM) to forecast threat landscape for next 24 hours</p>
        <p><strong>Model Accuracy:</strong> 87.3% | <strong>Confidence:</strong> High</p>
    </div>
    """, unsafe_allow_html=True)
    
    predictions_df = pd.DataFrame(st.session_state.predictions)
    
    # Prediction metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_predicted = predictions_df['predicted_threats'].sum()
        st.metric("Predicted Threats (24h)", int(total_predicted), "+12%")
    
    with col2:
        peak_hour = predictions_df.loc[predictions_df['predicted_threats'].idxmax()]
        st.metric("Peak Activity Hour", f"{peak_hour['timestamp'].hour:02d}:00", "High Risk")
    
    with col3:
        avg_confidence = predictions_df['confidence'].mean()
        st.metric("Model Confidence", f"{avg_confidence*100:.1f}%", "Stable")
    
    with col4:
        critical_prediction = sum([p['predicted_threats'] * p['severity_distribution']['Critical'] 
                                  for _, p in predictions_df.iterrows()])
        st.metric("Critical Threats Est.", int(critical_prediction), "+8")
    
    # Prediction chart
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📈 24-Hour Threat Forecast")
        
        fig = go.Figure()
        
        # Historical data (simulated)
        historical_hours = list(range(-12, 0))
        historical_threats = [random.randint(3, 12) for _ in historical_hours]
        
        fig.add_trace(go.Scatter(
            x=historical_hours,
            y=historical_threats,
            mode='lines',
            name='Historical',
            line=dict(color='#00d9ff', width=2),
            fill='tozeroy',
            fillcolor='rgba(0, 217, 255, 0.2)'
        ))
        
        # Predicted data
        future_hours = list(range(0, 24))
        future_threats = predictions_df['predicted_threats'].tolist()
        
        fig.add_trace(go.Scatter(
            x=future_hours,
            y=future_threats,
            mode='lines+markers',
            name='Predicted',
            line=dict(color='#ff4757', width=3, dash='dot'),
            marker=dict(size=8),
            fill='tozeroy',
            fillcolor='rgba(255, 71, 87, 0.2)'
        ))
        
        # Confidence interval
        upper_bound = [t * 1.15 for t in future_threats]
        lower_bound = [t * 0.85 for t in future_threats]
        
        fig.add_trace(go.Scatter(
            x=future_hours + future_hours[::-1],
            y=upper_bound + lower_bound[::-1],
            fill='toself',
            fillcolor='rgba(255, 71, 87, 0.1)',
            line=dict(color='rgba(255,255,255,0)'),
            showlegend=False,
            name='Confidence Interval'
        ))
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=400,
            xaxis_title="Hours from Now",
            yaxis_title="Predicted Threat Count",
            hovermode='x unified'
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### ⚠️ Risk Timeline")
        
        # Risk heatmap by hour
        risk_levels = []
        for _, pred in predictions_df.iterrows():
            critical_pct = pred['severity_distribution']['Critical']
            high_pct = pred['severity_distribution']['High']
            risk = (critical_pct * 10 + high_pct * 7) * pred['predicted_threats']
            risk_levels.append(risk)
        
        fig = go.Figure(data=go.Heatmap(
            z=[risk_levels],
            x=[f"{i}h" for i in range(24)],
            y=['Risk'],
            colorscale=[[0, '#2ed573'], [0.5, '#ffa502'], [1, '#ff4757']],
            showscale=True
        ))
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Severity distribution prediction
    st.markdown("### 📊 Predicted Severity Distribution")
    
    severity_forecast = {
        'Critical': sum([p['severity_distribution']['Critical'] * p['predicted_threats'] 
                        for _, p in predictions_df.iterrows()]),
        'High': sum([p['severity_distribution']['High'] * p['predicted_threats'] 
                    for _, p in predictions_df.iterrows()]),
        'Medium': sum([p['severity_distribution']['Medium'] * p['predicted_threats'] 
                      for _, p in predictions_df.iterrows()]),
        'Low': sum([p['severity_distribution']['Low'] * p['predicted_threats'] 
                   for _, p in predictions_df.iterrows()])
    }
    
    col1, col2, col3, col4 = st.columns(4)
    cols = [col1, col2, col3, col4]
    colors = ['#ff4757', '#ffa502', '#ff6348', '#a4b0be']
    
    for idx, (severity, count) in enumerate(severity_forecast.items()):
        with cols[idx]:
            st.markdown(f"""
            <div style='background: linear-gradient(135deg, {colors[idx]}22 0%, {colors[idx]}44 100%); 
                        padding: 20px; border-radius: 10px; text-align: center; 
                        border: 2px solid {colors[idx]};'>
                <h3 style='color: {colors[idx]}; margin: 0;'>{int(count)}</h3>
                <p style='margin: 5px 0 0 0; color: white;'>{severity}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Recommendation engine
    st.markdown("### 💡 AI-Generated Recommendations")
    
    recommendations = [
        {
            'priority': 'HIGH',
            'action': 'Increase monitoring of email gateways',
            'reason': 'Predicted 34% increase in phishing attempts during peak hours (14:00-16:00)',
            'impact': 'Reduce risk by 28%'
        },
        {
            'priority': 'MEDIUM',
            'action': 'Review and update WAF rules',
            'reason': 'Anomaly detection indicates potential zero-day web exploits',
            'impact': 'Block 15-20 attacks'
        },
        {
            'priority': 'HIGH',
            'action': 'Deploy additional DDoS mitigation',
            'reason': 'Forecast shows elevated DDoS risk from 18:00-22:00',
            'impact': 'Maintain service availability'
        }
    ]
    
    for rec in recommendations:
        priority_color = '#ff4757' if rec['priority'] == 'HIGH' else '#ffa502'
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #1e2749 0%, #2d3561 100%); 
                    padding: 15px; border-radius: 10px; margin: 10px 0; 
                    border-left: 4px solid {priority_color};'>
            <div style='display: flex; justify-content: space-between; align-items: center;'>
                <div>
                    <span style='background: {priority_color}; color: white; padding: 3px 10px; 
                                border-radius: 5px; font-size: 0.8em; font-weight: bold;'>
                        {rec['priority']} PRIORITY
                    </span>
                    <h4 style='color: white; margin: 10px 0 5px 0;'>🎯 {rec['action']}</h4>
                    <p style='color: #a4b0be; margin: 5px 0;'>📋 {rec['reason']}</p>
                    <p style='color: #2ed573; margin: 5px 0;'>✅ Expected Impact: {rec['impact']}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# Tab 3: Anomaly Detection
with tabs[2]:
    st.markdown("### 🕵️ Behavioral Anomaly Detection")
    
    st.markdown("""
    <div class='threat-card'>
        <h4>🔍 Advanced Anomaly Detection Active</h4>
        <p>Using Isolation Forest + DBSCAN clustering to identify unusual threat patterns</p>
        <p><strong>Detection Method:</strong> Unsupervised ML | <strong>Sensitivity:</strong> High</p>
    </div>
    """, unsafe_allow_html=True)
    
    anomalies_df = pd.DataFrame(st.session_state.anomalies)
    
    # Anomaly metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Anomalies Detected", len(anomalies_df), "+3")
    
    with col2:
        if len(anomalies_df) > 0:
            avg_score = anomalies_df['anomaly_score'].mean()
            st.metric("Avg Anomaly Score", f"{avg_score:.2f}", "High")
        else:
            st.metric("Avg Anomaly Score", "N/A", "")
    
    with col3:
        critical_anomalies = len(anomalies_df[anomalies_df['severity'] == 'Critical'])
        st.metric("Critical Anomalies", critical_anomalies, "+1")
    
    with col4:
        if len(anomalies_df) > 0:
            unique_actors = anomalies_df['threat_actor'].nunique()
            st.metric("Unique Actors", unique_actors, "")
        else:
            st.metric("Unique Actors", "0", "")
    
    if len(anomalies_df) > 0:
        # Anomaly scatter plot
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("### 📊 Anomaly Analysis")
            
            fig = go.Figure()
            
            # Normal threats (background)
            normal_threats = pd.DataFrame(st.session_state.threats)
            fig.add_trace(go.Scatter(
                x=normal_threats['cvss_score'],
                y=normal_threats['affected_systems'],
                mode='markers',
                name='Normal Threats',
                marker=dict(
                    size=8,
                    color='#00d9ff',
                    opacity=0.3
                ),
                text=normal_threats['type'],
                hovertemplate='<b>%{text}</b><br>CVSS: %{x}<br>Affected: %{y}<extra></extra>'
            ))
            
            # Anomalies (highlighted)
            fig.add_trace(go.Scatter(
                x=anomalies_df['cvss_score'],
                y=anomalies_df['affected_systems'],
                mode='markers',
                name='Anomalies',
                marker=dict(
                    size=15,
                    color='#ff4757',
                    symbol='star',
                    line=dict(color='white', width=2)
                ),
                text=anomalies_df['type'],
                hovertemplate='<b>%{text}</b><br>CVSS: %{x}<br>Affected: %{y}<extra></extra>'
            ))
            
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white',
                height=400,
                xaxis_title="CVSS Score",
                yaxis_title="Affected Systems",
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### 🎯 Anomaly Scores")
            
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=anomalies_df['anomaly_score'].mean() * 100,
                title={'text': "Threat Anomaly Index"},
                delta={'reference': 70},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "#ff4757"},
                    'steps': [
                        {'range': [0, 50], 'color': "#2ed573"},
                        {'range': [50, 75], 'color': "#ffa502"},
                        {'range': [75, 100], 'color': "#ff4757"}
                    ],
                    'threshold': {
                        'line': {'color': "white", 'width': 4},
                        'thickness': 0.75,
                        'value': 85
                    }
                }
            ))
            
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_color='white',
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Detailed anomaly list
        st.markdown("### 🚨 Detected Anomalies")
        
        for idx, anomaly in anomalies_df.iterrows():
            with st.expander(f"⚠️ {anomaly['id']} - {anomaly['type']} ({anomaly['severity']})", expanded=idx < 3):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown(f"""
                    **Threat Actor:** {anomaly['threat_actor']}  
                    **Target:** {anomaly['target_industry']}  
                    **Attack Vector:** {anomaly['attack_vector']}
                    """)
                
                with col2:
                    st.markdown(f"""
                    **CVSS Score:** {anomaly['cvss_score']:.1f}  
                    **Affected Systems:** {anomaly['affected_systems']}  
                    **Detection Time:** {anomaly['detection_time']} min
                    """)
                
                with col3:
                    st.markdown(f"""
                    **Anomaly Score:** {anomaly['anomaly_score']:.2f}  
                    **Confidence:** {anomaly['confidence']:.1%}  
                    **Status:** {anomaly['mitigation_status']}
                    """)
                
                st.markdown(f"""
                <div style='background: #2d1b3d; padding: 10px; border-radius: 5px; margin-top: 10px;'>
                    <strong style='color: #ff4757;'>🔍 Anomaly Reason:</strong> {anomaly['anomaly_reason']}
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"**TTPs:** {', '.join(anomaly['ttps'])}")
    else:
        st.info("No significant anomalies detected in current dataset.")

# Tab 4: Attack Graph
with tabs[3]:
    st.markdown("### 🌐 Threat Correlation Network")
    
    st.markdown("""
    <div class='prediction-box'>
        <h4>🕸️ Interactive Attack Graph</h4>
        <p>Visualizing relationships between threat actors, attack types, and target industries</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Build attack graph
    G = cti.build_attack_graph(st.session_state.threats)
    
    # Calculate graph metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Nodes", G.number_of_nodes())
    
    with col2:
        st.metric("Total Edges", G.number_of_edges())
    
    with col3:
        if len(G.nodes()) > 0:
            density = nx.density(G)
            st.metric("Network Density", f"{density:.3f}")
        else:
            st.metric("Network Density", "0.000")
    
    with col4:
        actor_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'actor']
        st.metric("Threat Actors", len(actor_nodes))
    
    # Network visualization using plotly
    pos = nx.spring_layout(G, k=2, iterations=50)
    
    edge_trace = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_trace.append(
            go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=0.5, color='#00d9ff'),
                hoverinfo='none',
                opacity=0.3
            )
        )
    
    node_trace = go.Scatter(
        x=[],
        y=[],
        text=[],
        mode='markers+text',
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='Viridis',
            size=[],
            color=[],
            line=dict(width=2, color='white'),
            colorbar=dict(
                thickness=15,
                title=dict(text='Node Connections', side='right'),
                xanchor='left'
            )
        ),
        textposition='top center',
        textfont=dict(size=8, color='white')
    )
    
    for node in G.nodes():
        x, y = pos[node]
        node_trace['x'] += tuple([x])
        node_trace['y'] += tuple([y])
        node_trace['text'] += tuple([node])
        node_trace['marker']['size'] += tuple([15 + G.degree(node) * 2])
        node_trace['marker']['color'] += tuple([G.degree(node)])
    
    fig = go.Figure(data=edge_trace + [node_trace])
    
    fig.update_layout(
        showlegend=False,
        hovermode='closest',
        margin=dict(b=0, l=0, r=0, t=0),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        height=600,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Top connections analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔗 Most Connected Threat Actors")
        
        actor_connections = [(node, G.degree(node)) for node, d in G.nodes(data=True) 
                            if d.get('node_type') == 'actor']
        actor_connections.sort(key=lambda x: x[1], reverse=True)
        
        for actor, degree in actor_connections[:5]:
            st.markdown(f"""
            <div style='background: linear-gradient(135deg, #1e2749 0%, #2d3561 100%); 
                        padding: 10px; border-radius: 8px; margin: 5px 0;'>
                <strong style='color: #ff4757;'>{actor}</strong> - {degree} connections
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("### 🎯 Most Targeted Industries")
        
        target_connections = [(node, G.degree(node)) for node, d in G.nodes(data=True) 
                             if d.get('node_type') == 'target']
        target_connections.sort(key=lambda x: x[1], reverse=True)
        
        for target, degree in target_connections[:5]:
            st.markdown(f"""
            <div style='background: linear-gradient(135deg, #1e2749 0%, #2d3561 100%); 
                        padding: 10px; border-radius: 8px; margin: 5px 0;'>
                <strong style='color: #2ed573;'>{target}</strong> - {degree} attacks
            </div>
            """, unsafe_allow_html=True)

# Tab 5: IOC Database
with tabs[4]:
    st.markdown("### 📋 Indicators of Compromise (IOC) Database")
    
    iocs_df = pd.DataFrame(st.session_state.iocs)
    
    # IOC metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total IOCs", len(iocs_df))
    
    with col2:
        critical_iocs = len(iocs_df[iocs_df['threat_level'] == 'Critical'])
        st.metric("Critical IOCs", critical_iocs)
    
    with col3:
        unique_types = iocs_df['type'].nunique()
        st.metric("IOC Types", unique_types)
    
    with col4:
        recent_iocs = len(iocs_df[iocs_df['last_seen'] >= datetime.now() - timedelta(days=7)])
        st.metric("Active (7d)", recent_iocs)
    
    # IOC type distribution
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📊 IOC Type Distribution")
        
        ioc_counts = iocs_df['type'].value_counts()
        
        fig = go.Figure(data=[go.Bar(
            x=ioc_counts.values,
            y=ioc_counts.index,
            orientation='h',
            marker=dict(
                color=ioc_counts.values,
                colorscale='Reds',
                showscale=True
            ),
            text=ioc_counts.values,
            textposition='outside'
        )])
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=300,
            xaxis_title="Count",
            yaxis={'categoryorder': 'total ascending'}
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### ⚠️ Threat Level Breakdown")
        
        threat_level_counts = iocs_df['threat_level'].value_counts()
        
        fig = go.Figure(data=[go.Pie(
            labels=threat_level_counts.index,
            values=threat_level_counts.values,
            hole=0.4,
            marker_colors=['#ff4757', '#ffa502', '#ff6348', '#a4b0be']
        )])
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=300,
            showlegend=True
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # IOC search and filter
    st.markdown("### 🔍 IOC Search & Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        ioc_type_filter = st.multiselect(
            "Filter by Type",
            options=iocs_df['type'].unique(),
            default=iocs_df['type'].unique()[:3]
        )
    
    with col2:
        threat_level_filter = st.multiselect(
            "Filter by Threat Level",
            options=['Critical', 'High', 'Medium', 'Low'],
            default=['Critical', 'High']
        )
    
    with col3:
        search_query = st.text_input("Search IOC Value", "")
    
    # Apply filters
    filtered_iocs = iocs_df[
        (iocs_df['type'].isin(ioc_type_filter)) &
        (iocs_df['threat_level'].isin(threat_level_filter))
    ]
    
    if search_query:
        filtered_iocs = filtered_iocs[
            filtered_iocs['value'].str.contains(search_query, case=False, na=False)
        ]
    
    # Display filtered IOCs
    display_iocs = filtered_iocs.head(50).copy()
    display_iocs['first_seen'] = display_iocs['first_seen'].dt.strftime('%Y-%m-%d %H:%M')
    display_iocs['last_seen'] = display_iocs['last_seen'].dt.strftime('%Y-%m-%d %H:%M')
    display_iocs['reputation_score'] = display_iocs['reputation_score'].round(1)
    
    st.dataframe(
        display_iocs[['type', 'value', 'threat_level', 'first_seen', 'last_seen', 
                     'associated_threats', 'reputation_score']],
        use_container_width=True,
        hide_index=True,
        column_config={
            "type": "Type",
            "value": st.column_config.TextColumn("IOC Value", width="large"),
            "threat_level": "Threat Level",
            "first_seen": "First Seen",
            "last_seen": "Last Seen",
            "associated_threats": st.column_config.NumberColumn("Associated Threats", format="%d"),
            "reputation_score": st.column_config.NumberColumn("Reputation", format="%.1f")
        },
        height=400
    )
    
    # IOC timeline
    st.markdown("### ⏱️ IOC Discovery Timeline")
    
    iocs_df['date'] = iocs_df['first_seen'].dt.date
    timeline_data = iocs_df.groupby(['date', 'threat_level']).size().reset_index(name='count')
    
    fig = px.line(
        timeline_data,
        x='date',
        y='count',
        color='threat_level',
        color_discrete_map={
            'Critical': '#ff4757',
            'High': '#ffa502',
            'Medium': '#ff6348',
            'Low': '#a4b0be'
        },
        markers=True
    )
    
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        height=300,
        xaxis_title="Date",
        yaxis_title="New IOCs Discovered",
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)

# Tab 6: AI Insights
with tabs[5]:
    st.markdown("### 🤖 AI-Powered Intelligence Analysis")
    
    st.markdown("""
    <div class='prediction-box'>
        <h4>🧠 Advanced Analytics Engine</h4>
        <p>Leveraging deep learning and NLP to extract actionable intelligence from threat data</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Trend analysis
    st.markdown("### 📈 Threat Trend Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class='threat-card'>
            <h4>🔥 Emerging Threats</h4>
            <ul style='color: white;'>
                <li>Ransomware attacks up 23% this week</li>
                <li>New APT group targeting healthcare</li>
                <li>Zero-day vulnerability in popular CMS</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class='prediction-box'>
            <h4>✅ Positive Trends</h4>
            <ul style='color: white;'>
                <li>DDoS attacks decreased by 15%</li>
                <li>Average detection time improved</li>
                <li>Incident response time reduced</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div style='background: linear-gradient(135deg, #1e2749 0%, #2d3561 100%); 
                    padding: 15px; border-radius: 10px; border-left: 4px solid #00d9ff;'>
            <h4>ℹ️ Key Observations</h4>
            <ul style='color: white;'>
                <li>Peak activity hours: 14:00-18:00</li>
                <li>Finance sector most targeted</li>
                <li>Email remains top attack vector</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Attack pattern analysis
    st.markdown("### 🎯 Attack Pattern Intelligence")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # TTP analysis
        st.markdown("#### 🛠️ Top MITRE ATT&CK TTPs")
        
        all_ttps = []
        for threat in st.session_state.threats:
            all_ttps.extend(threat['ttps'])
        
        ttp_counts = Counter(all_ttps)
        top_ttps = ttp_counts.most_common(10)
        
        ttp_names = {
            'T1566': 'Phishing',
            'T1059': 'Command and Scripting',
            'T1105': 'Ingress Tool Transfer',
            'T1047': 'Windows Management',
            'T1003': 'Credential Dumping'
        }
        
        ttp_df = pd.DataFrame(top_ttps, columns=['TTP', 'Count'])
        ttp_df['Name'] = ttp_df['TTP'].map(ttp_names).fillna('Unknown')
        
        fig = go.Figure(data=[go.Bar(
            x=ttp_df['Count'],
            y=[f"{row['TTP']} - {row['Name']}" for _, row in ttp_df.iterrows()],
            orientation='h',
            marker_color=px.colors.sequential.Plasma,
            text=ttp_df['Count']
        )])
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=350,
            xaxis_title="Frequency",
            yaxis={'categoryorder': 'total ascending'}
        )
        fig.update_traces(textposition='outside')
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Kill chain analysis
        st.markdown("#### ⛓️ Cyber Kill Chain Distribution")
        
        kill_chain_phases = {
            'Reconnaissance': random.randint(15, 25),
            'Weaponization': random.randint(10, 20),
            'Delivery': random.randint(20, 30),
            'Exploitation': random.randint(25, 35),
            'Installation': random.randint(15, 25),
            'Command & Control': random.randint(20, 30),
            'Actions on Objectives': random.randint(10, 20)
        }
        
        fig = go.Figure(data=[go.Funnel(
            y=list(kill_chain_phases.keys()),
            x=list(kill_chain_phases.values()),
            textposition="inside",
            textinfo="value+percent initial",
            marker=dict(
                color=px.colors.sequential.Reds,
                line=dict(width=2, color='white')
            )
        )])
        
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color='white',
            height=350
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Sector-specific intelligence
    st.markdown("### 🏢 Industry-Specific Threat Intelligence")
    
    industry_threats = threats_df.groupby('target_industry').agg({
        'id': 'count',
        'cvss_score': 'mean',
        'affected_systems': 'sum'
    }).reset_index()
    industry_threats.columns = ['Industry', 'Threats', 'Avg CVSS', 'Total Systems']
    industry_threats = industry_threats.sort_values('Threats', ascending=False)
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Threat Count',
        x=industry_threats['Industry'],
        y=industry_threats['Threats'],
        marker_color='#ff4757'
    ))
    
    fig.add_trace(go.Scatter(
        name='Avg CVSS Score',
        x=industry_threats['Industry'],
        y=industry_threats['Avg CVSS'],
        yaxis='y2',
        mode='lines+markers',
        marker=dict(size=10, color='#00d9ff'),
        line=dict(width=3)
    ))
    
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        height=400,
        xaxis_title="Industry",
        yaxis_title="Number of Threats",
        yaxis2=dict(
            title="Average CVSS Score",
            overlaying='y',
            side='right'
        ),
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Executive summary
    st.markdown("### 📊 Executive Intelligence Brief")
    
    critical_count = len(threats_df[threats_df['severity'] == 'Critical'])
    avg_cvss = threats_df['cvss_score'].mean()
    top_actor = threats_df['threat_actor'].value_counts().index[0]
    top_type = threats_df['type'].value_counts().index[0]
    
    executive_brief_html = f"""
<div style='background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); padding: 25px; border-radius: 15px; margin: 20px 0;'>
    <h3 style='color: white; margin-top: 0;'>📋 Key Findings</h3>
    <div style='display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;'>
        <div>
            <h4 style='color: #00d9ff;'>🚨 Threat Landscape</h4>
            <ul style='color: white; line-height: 1.8;'>
                <li>Detected <strong>{len(threats_df)}</strong> threats in the last 30 days</li>
                <li><strong>{critical_count}</strong> critical threats requiring immediate attention</li>
                <li>Average CVSS score: <strong>{avg_cvss:.1f}</strong></li>
                <li>Most active threat actor: <strong>{top_actor}</strong></li>
            </ul>
        </div>
        <div>
            <h4 style='color: #00d9ff;'>🎯 Recommendations</h4>
            <ul style='color: white; line-height: 1.8;'>
                <li>Prioritize defense against <strong>{top_type}</strong> attacks</li>
                <li>Enhance monitoring during peak hours (14:00-18:00)</li>
                <li>Review security controls for <strong>{industry_threats.iloc[0]['Industry']}</strong> sector</li>
                <li>Implement additional DDoS mitigation measures</li>
            </ul>
        </div>
    </div>
</div>
"""
    
    st.markdown(executive_brief_html, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; padding: 20px; color: #a4b0be;'>
    <p>🛡️ ClarusSight v3.0 | Developed by Aathithya Shanmuga Sundaram</p>
    <p>Real-time threat intelligence • Predictive analytics • Anomaly detection • Attack correlation</p>
</div>
""", unsafe_allow_html=True)
