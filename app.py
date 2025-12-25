import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from prophet import Prophet
from sklearn.ensemble import IsolationForest
from datetime import timedelta, date

# ----------------- CRITICAL FIX: Set page config first -----------------
st.set_page_config(layout="wide", page_title="Cyber Threat Intelligence Dashboard", page_icon="🛡️")

# ----------------- UI Styling -----------------
st.markdown(
    """
    <style>
    .title {
        font-size: 36px;
        background: linear-gradient(90deg, #00bcd4, #007acc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: bold;
        text-align: center;
    }
    .metric-card {
        padding: 15px;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 20px;
    }
    .metric-card h3 {
        margin: 0;
        font-size: 1.2em;
        opacity: 0.8;
    }
    .metric-card p {
        font-size: 2.5em;
        font-weight: bold;
        margin: 5px 0 0 0;
    }
    .bg-red { background-color: #ff4c4c; } /* Critical */
    .bg-orange { background-color: #ff9900; } /* High */
    .bg-yellow { background-color: #ffcc00; color: #333 !important; } /* Medium */
    .bg-green { background-color: #008080; } /* Low */
    </style>
    <h1 class="title">🛡️ Cyber Threat Intelligence Dashboard</h1>
    ---
    """,
    unsafe_allow_html=True
)

# ----------------- Demo Data Generator (NO CACHING) -----------------
def generate_mock_threat_data(num_entries=365 * 3):
    """Generates mock threat data with enhanced randomness and volume.""" 
    
    dates = pd.date_range(start="2022-11-01", periods=num_entries, freq='D')
    
    base_lam = 5
    daily_trend = np.sin(np.linspace(0, 2 * np.pi * 3, num_entries)) * 2 + np.random.normal(0, 1, num_entries)
    daily_counts = np.maximum(1, np.round(base_lam + daily_trend)).astype(int)

    descriptions, severities, latitudes, longitudes, types, countries = [], [], [], [], [], []

    # Mock Country/Lat/Lon for better geo-visualization
    geo_data = {
        'USA': (37.0902, -95.7129), 'CHN': (35.8617, 104.1954),
        'RUS': (61.5240, 105.3188), 'DEU': (51.1657, 10.4515),
        'IND': (20.5937, 78.9629), 'BRA': (-14.235, -51.9253)
    }
    country_list = list(geo_data.keys())
    country_weights = [0.25, 0.2, 0.15, 0.1, 0.2, 0.1]

    for i, count in enumerate(daily_counts):
        for j in range(count):
            countries.append(np.random.choice(country_list, p=country_weights))
            lat, lon = geo_data[countries[-1]]
            latitudes.append(lat + np.random.uniform(-5, 5))
            longitudes.append(lon + np.random.uniform(-5, 5))
            descriptions.append(f"Threat {dates[i].date()} - {j}: Description of threat.")
            severities.append(np.random.choice(['Low', 'Medium', 'High', 'Critical'], p=[0.4, 0.3, 0.2, 0.1]))
            types.append(np.random.choice(['Malware', 'Phishing', 'Ransomware', 'DDoS', 'Zero-Day'], p=[0.3, 0.2, 0.2, 0.15, 0.15]))

    df = pd.DataFrame({
        'publisheddate': np.repeat(dates, daily_counts),
        'description': descriptions,
        'severity': severities,
        'latitude': latitudes,
        'longitude': longitudes,
        'type': types,
        'country': countries
    })
    return df

# ----------------- Load Data -----------------
uploaded_file = st.sidebar.file_uploader("📂 Upload your threat data (CSV format)", type=["csv"])

if uploaded_file is not None:
    df_raw = pd.read_csv(uploaded_file)
    st.sidebar.success("✅ Data loaded successfully from your file!")
else:
    df_raw = generate_mock_threat_data()
    st.sidebar.info("ℹ️ No file uploaded. Using **newly generated** 3 years of demo threat data.")

# Normalize columns
df_raw.columns = df_raw.columns.str.strip().str.lower()
rename_map = {
    'date': 'publisheddate', 'desc': 'description',
    'severity_level': 'severity', 'lat': 'latitude',
    'lon': 'longitude', 'threat_type': 'type'
}
df_raw = df_raw.rename(columns=rename_map)

df_raw['publisheddate'] = pd.to_datetime(df_raw['publisheddate'], utc=True, errors='coerce').dt.tz_localize(None)
df_raw = df_raw.dropna(subset=['publisheddate'])
df_raw['date'] = df_raw['publisheddate'].dt.normalize() # Date without time


if len(df_raw) > 200000:
    st.warning(f"Large dataset detected ({len(df_raw)} rows). Showing a 200k-sample for performance. Consider DB-backed approach for production.")
    df_raw = df_raw.sample(200000, random_state=42).copy()


# ----------------- Filtering (Enhanced UX) -----------------
st.sidebar.header("⚙️ Dashboard Filters")

# 1. Date Range Filter
min_date = df_raw['publisheddate'].min().date()
max_date = df_raw['publisheddate'].max().date()

date_range = st.sidebar.date_input(
    "Select Date Range",
    [max_date - timedelta(days=90), max_date]
)

try:
    start_date, end_date = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
    if start_date > end_date:
        start_date, end_date = end_date, start_date # Swap if out of order
except Exception:
    start_date, end_date = df_raw['publisheddate'].min(), df_raw['publisheddate'].max()
    st.sidebar.warning("Using full data range — please select valid start and end dates.")

df_filtered = df_raw[(df_raw['publisheddate'] >= start_date) & (df_raw['publisheddate'] <= end_date)].copy()


# 2. Severity Filter
severity_options = df_raw['severity'].unique().tolist()
selected_severity = st.sidebar.multiselect(
    "Filter by Severity",
    options=severity_options,
    default=severity_options
)

if selected_severity:
    df_filtered = df_filtered[df_filtered['severity'].isin(selected_severity)].copy()
elif not df_filtered.empty:
     st.warning("No data found for the selected severity levels.")

cont_val = st.sidebar.slider(
    "Anomaly Contamination (Expected fraction of anomalies)", 
    0.01, 0.2, 0.05, 0.01,
    help="Higher contamination values flag more points as anomalies."
)


# ----------------- Key Performance Indicators (KPIs) -----------------
st.subheader("💡 Key Threat Metrics")

total_threats = len(df_filtered)

days_in_period = (end_date - start_date).days
if days_in_period < 1: # Handle single day or invalid range
    days_in_period = 1
    avg_daily_threats = total_threats
else:
    avg_daily_threats = total_threats / days_in_period

if not df_filtered.empty:
    critical_threats = len(df_filtered[df_filtered['severity'] == 'Critical'])
    unique_types = df_filtered['type'].nunique()

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f'<div class="metric-card bg-red"><h3>Total Threats (Filtered)</h3><p>{total_threats}</p></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-card bg-orange"><h3>Critical Alerts</h3><p>{critical_threats}</p></div>', unsafe_allow_html=True)
    with col3:
        st.markdown(f'<div class="metric-card bg-green"><h3>Unique Threat Types</h3><p>{unique_types}</p></div>', unsafe_allow_html=True)
    with col4:
        st.markdown(f'<div class="metric-card bg-red"><h3>Avg. Threats per Day</h3><p>{avg_daily_threats:.1f}</p></div>', unsafe_allow_html=True)

    st.markdown("---")
else:
    st.warning("No data to display for the selected filters.")
    st.stop() # Stop execution if no data is available


# ----------------- Layout for Visuals -----------------
col_chart_1, col_chart_2 = st.columns(2)

# ----------------- Threat Classification by Severity (Pie Chart) -----------------
with col_chart_1:
    st.subheader("📊 Threat Distribution by Severity")
    severity_counts = df_filtered['severity'].value_counts().reset_index()
    severity_counts.columns = ['Severity', 'Count']
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    severity_colors = {'Critical': '#ff4c4c', 'High': '#ff9900', 'Medium': '#ffcc00', 'Low': '#00bcd4'}

    severity_counts['Severity'] = pd.Categorical(severity_counts['Severity'], categories=severity_order, ordered=True)
    severity_counts = severity_counts.sort_values('Severity')

    fig_pie = px.pie(
        severity_counts, values='Count', names='Severity',
        title='Threat Severity Breakdown',
        color='Severity',
        color_discrete_map=severity_colors,
        hole=0.3
    )
    fig_pie.update_traces(textposition='inside', textinfo='percent+label')
    st.plotly_chart(fig_pie, use_container_width=True)

# ----------------- Top Threat Types (Bar Chart) -----------------
with col_chart_2:
    st.subheader("📈 Top 5 Most Active Threat Types")
    type_counts = df_filtered['type'].value_counts().nlargest(5).reset_index()
    type_counts.columns = ['Threat Type', 'Count']
    
    fig_bar = px.bar(
        type_counts, x='Count', y='Threat Type',
        orientation='h',
        title='Count of Top Threat Categories',
        color_discrete_sequence=['#007acc']
    )
    fig_bar.update_layout(yaxis={'categoryorder':'total ascending'})
    st.plotly_chart(fig_bar, use_container_width=True)

st.markdown("---")

# ----------------- Threats Over Time -----------------
st.subheader("📅 Threats Over Time")

threats_over_time = df_filtered.groupby(df_filtered['publisheddate'].dt.to_period('D')).size().reset_index(name='count')
threats_over_time['publisheddate'] = threats_over_time['publisheddate'].dt.to_timestamp()

fig = px.line(threats_over_time, x='publisheddate', y='count',
              title='Daily Threat Volume Trend',
              color_discrete_sequence=['#00bcd4'])
st.plotly_chart(fig, use_container_width=True)

# ----------------- Geolocation Mapping -----------------
if 'latitude' in df_filtered.columns and 'longitude' in df_filtered.columns:
    st.subheader("🌍 Threats by Location")

    map_fig = px.scatter_geo(
        df_filtered,
        lat='latitude',
        lon='longitude',
        text='description',
        title='Threats by Geolocation (Filtered)',
        hover_name='description',
        color='severity',
        color_discrete_map=severity_colors,
        size_max=15,
        projection="natural earth"
    )
    st.plotly_chart(map_fig, use_container_width=True)

st.markdown("---")

# PROPHET MODULE + INTERPRETATION 
st.header("📈 Threat Trend Prediction (Prophet)")

# Prophet Prediction Period Widget
forecast_periods = st.slider(
    "Select Forecast Period (Days)",
    min_value=7, max_value=60, value=15, step=7
)

try:
    daily_counts = df_filtered.groupby(df_filtered['date']).size().reset_index(name='Count')
    
    if len(daily_counts) < 2:
        st.warning("⚠️ Need at least 2 days of data for Prophet forecasting in the selected range.")
    else:
        forecast_df = daily_counts.rename(columns={daily_counts.columns[0]: 'ds', 'Count': 'y'})
        forecast_df['ds'] = pd.to_datetime(forecast_df['ds'])


        weekly_seasonality_enabled = len(forecast_df) > 14
        
        with st.spinner(f'Training Prophet model... (Weekly Seasonality: {weekly_seasonality_enabled})'):
            model = Prophet(
                daily_seasonality=False, 
                weekly_seasonality=weekly_seasonality_enabled, 
                yearly_seasonality=False
            )
            model.fit(forecast_df)

        future = model.make_future_dataframe(periods=forecast_periods)
        forecast = model.predict(future)

        fig_pred = px.line(forecast, x='ds', y='yhat', title=f'Predicted Daily Threat Trends (Next {forecast_periods} Days)', color_discrete_sequence=['#007acc'])
        fig_pred.add_scatter(x=forecast_df['ds'], y=forecast_df['y'], mode='lines', name='Actual', line=dict(color='#00bcd4'))
        st.plotly_chart(fig_pred, use_container_width=True)

        # 🔍 Forecast Interpretation
        latest_yhat = forecast['yhat'].iloc[-1]
        previous_yhat = forecast['yhat'].iloc[len(forecast_df)-1]
        
        # Calculate percentage change from the last actual day's prediction to the end of the forecast
        pct_forecast_change = ((latest_yhat - previous_yhat) / previous_yhat) * 100 if previous_yhat != 0 else 0

        st.subheader("📊 Forecast Insight")
        if pct_forecast_change > 10:
            st.warning(f"⚠️ **Action Required:** Threat volume is expected to **increase significantly** by **{pct_forecast_change:.1f}%** over the next {forecast_periods} days. Review defenses.")
        elif pct_forecast_change < -10:
            st.success(f"✅ Threat levels are projected to **decline** by **{abs(pct_forecast_change):.1f}%** over the next {forecast_periods} days.")
        else:
            st.info(f"ℹ️ Threat activity is expected to remain relatively stable (change: {pct_forecast_change:.1f}%) over the next {forecast_periods} days.")

except Exception as e:
    st.error(f"Prediction module error: Could not train model. ({e})")

st.markdown("---")


# ANOMALY DETECTION (ISOLATION FOREST)

st.header("🚨 Anomaly Detection in Threat Data")

try:
    anomaly_data = df_filtered.groupby(df_filtered['date']).size().reset_index(name='Count')
    anomaly_data['date'] = pd.to_datetime(anomaly_data['date'])


    clf = IsolationForest(contamination=cont_val, random_state=42)
    anomaly_data['Anomaly'] = clf.fit_predict(anomaly_data[['Count']])
    anomalies = anomaly_data[anomaly_data['Anomaly'] == -1]
    
    # Get the raw number of anomaly points for the report
    num_anomalies = len(anomalies)

    fig2 = px.scatter(
        anomaly_data, x='date', y='Count',
        color=anomaly_data['Anomaly'].map({1: 'Normal', -1: 'Anomaly'}),
        title='Anomaly Detection in Threat Trends',
        color_discrete_map={'Normal': '#00bcd4', 'Anomaly': '#ff4c4c'}
    )
    if not anomalies.empty:
        fig2.add_scatter(x=anomalies['date'], y=anomalies['Count'],
                          mode='markers', marker=dict(size=10, color='red'), name='Anomalies')
    st.plotly_chart(fig2, use_container_width=True)

    # 🧩 Contextual summary
    if not anomalies.empty:
        spike_dates = anomalies.sort_values(by='Count', ascending=False)['date'].dt.strftime('%Y-%m-%d').tolist()
        st.warning(f"🚨 **Urgent Review:** Significant threat spikes detected on **{', '.join(spike_dates[:3])}** with unusually high volumes.")
        

        st.subheader("🔍 Anomaly Drilldown: Raw Events")
        for d in anomalies['date'].dt.date.unique()[:3]:
            st.markdown(f"**Top 20 Events on {d}:**")
            st.dataframe(
                df_filtered[df_filtered['date'] == pd.to_datetime(d)].sort_values(by='severity', ascending=False).head(20),
                use_container_width=True
            )
            
    else:
        st.info("✅ No anomalous threat activity detected in the selected time frame.")
except Exception as e:
    st.error(f"Anomaly detection module error: {e}")

st.markdown("---")


# 💾 Data Tables and Export + POLISH

st.header("🧾 Raw Data View and Export")

# ----------------- One-Line Report (POLISH) -----------------
today = date.today()
k_total = len(df_filtered)

report = f"""
CTI Quick Report ({today}):
Total threats in period: {k_total}
Period duration: {days_in_period} days
Avg. daily threats: {avg_daily_threats:.1f}
Anomalies detected: {num_anomalies}
Top threat type: {type_counts['Threat Type'].iloc[0] if not type_counts.empty else 'N/A'}
Forecast change (over next {forecast_periods} days): {pct_forecast_change:.1f}%
"""

st.download_button(
    label="⬇️ Download Quick Report TXT",
    data=report,
    file_name=f"cti_quick_report_{today}.txt",
    mime='text/plain',
    help="Generates a short text summary of the current filtered view."
)
# ----------------- Filtered Threat Data Display -----------------
st.subheader("Filtered Threat Data")
st.caption(f"Showing {len(df_filtered)} records.")

search_term = st.text_input("🔍 Search threat descriptions:", help="Search across the current filtered data.")
if search_term:
    search_filtered_data = df_filtered[df_filtered['description'].str.contains(search_term, case=False, na=False)]
    st.dataframe(search_filtered_data, use_container_width=True)
else:
    st.dataframe(df_filtered, use_container_width=True)

# ----------------- Export Data -----------------
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

csv = convert_df_to_csv(df_filtered)
st.download_button(
    label="💾 Download Full Filtered Data as CSV",
    data=csv,
    file_name='threat_data_filtered.csv',
    mime='text/csv',
    key='download_csv'
)

st.markdown("---")
st.markdown("<p style='text-align: center; color: gray;'>Developed by Aathithya Shanmuga Sundaram #MakeEveryoneCyberSafe</p>", unsafe_allow_html=True)
