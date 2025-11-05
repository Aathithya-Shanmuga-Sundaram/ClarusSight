import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from prophet import Prophet
from sklearn.ensemble import IsolationForest

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
    </style>
    <h1 class="title">Cyber Threat Intelligence Dashboard</h1>
    """,
    unsafe_allow_html=True
)

# ----------------- Demo Data Generator -----------------
def generate_mock_threat_data(num_entries=365):
    # Random seed removed for variability
    dates = pd.date_range(start="2024-01-01", periods=num_entries, freq='D')

    # Introduce random daily variations (simulating more realistic threat intensity)
    daily_counts = np.random.poisson(lam=5, size=num_entries)
    descriptions, severities, latitudes, longitudes, types = [], [], [], [], []

    for i, count in enumerate(daily_counts):
        for j in range(count):
            descriptions.append(f"Threat {i}-{j}: Description of threat.")
            severities.append(np.random.choice(['Low', 'Medium', 'High', 'Critical'], p=[0.4, 0.3, 0.2, 0.1]))
            latitudes.append(np.random.uniform(-90, 90))
            longitudes.append(np.random.uniform(-180, 180))
            types.append(np.random.choice(['Malware', 'Phishing', 'Ransomware', 'DDoS'], p=[0.4, 0.3, 0.2, 0.1]))

    df = pd.DataFrame({
        'publishedDate': np.repeat(dates, daily_counts),
        'description': descriptions,
        'severity': severities,
        'latitude': latitudes,
        'longitude': longitudes,
        'type': types
    })
    return df


# ----------------- Upload or Demo Data -----------------
uploaded_file = st.file_uploader("Upload your threat data (CSV format)", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("✅ Data loaded successfully from your file!")
else:
    st.info("ℹ️ No file uploaded. Using demo threat data instead.")
    df = generate_mock_threat_data()

# Normalize columns
df.columns = df.columns.str.strip().str.lower()
rename_map = {
    'date': 'publisheddate',
    'desc': 'description',
    'severity_level': 'severity',
    'lat': 'latitude',
    'lon': 'longitude',
    'threat_type': 'type'
}
df = df.rename(columns=rename_map)

# ----------------- Display Threat Data -----------------
st.subheader("Recent Threats")
st.dataframe(df)

# ----------------- Threats Over Time -----------------
if not df.empty:
    df['date'] = pd.to_datetime(df['publisheddate'])
    threats_over_time = df.groupby(df['date'].dt.to_period('M')).size().reset_index(name='count')
    threats_over_time['date'] = threats_over_time['date'].dt.strftime('%Y-%m')

    fig = px.line(threats_over_time, x='date', y='count',
                  title='Threats Over Time',
                  color_discrete_sequence=['#00bcd4'])
    st.plotly_chart(fig)

# ----------------- Search Function -----------------
search_term = st.text_input("🔍 Search for a specific threat:")
if search_term:
    filtered_data = df[df['description'].str.contains(search_term, case=False, na=False)]
    st.dataframe(filtered_data)

# ----------------- Geolocation Mapping -----------------
if 'latitude' in df.columns and 'longitude' in df.columns:
    st.subheader("🌍 Threats by Location")
    map_fig = px.scatter_geo(
        df,
        lat='latitude',
        lon='longitude',
        text='description',
        title='Threats by Geolocation',
        hover_name='description',
        color='severity',
        size_max=15
    )
    st.plotly_chart(map_fig)
else:
    st.warning("Geolocation data is not available.")

# ----------------- Alerts Section -----------------
def generate_mock_alerts(num_alerts=5):
    alerts = [
        {"date": f"2024-11-0{i+1}", "description": f"Critical vulnerability alert for Software {i+1}"}
        for i in range(num_alerts)
    ]
    return pd.DataFrame(alerts)

alerts_df = generate_mock_alerts()
if not alerts_df.empty:
    st.subheader("🚨 Recent Alerts")
    st.dataframe(alerts_df)

# ----------------- Threat Classification -----------------
if 'severity' in df.columns:
    severity_counts = df['severity'].value_counts()
    st.subheader("📊 Threat Classification by Severity")
    st.bar_chart(severity_counts)
else:
    st.warning("Severity data is not available.")

# ----------------- PROPHET -----------------
st.header("📈 Threat Trend Prediction")

try:
    # Build daily counts (ensure datetime)
    daily_data = df.copy()
    daily_data['publisheddate'] = pd.to_datetime(daily_data['publisheddate'], errors='coerce')
    daily_data = daily_data.dropna(subset=['publisheddate'])
    daily_counts = daily_data.groupby(daily_data['publisheddate'].dt.date).size().reset_index(name='Count')

    # Prepare for Prophet: exact column names
    forecast_df = daily_counts.rename(columns={'publisheddate': 'ds', 'Count': 'y'})
    # If rename above didn't create 'ds' because the date column name is different, set explicitly:
    if 'ds' not in forecast_df.columns:
        forecast_df.columns = ['ds', 'y']

    # ensure ds is datetime
    forecast_df['ds'] = pd.to_datetime(forecast_df['ds'])

    # If data is too flat, add tiny jitter so Prophet can model seasonality/trend
    if forecast_df['y'].nunique() <= 2 and len(forecast_df) > 5:
        forecast_df['y'] = forecast_df['y'] + np.random.randint(0, 3, size=len(forecast_df))

    # Safety: need at least 8-10 points for a meaningful forecast
    if len(forecast_df) < 8:
        st.warning("Not enough data points for forecasting (need >= 8 daily aggregates).")
    else:
        model = Prophet()
        model.fit(forecast_df)

        future = model.make_future_dataframe(periods=15)
        forecast = model.predict(future)

        # Plot forecast
        fig_pred = px.line(forecast, x='ds', y='yhat', title='Predicted Threat Trends (Next 15 Days)')
        fig_pred.add_scatter(x=forecast_df['ds'], y=forecast_df['y'], mode='lines', name='Actual')
        st.plotly_chart(fig_pred)

        # show a quick head of forecast for debugging/inspection
        st.write("Forecast sample:")
        st.dataframe(forecast[['ds','yhat','yhat_lower','yhat_upper']].tail(10))

        st.info("📊 This prediction helps identify potential surge periods in cyber threats.")
except Exception as e:
    st.error(f"Prediction module error: {e}")


# ----------------- ISOLATION FOREST -----------------

st.header("🚨 Anomaly Detection in Threat Data")

try:
    # Use the same aggregated daily_counts as used above
    # Recreate/ensure daily_counts exists
    daily_data = df.copy()
    daily_data['publisheddate'] = pd.to_datetime(daily_data['publisheddate'], errors='coerce')
    daily_data = daily_data.dropna(subset=['publisheddate'])
    daily_counts = daily_data.groupby(daily_data['publisheddate'].dt.date).size().reset_index(name='Count')

    # Normalize column names to use 'date' and 'Count'
    anomaly_data = daily_counts.rename(columns={daily_counts.columns[0]: 'date'})

    # convert date to datetime for plotting
    anomaly_data['date'] = pd.to_datetime(anomaly_data['date'])

    # Anomaly detection requires numeric features; we'll use 'Count'
    if len(anomaly_data) < 5:
        st.warning("Not enough aggregated daily points for anomaly detection.")
    else:
        clf = IsolationForest(contamination=0.05, random_state=42)
        anomaly_data['Anomaly'] = clf.fit_predict(anomaly_data[['Count']])

        # Map labels for plotting
        anomaly_data['label'] = anomaly_data['Anomaly'].map({1: 'Normal', -1: 'Anomaly'})
        anomalies = anomaly_data[anomaly_data['Anomaly'] == -1]

        # Plot
        fig2 = px.scatter(
            anomaly_data, x='date', y='Count',
            color='label',
            title='Anomaly Detection in Threat Trends',
            color_discrete_map={'Normal': '#7fb3d5', 'Anomaly': '#ff4c4c'}
        )
        if not anomalies.empty:
            fig2.add_scatter(x=anomalies['date'], y=anomalies['Count'],
                             mode='markers', marker=dict(size=10, color='red'), name='Anomalies')
        st.plotly_chart(fig2)

        # show anomalies table for inspection
        if not anomalies.empty:
            st.subheader("Detected Anomalies")
            st.dataframe(anomalies.sort_values(by='date', ascending=False).reset_index(drop=True))
        else:
            st.info("No anomalies detected in aggregated daily counts.")

except Exception as e:
    st.error(f"Anomaly detection module error: {e}")

# ----------------- Threat Type Filter -----------------
threat_types = df['type'].unique().tolist() if 'type' in df.columns else []
selected_type = st.selectbox("Select Threat Type", options=['All'] + threat_types)

if selected_type != 'All':
    filtered_df = df[df['type'] == selected_type]
else:
    filtered_df = df

st.dataframe(filtered_df)

# ----------------- Export Data -----------------
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

csv = convert_df_to_csv(filtered_df)
st.download_button(
    label="💾 Download filtered data as CSV",
    data=csv,
    file_name='threat_data.csv',
    mime='text/csv',
)
