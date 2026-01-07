# ClarusSight CTI Dashboard
[![Python 3.6+](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/)
[![Seven Dependencies](https://img.shields.io/badge/Dependencies-5-green.svg)](https://www.python.org/)
[![Cybersecurity Lab](https://img.shields.io/badge/%23MakeEveryoneCyberSafe-orange.svg)](https://github.com/Aathithya-Shanmuga-Sundaram)

### 🌟 Project Overview

This is a cutting-edge Cyber Threat Intelligence (CTI) Framework that leverages Machine Learning, Advanced Analytics, and Interactive Visualizations to provide real-time threat intelligence, predictive forecasting, and anomaly detection capabilities.

### 🚀 Unique Features That Make This Project Stand Out

#### 1. **AI-Powered Threat Prediction** 🔮
- **24-Hour Threat Forecasting**: Uses ensemble ML models (Random Forest + time series analysis) to predict future threats
- **Confidence Intervals**: Provides uncertainty quantification for predictions
- **Severity Distribution Forecasting**: Predicts not just threat counts but severity breakdown
- **Actionable Recommendations**: AI generates specific, prioritized security recommendations based on predictions

#### 2. **Advanced Anomaly Detection** 🕵️
- **Unsupervised Learning**: Combines Isolation Forest and DBSCAN clustering
- **Behavioral Analysis**: Detects unusual patterns in attack behaviors
- **Anomaly Scoring**: Quantifies how unusual each threat is
- **Real-time Alerts**: Immediate flagging of zero-day indicators and novel attack patterns

#### 3. **Interactive Attack Correlation Graph** 🌐
- **Network Visualization**: Shows relationships between threat actors, attack types, and targets
- **Graph Analytics**: Calculates network density and connection metrics
- **Pattern Recognition**: Identifies coordinated attacks and actor patterns
- **Dynamic Layout**: Spring-force algorithm for optimal visualization

#### 4. **Comprehensive IOC Database** 📋
- **Multi-Type IOCs**: IP addresses, domains, file hashes, URLs, emails, registry keys
- **Reputation Scoring**: Each IOC has a dynamic reputation score
- **Timeline Tracking**: First seen / last seen timestamps
- **Associated Threat Linking**: Shows which threats are connected to each IOC

#### 5. **MITRE ATT&CK Integration** 🛠️
- **TTP Mapping**: All threats mapped to MITRE ATT&CK tactics, techniques, and procedures
- **Kill Chain Analysis**: Visualization of where threats fall in the cyber kill chain
- **Pattern Detection**: Identifies most common attack techniques

#### 6. **Industry-Specific Intelligence** 🏢
- **Sector Targeting Analysis**: Shows which industries are most at risk
- **Custom Risk Scoring**: Calculates organization-specific risk scores
- **Comparative Analysis**: Benchmarking against industry averages

#### 7. **Executive Intelligence Brief** 📊
- **Auto-Generated Summaries**: AI creates executive-level threat summaries
- **Key Findings**: Highlights most critical information
- **Strategic Recommendations**: Actionable insights for decision-makers

#### 8. **Modern, Intuitive UI** 🎨
- **Dark Themed Dashboard**: Professional, cyber-security aesthetic
- **Interactive Visualizations**: All charts are interactive with Plotly
- **Real-time Updates**: Live data refresh capabilities
- **Responsive Design**: Works on desktop and tablet devices

#### 9. **Advanced Analytics** 📈
- **Time Series Analysis**: Trend detection over multiple time periods
- **Statistical Modeling**: CVSS score distribution analysis
- **Geographic Intelligence**: Source country threat mapping
- **Correlation Analysis**: Multi-dimensional threat correlation

#### 10. **Unique Detection Capabilities** 🎯
- **Rapid Propagation Detection**: Identifies fast-spreading threats
- **Coordinated Attack Detection**: Spots multi-vector campaigns
- **Zero-Day Indicators**: Flags potential unknown vulnerabilities
- **Behavioral Baseline**: Learns normal patterns to detect deviations

### 📋 System Requirements

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- Modern web browser (Chrome, Firefox, Safari, Edge)

### 🔧 Installation & Setup

1. **Clone or download the project files**

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Run the application**:
```bash
streamlit run app.py
```

4. **Access the dashboard**:
   - Open your browser and go to `http://localhost:8501`

### 📊 Dashboard Modules

#### 1. Threat Dashboard
- Real-time threat metrics
- Threat timeline visualization
- Geographic distribution maps
- Top threat actors analysis
- Recent critical threats table

#### 2. Predictive Analytics
- 24-hour threat forecasts
- Confidence intervals
- Risk timeline heatmap
- Severity distribution predictions
- AI-generated recommendations

#### 3. Anomaly Detection
- Behavioral anomaly identification
- Anomaly scoring system
- Detailed anomaly analysis
- Pattern deviation alerts

#### 4. Attack Graph
- Network correlation visualization
- Threat actor connection analysis
- Target industry patterns
- Graph metrics and statistics

#### 5. IOC Database
- Comprehensive IOC tracking
- Multi-type IOC support
- Search and filter capabilities
- IOC discovery timeline
- Reputation scoring

#### 6. AI Insights
- Threat trend analysis
- MITRE ATT&CK TTP mapping
- Cyber kill chain distribution
- Industry-specific intelligence
- Executive intelligence brief

### 🎯 Key Features Breakdown

#### Machine Learning Models
- **Isolation Forest**: Anomaly detection with 0.1 contamination factor
- **Random Forest Classifier**: 100 estimators for threat prediction
- **DBSCAN**: Density-based clustering for pattern recognition
- **PCA**: Dimensionality reduction for feature engineering

#### Data Generation
- Realistic threat scenarios across 10 threat types
- 9 major threat actor groups
- 8 industry sectors
- Multiple attack vectors and TTPs
- Geographic distribution across 9 countries

#### Visualization Types
- Line charts (time series)
- Area charts (stacked trends)
- Bar charts (comparisons)
- Pie charts (distributions)
- Heatmaps (risk timelines)
- Network graphs (correlations)
- Gauge charts (metrics)
- Funnel charts (kill chain)
- Scatter plots (anomalies)

### 🔬 Technical Highlights

#### Advanced Algorithms
- Spring-force layout for graph visualization
- Time series decomposition for trend analysis
- Statistical anomaly scoring
- Risk calculation with multi-factor weighting
- Confidence interval computation

#### Data Processing
- Real-time data aggregation
- Multi-dimensional filtering
- Dynamic threshold adjustment
- Automated pattern recognition
- Correlation matrix computation

#### User Experience
- Instant data refresh
- Interactive filtering
- Responsive metrics
- Context-aware insights
- Expandable detail views

### 📈 Use Cases

1. **Security Operations Center (SOC)**
   - Real-time threat monitoring
   - Incident prioritization
   - Resource allocation

2. **Threat Intelligence Teams**
   - Pattern analysis
   - Actor profiling
   - Campaign tracking

3. **Executive Leadership**
   - Risk assessment
   - Strategic planning
   - Budget justification

4. **Incident Response**
   - IOC tracking
   - Attack timeline reconstruction
   - Attribution analysis

5. **Security Researchers**
   - Trend identification
   - Predictive modeling
   - Anomaly investigation

### 🎓 Learning Outcomes

This project demonstrates:
- Machine Learning for cybersecurity
- Advanced data visualization
- Real-time analytics systems
- Interactive dashboard development
- Graph theory applications
- Statistical modeling
- Time series forecasting
- Anomaly detection techniques
- Network analysis
- Security intelligence concepts

### 🔮 Future Enhancements

Potential additions:
- Integration with SIEM systems
- Automated threat hunting
- ML model retraining pipeline
- Threat intel feeds integration
- Multi-language support
- Export to PDF reports
- Email alerting system
- REST API endpoints
- Docker containerization
- Cloud deployment ready

### 📝 Code Structure

```
app.py
├── AdvancedThreatIntelligence (Class)
│   ├── generate_realistic_threats()
│   ├── generate_ioc_data()
│   ├── predict_threat_trends()
│   ├── detect_anomalies()
│   ├── build_attack_graph()
│   └── calculate_risk_score()
├── UI Components
│   ├── Header & Sidebar
│   ├── Tab 1: Threat Dashboard
│   ├── Tab 2: Predictive Analytics
│   ├── Tab 3: Anomaly Detection
│   ├── Tab 4: Attack Graph
│   ├── Tab 5: IOC Database
│   └── Tab 6: AI Insights
└── Styling & Configuration
```

### 🎨 Design Philosophy

- **Dark Theme**: Reduces eye strain during long monitoring sessions
- **Color Coding**: Red for threats, green for positive trends, blue for information
- **Progressive Disclosure**: Details available on demand
- **Minimal Cognitive Load**: Clear hierarchy and organization
- **Professional Aesthetic**: Enterprise-ready appearance

### ⚡ Performance Optimizations

- Caching for repeated computations
- Efficient data structures
- Optimized chart rendering
- Lazy loading for large datasets
- Memory-efficient algorithms

### 🛡️ Security Considerations

This is a demonstration system using simulated data. For production use:
- Implement proper authentication
- Add role-based access control
- Enable audit logging
- Encrypt sensitive data
- Use secure API connections
- Implement rate limiting

### 🤝 Contributing

This project is designed as a showcase piece. Areas for contribution:
- Additional ML models
- New visualization types
- Performance improvements
- Documentation enhancements
- Test coverage
- Feature additions

### 🙏 Acknowledgments

- MITRE ATT&CK Framework for TTP taxonomy
- Cyber Kill Chain model by Lockheed Martin
- Open-source community for amazing libraries

### 📞 Support

For questions or issues:
- Review the code comments
- Check the inline documentation
- Examine the example data generation

---

**Built with ❤️ using Python, Streamlit, and Advanced ML**
