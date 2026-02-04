from flask import Flask, render_template, request, jsonify
import pandas as pd
import plotly.express as px
import plotly.utils
import json

app = Flask(__name__)

# ==============================
# SIMULATED THREAT INTELLIGENCE
# ==============================
KNOWN_IOCS = {
    "45.67.89.1": "Cobalt Strike C2 Server",
    "malware.exe": "Emotet Loader",
    "bad-domain.com": "Phishing Landing Page",
    "192.168.1.100": "Test Malicious IP"
}

# ==============================
# LOAD DATA
# ==============================
def load_data():
    return pd.read_csv("data/threats.csv")

# ==============================
# HELPER: NORMALIZE SEVERITY
# ==============================
def normalize_severity(value):
    if isinstance(value, int):
        return value

    value = str(value).strip().lower()

    if value == "low":
        return 3
    elif value == "medium":
        return 6
    elif value == "high":
        return 9

    # fallback if something unexpected appears
    try:
        return int(value)
    except:
        return 1

# ==============================
# DASHBOARD ROUTE
# ==============================
@app.route("/")
def dashboard():
    df = load_data()

    total_attacks = len(df)
    unique_types = df["attack_type"].nunique()

    latest = df.iloc[-1]
    severity_score = normalize_severity(latest["severity"])

    if severity_score >= 8:
        current_risk = "HIGH"
    elif severity_score >= 5:
        current_risk = "MEDIUM"
    else:
        current_risk = "LOW"

    # Chart 1: Attacks by Type
    attack_counts = df["attack_type"].value_counts().reset_index()
    attack_counts.columns = ["attack_type", "count"]

    fig_attacks = px.bar(
        attack_counts,
        x="attack_type",
        y="count",
        title="Attacks by Type",
        template="plotly_dark",
        color="count",
        color_continuous_scale=["#3b0764", "#7e22ce", "#d946ef"] # Deep purple to Neon Pink
    )
    
    fig_attacks.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family="Inter, sans-serif", size=12, color="#e2e8f0"),
        title_font=dict(size=18, color="#f8fafc")
    )

    graph_attacks = json.dumps(fig_attacks, cls=plotly.utils.PlotlyJSONEncoder)

    # Chart 2: Global Attack Distribution
    country_counts = df["country"].value_counts().reset_index()
    country_counts.columns = ["country", "count"]

    fig_map = px.choropleth(
        country_counts,
        locations="country",
        locationmode="country names",
        color="count",
        title="Global Attack Distribution",
        color_continuous_scale="Purples", # Built-in dark friendly scale
        template="plotly_dark"
    )
    
    fig_map.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        geo=dict(
            bgcolor='rgba(0,0,0,0)',
            showocean=True,
            oceancolor="#131129",
            showlakes=True,
            lakecolor="#131129",
            showland=True,
            landcolor="#1e1b4b"
        ),
        font=dict(family="Inter, sans-serif", size=12, color="#e2e8f0"),
        title_font=dict(size=18, color="#f8fafc"),
        margin={"r":0,"t":40,"l":0,"b":0}
    )

    graph_map = json.dumps(fig_map, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template(
        "dashboard.html",
        total_attacks=total_attacks,
        unique_types=unique_types,
        current_risk=current_risk,
        graph_attacks=graph_attacks,
        graph_map=graph_map
    )

# ==============================
# IOC ANALYSIS ROUTE
# ==============================
# ==============================
# SIMULATED AI AUTOMATION ENGINE
# ==============================
import random

def auto_classify_threat(ioc):
    """
    Simulates sending the IOC to a BERT/Transformer model for text classification.
    Returns: Malware, Phishing, Botnet, or DDoS
    """
    # Simulate meaningful classification based on basic rules or random weighted choice
    if "malware" in ioc or ".exe" in ioc:
        return "Malware"
    if "phishing" in ioc or "login" in ioc:
        return "Phishing"
    if "ddos" in ioc:
        return "DDoS"
    
    # Random fallback for simulation
    types = ["Malware", "Phishing", "Botnet", "DDoS"]
    return random.choice(types)

def auto_calculate_risk_factors():
    """
    Simulates gathering context: Volume, Severity, Trends.
    Returns a dict of factors.
    """
    return {
        "volume": random.randint(100, 10000), # "Volume of attacks"
        "severity": random.choice(["Critical", "High", "Medium", "Low"]),
        "trends": random.choice(["Increasing", "Stable", "Decreasing"])
    }

def auto_decide_action(risk_score, clean=False):
    """
    Simulates the Decision Support System.
    """
    if clean:
        return "Monitor"
        
    if risk_score >= 80:
        return "Block"
    elif risk_score >= 50:
        return "Investigate"
    else:
        return "Monitor"

# ==============================
# IOC ANALYSIS ROUTE (UPDATED)
# ==============================
@app.route("/analyze", methods=["POST"])
def analyze_ioc():
    ioc = request.form.get("ioc")

    if not ioc:
        return jsonify({
            "status": "ERROR",
            "message": "No IOC provided"
        })

    # Step 1: Auto Ingestion (Simulated by receiving the request)
    
    # Step 2: Auto Classification
    classification = auto_classify_threat(ioc)
    
    # Step 3: Auto Risk Scoring
    # Check if known malicious
    is_known_malicious = ioc in KNOWN_IOCS
    
    risk_factors = auto_calculate_risk_factors()
    
    if is_known_malicious:
        # Known threat
        threat_name = KNOWN_IOCS[ioc]
        base_score = 90
        risk_level = "CRITICAL"
        status = "MALICIOUS"
    else:
        # Unknown/New threat simulation
        # If it looks like an IP, 50% chance it's flagged for the hackathon demo
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc) and random.random() > 0.5:
             base_score = random.randint(60, 95)
             risk_level = "HIGH" if base_score > 80 else "MEDIUM"
             status = "MALICIOUS"
             threat_name = f"Unknown {classification} Variant"
        else:
            base_score = 10
            risk_level = "LOW"
            status = "CLEAN"
            threat_name = "None"

    # Step 4: Auto Decision Support
    decision = auto_decide_action(base_score, clean=(status=="CLEAN"))

    return jsonify({
        "status": status,
        "threat": threat_name,
        "classification": classification,
        "risk_score": base_score,
        "risk_level": risk_level,
        "decision": decision,
        "factors": risk_factors
    })

# ==============================
# RUN SERVER
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
