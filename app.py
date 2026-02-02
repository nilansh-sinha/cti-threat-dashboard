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
        template="plotly_dark"
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
        color_continuous_scale="Reds",
        template="plotly_dark"
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
@app.route("/analyze", methods=["POST"])
def analyze_ioc():
    ioc = request.form.get("ioc")

    if not ioc:
        return jsonify({
            "status": "ERROR",
            "message": "No IOC provided"
        })

    if ioc in KNOWN_IOCS:
        return jsonify({
            "status": "MALICIOUS",
            "threat": KNOWN_IOCS[ioc],
            "risk_level": "HIGH"
        })

    return jsonify({
        "status": "CLEAN",
        "message": "No records found",
        "risk_level": "LOW"
    })

# ==============================
# RUN SERVER
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
