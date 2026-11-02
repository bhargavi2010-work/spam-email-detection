from flask import Flask, request, jsonify, render_template
import pickle
import re
import os
import time
from datetime import datetime
from preprocess import preprocess_text
from forensics import EmailForensicsEngine
from geoip_resolver import GeoIPResolver
from flask_cors import CORS

import nltk
# Ensure required NLTK corpora are downloaded without querying network on every start
for pkg_name, path_name in [('punkt', 'tokenizers/punkt'), ('stopwords', 'corpora/stopwords')]:
    try:
        nltk.data.find(path_name)
    except LookupError:
        nltk.download(pkg_name, quiet=True)

app = Flask(__name__)
CORS(app)

# Initialize Forensics & GeoIP Engines
forensics_engine = EmailForensicsEngine()
geoip_resolver = GeoIPResolver()

# Load the saved model and vectorizer
with open('model/metrics.pkl', 'rb') as f:
    metrics = pickle.load(f)

with open('model/pie_data.pkl', 'rb') as f:
    pie_data = pickle.load(f)

with open('model/model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('model/vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)

# In-memory Incident Case Store (Sample incidents + newly scanned emails)
INCIDENTS_DATABASE = [
    {
        "case_id": "#SEC-9402",
        "timestamp": "2026-11-02 08:14:22",
        "sender": "PayPal Support <scammer@rogue-host.xyz>",
        "origin_ip": "185.220.101.5",
        "country": "Russia",
        "country_code": "RU",
        "classification": "Credential Phishing / Impersonation",
        "risk_score": 92,
        "action": "QUARANTINED"
    },
    {
        "case_id": "#SEC-9398",
        "timestamp": "2026-11-01 16:45:10",
        "sender": "CEO John <wire-transfer@finance-corp-update.com>",
        "origin_ip": "194.109.6.92",
        "country": "Germany",
        "country_code": "DE",
        "classification": "Business Email Compromise (BEC)",
        "risk_score": 85,
        "action": "QUARANTINED"
    },
    {
        "case_id": "#SEC-9391",
        "timestamp": "2026-11-01 11:20:05",
        "sender": "Google Security <support@google.com>",
        "origin_ip": "209.85.208.52",
        "country": "United States",
        "country_code": "US",
        "classification": "Legitimate Notification",
        "risk_score": 0,
        "action": "DELIVERED"
    },
    {
        "case_id": "#SEC-9384",
        "timestamp": "2026-10-31 19:05:43",
        "sender": "Discount Meds <promo@bulk-sales-discount.net>",
        "origin_ip": "185.234.111.9",
        "country": "Lithuania",
        "country_code": "LT",
        "classification": "Marketing Spam",
        "risk_score": 45,
        "action": "FLAGGED"
    }
]

# Routes
@app.route('/')
def home():
    return render_template(
        'dashboard.html',
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        spam=pie_data["spam"],
        ham=pie_data["ham"],
        incidents=INCIDENTS_DATABASE
    )

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json() or {}
    message = data.get('message', '').strip()

    # Backend validation
    if not message:
        return jsonify({'error': 'Message is required'}), 400

    processed = preprocess_text(message)
    vectorized = vectorizer.transform([processed])
    
    prediction = model.predict(vectorized)
    proba = model.predict_proba(vectorized)[0]
    
    confidence = max(proba)
    result = "Spam" if prediction[0] == 1 else "Ham"
    
    return jsonify({
        'prediction': result,
        'confidence': round(float(confidence * 100), 2)
    })

@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    """
    Forensics, GeoLocation, Protocol Analysis & NLP Classification.
    Accepts:
      - .eml file upload via form-data (key: 'file')
      - raw email text via form-data (key: 'raw_email')
      - raw email text via JSON body (key: 'raw_email')
    """
    raw_content = None

    # 1. Check if .eml file was uploaded
    if 'file' in request.files:
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            raw_content = uploaded_file.read()

    # 2. Check form data (textarea)
    if not raw_content and 'raw_email' in request.form:
        raw_content = request.form.get('raw_email', '').strip()

    # 3. Check JSON payload
    if not raw_content and request.is_json:
        data = request.get_json() or {}
        raw_content = data.get('raw_email', '').strip()

    if not raw_content:
        return jsonify({'error': 'No email content or .eml file provided'}), 400

    try:
        # Run deep header and protocol forensics
        forensic_data = forensics_engine.parse_eml(raw_content)

        # Classify the extracted email body using NLP model
        body_to_classify = forensic_data['body']['plain'] or forensic_data['envelope']['subject']
        nlp_result = None
        if body_to_classify and body_to_classify.strip():
            processed = preprocess_text(body_to_classify)
            vectorized = vectorizer.transform([processed])
            pred = model.predict(vectorized)[0]
            proba = model.predict_proba(vectorized)[0]
            confidence = max(proba)
            nlp_result = {
                'prediction': 'Spam' if pred == 1 else 'Ham',
                'confidence': round(float(confidence * 100), 2)
            }

        forensic_data['nlp_analysis'] = nlp_result

        # Phase 2: Resolve Origin IP Geolocation & Relay Hop Coordinates
        origin_ip = forensic_data['traceability']['origin_ip']
        origin_geo = geoip_resolver.resolve_ip(origin_ip)
        enriched_hops = geoip_resolver.resolve_relay_hops(forensic_data['traceability']['relay_hops'])

        forensic_data['geolocation'] = {
            "origin_geo": origin_geo,
            "relay_hops_geo": enriched_hops
        }

        # Dynamically record this scan into the Incidents Database
        case_id = f"#SEC-{int(time.time()) % 10000:04d}"
        risk_score = forensic_data['forensic_assessment']['risk_score']
        
        if risk_score >= 70:
            classification = "Malicious Phishing / Spoofed"
            action = "QUARANTINED"
        elif risk_score >= 35:
            classification = "Suspicious Origin / Inconclusive"
            action = "FLAGGED"
        else:
            classification = "Clean / Legitimate"
            action = "DELIVERED"

        incident_entry = {
            "case_id": case_id,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "sender": forensic_data['envelope']['from_header'] or "Unknown",
            "origin_ip": origin_ip or "N/A",
            "country": origin_geo.get("country", "Unknown"),
            "country_code": origin_geo.get("country_code", "UN"),
            "classification": classification,
            "risk_score": risk_score,
            "action": action
        }
        INCIDENTS_DATABASE.insert(0, incident_entry)

        return jsonify({
            'status': 'success',
            'data': forensic_data,
            'incident': incident_entry
        })
    except Exception as e:
        return jsonify({'error': f'Failed to parse email: {str(e)}'}), 500

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    return jsonify({
        'status': 'success',
        'incidents': INCIDENTS_DATABASE
    })

@app.route('/performance')
def performance():
    return render_template(
        'performance.html',
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"]
    )

@app.route('/pie')
def pie():
    return render_template(
        'pie.html',
        spam=pie_data["spam"],
        ham=pie_data["ham"]
    )

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
