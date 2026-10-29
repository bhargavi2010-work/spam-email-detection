from flask import Flask, request, jsonify, render_template
import pickle
import re
import os
from preprocess import preprocess_text
from forensics import EmailForensicsEngine
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

# Initialize Forensics Engine
forensics_engine = EmailForensicsEngine()

# Load the saved model and vectorizer
with open('model/metrics.pkl', 'rb') as f:
    metrics = pickle.load(f)

with open('model/pie_data.pkl', 'rb') as f:
    pie_data = pickle.load(f)

with open('model/model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('model/vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f)

# Routes
@app.route('/')
def home():
    return render_template(
        'dashboard.html',
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        spam=pie_data["spam"],
        ham=pie_data["ham"]
    )

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
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
    Forensics & Protocol Analysis Endpoint.
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
        return jsonify({
            'status': 'success',
            'data': forensic_data
        })
    except Exception as e:
        return jsonify({'error': f'Failed to parse email: {str(e)}'}), 500

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
