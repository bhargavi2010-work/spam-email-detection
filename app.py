from flask import Flask, request, jsonify, render_template
import pickle
import re
import os
from preprocess import preprocess_text
from flask_cors import CORS

import nltk
nltk.download('punkt')
nltk.download('stopwords')

app = Flask(__name__)
CORS(app)

# Load the saved model and vectorizer
with open('model/metrics.pkl', 'rb') as f:
    metrics = pickle.load(f)

with open('model/pie_data.pkl', 'rb') as f:
    pie_data = pickle.load(f)

with open('model/model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('model/vectorizer.pkl', 'rb') as f:
    vectorizer = pickle.load(f) 

app = Flask(__name__)  

# Data preprocessing
# def preprocess_text(text):
#     text = text.lower()
#     text = re.sub(r'[^a-z\s]', '', text)
#     return text

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
    # return render_template('index.html')

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
    
    
    
