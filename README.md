# 📧 Spam Email Detection System

A Machine Learning-based web application that classifies emails/messages as **Spam** or **Not Spam** using Natural Language Processing (NLP).

---

## 🚀 Features

- Detects spam messages instantly  
- Shows prediction confidence score  
- Web interface using Flask  
- Fast and lightweight ML model  

---

## 🧠 Tech Stack

- Python  
- Flask  
- Scikit-learn  
- Pandas, NumPy  
- HTML, CSS

--- 

## 🔍 NLP Pipeline

The application uses Natural Language Processing techniques:

* Text cleaning (removing special characters)
* Lowercasing
* Tokenization
* Stopword removal
* TF-IDF vectorization
---
## 📈 Model Performance

Metrics are computed during training and stored for dashboard visualization:

* Accuracy
* Precision
* Recall

---
## 📂 Project Structure

```
spam-email-detection/
│
├── app.py
├── preprocess.py
├── train.py
├── requirements.txt
├── Procfile
├── .gitignore
│
├── data/
│   └── spam.csv
│
├── model/
│   ├── model.pkl
│   ├── vectorizer.pkl
│   ├── metrics.pkl
│   ├── pie_data.pkl
│
├── notebook/
│   └── spam_email_detection.ipynb
│
├── templates/
│   └── dashboard.html
│
├── static/
│   ├── bg.png
│   └── script.js
│
└── README.md

```
---

## ⚙️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/bhargavi2010-work/spam-email-detection.git
cd spam-email-detection
```
### 2. Create Virtual Environment
```
python -m venv spam_env
```
### 3. Activate Environment
▶️ Windows:
```
.\spam_env\Scripts\activate
```
▶️ Mac/Linux:
```
source spam_env/bin/activate
```
### 4. Install Dependencies
```
pip install -r requirements.txt
``` 
### 5. Run the Application
```
python app.py
```
--- 

## 🌍 Access the App

Open your browser and go to:

http://127.0.0.1:5000/

## API Usage
Endpoint:
```
POST /predict
```

### Request:
```json
{
  "message": "Win a free iPhone now!"
}
```

### Response:
```
{
  "prediction": "Spam",
  "confidence": 75.22
}
```
--- 

## 📊 Model Information
* Algorithm: Multinomial Naive Bayes
* Vectorizer: TF-IDF (max_features=3000)
* Dataset: SMS Spam Collection Dataset
* Evaluation Metrics:
  * Accuracy
  * Precision
  * Recall
---
## 🚀 Deployment (Optional)

Can be deployed using:
* Render 
* Heroku 
* AWS / GCP
