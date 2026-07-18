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
## 📂 Project Structure

```
spam-email-detection/
│
├── app.py
├── preprocess.py
├── requirements.txt
├── model.pkl
├── vectorizer.pkl
├── metrics.pkl
├── pie_data.pkl
├── spam.csv
│
├── templates/
│   └── dashboard.html
│
├── static/
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

### Example Request:
```
</>/JSON
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
* Algorithm: Naive Bayes
* Vectorizer: TF-IDF
* Dataset: SMS Spam Collection Dataset
---
## 🚀 Deployment (Optional)

Can be deployed using:
* Render 
* Heroku 
* AWS / GCP 
