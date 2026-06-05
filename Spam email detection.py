# Step 1: Import Libraries
import pandas as pd
import numpy as np
import re
import nltk
import pickle
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score
from preprocess import preprocess_text

# Step 2: Download NLTK Resources
nltk.download('punkt')
nltk.download('stopwords')

# Step 3: Load and Preprocess Dataset
data = pd.read_csv('spam.csv', encoding='latin-1')
data = data[['v1', 'v2']]
data.columns = ['label', 'message']

# Clean label column 
data['label'] = data['label'].str.strip().str.lower()
data = data[data['label'].isin(['ham', 'spam'])]  # Keep only ham/spam

# Map labels to binary values 
data['label'] = data['label'].map({'ham': 0, 'spam': 1})

# Drop missing messages and fill just in case
data['message'] = data['message'].fillna('')

# ADD PIE CHART DATA CODE RIGHT HERE

spam_count = data['label'].value_counts()

pie_data = {
    "spam": int(spam_count[1]),
    "ham": int(spam_count[0])
}

with open("pie_data.pkl", "wb") as f:
    pickle.dump(pie_data, f)

# Text preprocessing
stop_words = set(stopwords.words('english'))

data['message'] = data['message'].apply(preprocess_text)

# Step 4: Feature Extraction
vectorizer = TfidfVectorizer(max_features=3000)
X = vectorizer.fit_transform(data['message'])
y = data['label']

# Sanity check
assert not np.any(np.isnan(X.toarray())), "X contains NaNs"
assert not y.isnull().any(), "y contains NaNs"

# Step 5: Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 6: Train Model
model = MultinomialNB()
model.fit(X_train, y_train)

# Step 7: Evaluate Model
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)

print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")

print("Classification Report:\n", classification_report(y_test, y_pred))

# Save evaluation metrics
metrics = {
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall
}

with open("metrics.pkl", "wb") as f:
    pickle.dump(metrics, f)

# Step 8: Save Model and Vectorizer
with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("\n==============================")
print("Model Trained Successfully!")
print(f"Accuracy : {accuracy:.2f}")
print("==============================\n")

# Step 9: (Optional) Test on New Input
def predict_spam(text):
    text = preprocess_text(text)
    text_vec = vectorizer.transform([text])
    prediction = model.predict(text_vec)
    return "Spam" if prediction[0] == 1 else "Ham"

# Example prediction
print("Test:", predict_spam("Congratulations! You've won a $1000 gift card. Claim now!"))

