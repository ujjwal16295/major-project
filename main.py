import os
import joblib
import pandas as pd
import re
import secrets
import gdown
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Firebase Configuration
firebase_config = {
    "type": os.getenv("TYPE"),
    "project_id": os.getenv("PROJECT_ID"),
    "private_key_id": os.getenv("PRIVATE_KEY_ID"),
    "private_key": os.getenv("PRIVATE_KEY"),
    "client_email": os.getenv("CLIENT_EMAIL"),
    "client_id": os.getenv("CLIENT_ID"),
    "auth_uri": os.getenv("AUTH_URI"),
    "token_uri": os.getenv("TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("CLIENT_X509_CERT_URL"),
    "universe_domain": os.getenv("UNIVERSE_DOMAIN")
}

# Initialize Firebase
cred = credentials.Certificate(firebase_config)
firebase_admin.initialize_app(cred)
db = firestore.client()

# Flask App
app = Flask(__name__)
CORS(app)

# Google Drive Model Download
MODEL_PATH = "model/random_forest_model.pkl"
GOOGLE_DRIVE_FILE_ID = os.getenv("GOOGLE_DRIVE_FILE_ID")

if not os.path.exists(MODEL_PATH):
    os.makedirs("model", exist_ok=True)
    gdown.download(f"https://drive.google.com/uc?id={GOOGLE_DRIVE_FILE_ID}", MODEL_PATH, quiet=False)

# Load Model
model = joblib.load(MODEL_PATH)

# URL Processing Functions
def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 1 if hostname and re.search(hostname, url) else 0

def httpSecure(url):
    return 1 if urlparse(url).scheme == 'https' else 0

def digit_count(url):
    return sum(1 for i in url if i.isnumeric())

def letter_count(url):
    return sum(1 for i in url if i.isalpha())

def Shortining_Service(url):
    return 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|t\.co|tinyurl\.com', url) else 0

def having_ip_address(url):
    return 1 if re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])', url) else 0

# Convert URL to Features
def URL_Converter(url):
    data = pd.DataFrame({'url': [url]})
    data['url_len'] = len(url)
    feature = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    for a in feature:
        data[a] = url.count(a)
    data['abnormal_url'] = abnormal_url(url)
    data['https'] = httpSecure(url)
    data['digits'] = digit_count(url)
    data['letters'] = letter_count(url)
    data['Shortining_Service'] = Shortining_Service(url)
    data['having_ip_address'] = having_ip_address(url)
    return data.drop(['url'], axis=1)

# Prediction Function
def predict(url):
    try:
        X_test = URL_Converter(url)
        prediction = model.predict(X_test)[0]
        label_mapping = {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"}
        return label_mapping.get(prediction, "unknown")
    except Exception as e:
        return str(e)

# API Key Generation & Verification
DAILY_LIMIT = 100

def generate_unique_api_key():
    while True:
        api_key = secrets.token_hex(32)
        existing_keys = db.collection("apikeys").where("api_keys", "array_contains", api_key).stream()
        if not any(existing_keys):
            return api_key

@app.route("/apiKey", methods=["GET"])
def generate_api():
    email = request.args.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    user_doc_ref = db.collection("apikeys").document(email)
    user_doc = user_doc_ref.get()

    new_api_key = generate_unique_api_key()
    if user_doc.exists:
        user_data = user_doc.to_dict()
        existing_api_keys = user_data.get("api_keys", [])
        usage_counts = user_data.get("usage_counts", {})
        daily_usage = user_data.get("daily_usage", {})

        existing_api_keys.append(new_api_key)
        usage_counts[new_api_key] = 0
        daily_usage[new_api_key] = {"count": 0, "last_reset": datetime.now(timezone.utc)}

        user_doc_ref.update({"api_keys": existing_api_keys, "usage_counts": usage_counts, "daily_usage": daily_usage})
    else:
        user_doc_ref.set({"api_keys": [new_api_key], "usage_counts": {new_api_key: 0}, "daily_usage": {new_api_key: {"count": 0, "last_reset": datetime.now(timezone.utc)}}})

    return jsonify({"email": email, "api_key": new_api_key, "usage_count": 0, "daily_limit": DAILY_LIMIT})

def verify_api_key(email, api_key):
    user_doc_ref = db.collection("apikeys").document(email)
    user_doc = user_doc_ref.get()

    if not user_doc.exists:
        return False, "Invalid API key or email"

    user_data = user_doc.to_dict()
    if api_key not in user_data.get("api_keys", []):
        return False, "Invalid API key"

    return True, None

@app.route('/predict', methods=['POST'])
def classify_url():
    data = request.get_json()
    email = data.get("email", "").strip()
    api_key = data.get("api_key", "").strip()
    url = data.get("url", "").strip()

    if not email or not api_key or not url:
        return jsonify({"error": "Email, API key, and URL are required"}), 400

    is_valid, error_message = verify_api_key(email, api_key)
    if not is_valid:
        return jsonify({"error": error_message}), 403

    result = predict(url)
    return jsonify({"url": url, "classification": result})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)

