import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import secrets
import firebase_admin
from firebase_admin import credentials,firestore
from datetime import datetime, timezone


cred = credentials.Certificate("venv/serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db= firestore.client()



app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load the trained model
MODEL_PATH = 'random_forest_model.pkl'
model = joblib.load(MODEL_PATH)

# URL Preprocessing Functions
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

# Feature Extraction Function
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
        # Convert URL to features
        X_test = URL_Converter(url)

        # Make prediction
        prediction = model.predict(X_test)[0]

        # Map prediction to label
        label_mapping = {0: "benign", 1: "defacement", 2: "phishing", 3: "malware"}
        return label_mapping.get(prediction, "unknown")
    except Exception as e:
        return str(e)

# Set a daily request limit
DAILY_LIMIT = 100  # Change as needed

def generate_unique_api_key():
    """Generates a unique API key and ensures it's not already in Firestore."""
    while True:
        api_key = secrets.token_hex(32)  # 64-character API key
        existing_keys = db.collection("apikeys").where("api_keys", "array_contains", api_key).stream()
        if not any(existing_keys):  # Ensure uniqueness
            return api_key

@app.route("/apiKey", methods=["GET"])
def generate_api():
    """Generates an API key and initializes its usage count."""
    email = request.args.get("email")  # Get email from query parameters

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user_doc_ref = db.collection("apikeys").document(email)
    user_doc = user_doc_ref.get()

    new_api_key = generate_unique_api_key()  # Generate a unique API key

    if user_doc.exists:
        user_data = user_doc.to_dict()
        existing_api_keys = user_data.get("api_keys", [])
        usage_counts = user_data.get("usage_counts", {})
        daily_usage = user_data.get("daily_usage", {})

        existing_api_keys.append(new_api_key)
        usage_counts[new_api_key] = 0  # Set total usage count to zero
        daily_usage[new_api_key] = {"count": 0, "last_reset": datetime.now(timezone.utc)}

        user_doc_ref.update({
            "api_keys": existing_api_keys,
            "usage_counts": usage_counts,
            "daily_usage": daily_usage
        })
    else:
        user_doc_ref.set({
            "api_keys": [new_api_key],
            "usage_counts": {new_api_key: 0},
            "daily_usage": {new_api_key: {"count": 0, "last_reset": datetime.now(timezone.utc)}}
        })

    return jsonify({"email": email, "api_key": new_api_key, "usage_count": 0, "daily_limit": DAILY_LIMIT})

def verify_api_key(email, api_key):
    """Checks API key validity and ensures daily usage is within the limit."""
    user_doc_ref = db.collection("apikeys").document(email)
    user_doc = user_doc_ref.get()

    if not user_doc.exists:
        return False, "Invalid API key or email"

    user_data = user_doc.to_dict()
    api_keys = user_data.get("api_keys", [])
    usage_counts = user_data.get("usage_counts", {})
    daily_usage = user_data.get("daily_usage", {})

    if api_key not in api_keys:
        return False, "Invalid API key"

    # Get current UTC date
    now = datetime.now(timezone.utc)
    today = now.date()

    # Get API key's daily usage info
    usage_info = daily_usage.get(api_key, {"count": 0, "last_reset": now})
    last_reset = usage_info["last_reset"]
    last_reset_date = last_reset.date() if isinstance(last_reset, datetime) else today

    # Reset daily usage if a new day has started
    if last_reset_date < today:
        usage_info["count"] = 0
        usage_info["last_reset"] = now

    # Check if daily limit exceeded
    if usage_info["count"] >= DAILY_LIMIT:
        return False, "Daily request limit exceeded"

    # Increment API key usage count
    usage_info["count"] += 1
    usage_counts[api_key] = usage_counts.get(api_key, 0) + 1
    daily_usage[api_key] = usage_info

    # Update Firestore
    user_doc_ref.update({"usage_counts": usage_counts, "daily_usage": daily_usage})
    return True, None

@app.route('/predict', methods=['POST'])
def classify_url():
    try:
        data = request.get_json()
        email = data.get("email", "").strip()
        api_key = data.get("api_key", "").strip()
        url = data.get("url", "").strip()

        if not email or not api_key or not url:
            return jsonify({"error": "Email, API key, and URL are required"}), 400

        # Verify API Key, Check Daily Limit, and Increment Usage
        is_valid, error_message = verify_api_key(email, api_key)
        if not is_valid:
            return jsonify({"error": error_message}), 403

        # Proceed with URL classification
        result = predict(url)  # Replace with actual prediction function
        return jsonify({"url": url, "classification": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)


