import pickle
import pandas as pd
import numpy as np
import os
import gdown
from urllib.parse import urlparse
import ipaddress
import re
import whois
import requests
from datetime import datetime, timezone
import warnings
import secrets
import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

warnings.filterwarnings('ignore')

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

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
try:
    cred = credentials.Certificate(firebase_config)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    firebase_enabled = True
    print("Firebase initialized successfully!")
except Exception as e:
    print(f"Firebase initialization failed: {e}")
    firebase_enabled = False

# Google Drive Model Download
MODEL_PATH = "model/XGBoostClassifier.pickle.dat"
GOOGLE_DRIVE_FILE_ID = os.getenv("GOOGLE_DRIVE_FILE_ID")

if not os.path.exists(MODEL_PATH):
    os.makedirs("model", exist_ok=True)
    gdown.download(f"https://drive.google.com/uc?id={GOOGLE_DRIVE_FILE_ID}", MODEL_PATH, quiet=False)

# Set a daily request limit
DAILY_LIMIT = 100  # Change as needed


# 1.Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


# 2.Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 0
    except:
        ip = 1
    return ip


# 3.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    if "@" in url:
        at = 0
    else:
        at = 1
    return at


# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    if len(url) < 54:
        length = 1
    else:
        length = 0
    return length


# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth


# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 0
        else:
            return 1
    else:
        return 0


# 7.Existence of "HTTPS" Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 0
    else:
        return 1


# Listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


# 8. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 0
    else:
        return 1


# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 0  # phishing
    else:
        return 1  # legitimate


# 12.Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        # Use a more reliable method - simply check if the site responds
        response = requests.head(url, timeout=5)
        # Check if site responds with a successful status code
        if response.status_code < 400:  # Any 2xx or 3xx status code
            return 1  # Site is accessible, likely legitimate
        else:
            return 0  # Site has issues, might be phishing
    except:
        return 0  # Any error (timeout, connection refused, etc.) is suspicious


# 13.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 0
    if ((expiration_date is None) or (creation_date is None)):
        return 0
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 0
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain / 30) < 6):
            age = 0
        else:
            age = 1
    return age


# 14.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 0
    if (expiration_date is None):
        return 0
    elif (type(expiration_date) is list):
        return 0
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end / 30) < 6):
            end = 1
        else:
            end = 0
    return end


# 15. IFrame Redirection (iFrame)
def iframe(response):
    if response == "":
        return 0
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 1
        else:
            return 0


# 16.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if response == "":
        return 0
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 0
        else:
            return 1


# 17.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    if response == "":
        return 0
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 1
        else:
            return 0


# 18.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if response == "":
        return 0
    else:
        if len(response.history) <= 2:
            return 1
        else:
            return 0


# Function to extract features
def featureExtraction(url):
    features = []
    # Address bar based features (9)
    domain = getDomain(url)
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # Domain based features (4)
    dns = 1
    try:
        domain_name = whois.whois(domain)
    except:
        dns = 0

    features.append(dns)
    features.append(web_traffic(url))
    features.append(0 if dns == 0 else domainAge(domain_name))
    features.append(0 if dns == 0 else domainEnd(domain_name))

    # HTML & Javascript based features (4)
    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features


# Load the model
def load_model():
    try:
        with open(MODEL_PATH, 'rb') as file:
            loaded_model = pickle.load(file)
        print("Model loaded successfully!")
        return loaded_model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None


# Global variable for the model
xgb_model = load_model()


def generate_unique_api_key():
    """Generates a unique API key and ensures it's not already in Firestore."""
    while True:
        api_key = secrets.token_hex(32)
        existing_keys = db.collection("apikeys").where("api_keys", "array_contains", api_key).stream()
        if not any(existing_keys):  # Ensure uniqueness
            return api_key


@app.route("/apiKey", methods=["GET"])
def generate_api():
    """Generates an API key and initializes its usage count."""
    email = request.args.get("email")  # Get email from query parameters

    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not firebase_enabled:
        return jsonify({"error": "Firebase is not enabled. Cannot generate API key."}), 500

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
    if not firebase_enabled:
        return False, "Firebase is not enabled. Cannot verify API key."

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
    """API endpoint for URL classification with authentication."""
    try:
        if xgb_model is None:
            return jsonify({"error": "Model not loaded"}), 500

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

        # Extract features for prediction
        feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                         'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                         'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards']

        features = featureExtraction(url)
        feature_df = pd.DataFrame([features], columns=feature_names)

        # Make prediction
        prediction = xgb_model.predict(feature_df)[0]
        probability = xgb_model.predict_proba(feature_df)[0]

        # Format the result
        result = {
            "url": url,
            "is_phishing": prediction == 0,
            "confidence": float(probability[0 if prediction == 0 else 1]),
            "classification": "PHISHING" if prediction == 0 else "LEGITIMATE"
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/predicturl', methods=['POST'])
def classify_url_simple():
    """Simplified API endpoint for URL classification without authentication."""
    try:
        if xgb_model is None:
            return jsonify({"error": "Model not loaded"}), 500

        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"error": "URL is required"}), 400

        # Extract features for prediction
        feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
                         'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
                         'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards']

        features = featureExtraction(url)
        feature_df = pd.DataFrame([features], columns=feature_names)

        # Make prediction
        prediction = xgb_model.predict(feature_df)[0]

        # Format the result similar to the second code example
        is_safe = prediction != 0  # 0 is phishing (not safe)
        threat_category = "phishing" if prediction == 0 else "legitimate"

        result = {
            "url": url,
            "is_safe": is_safe,
            "threat_categories": [threat_category],
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Simple status endpoint
@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "online", "model_loaded": xgb_model is not None})


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
