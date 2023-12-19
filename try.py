import requests
import json

# Set the base URL of your Flask app
base_url = "http://127.0.0.1:5000"  # Change this to your Flask app's URL

# Test data for URL classification
url_test_data = {
    "url": "http://ebayisapidlld.altervista.org/"  # Replace with a test URL
}

# Test data for SMS classification
sms_test_data = {
    "body": "collect your lottery of 2500000 here immediately. Click on this link"  # Replace with a test SMS message
}

# Test data for content extraction
content_test_data = {
    "url": "https://cryptonite.live"  # Replace with a test URL for content extraction
}

# Test data for URL content phishing prediction
url_content_test_data = {
    "url":"https://www.google.com" # Replace with a test URL for phishing prediction
}


# Test data for domain prediction
domain_test_data = {
    "url": "sih.gov.in"   # Replace with a test URL for domain prediction
}

# Function to test domain prediction
def test_domain_prediction():
    response = requests.post(f"{base_url}/predictdomain", json=domain_test_data)
    if response.status_code == 200:
        print("Domain Prediction Success:", response.json())
    else:
        print("Domain Prediction Failed:", response.text)


# Function to test URL classification
def test_url_classification():
    response = requests.post(f"{base_url}/predictURL", json=url_test_data)
    if response.status_code == 200:
        print("URL Classification Success:", response.json())
    else:
        print("URL Classification Failed:", response.text)

# Function to test SMS classification
def test_sms_classification():
    response = requests.post(f"{base_url}/predictsms", json=sms_test_data)
    if response.status_code == 200:
        print("SMS Classification Success:", response.json())
    else:
        print("SMS Classification Failed:", response.text)

# Function to test content extraction
def test_content_extraction():
    response = requests.post(f"{base_url}/getcontent", json=content_test_data)
    if response.status_code == 200:
        print("Content Extraction Success:", response.json())
    else:
        print("Content Extraction Failed:", response.text)

# Function to test URL content phishing prediction
def test_url_content_prediction():
    response = requests.post(f"{base_url}/predicturlcontent", json=url_content_test_data)
    if response.status_code == 200:
        print("URL Content Phishing Prediction Success:", response.json())
    else:
        print("URL Content Phishing Prediction Failed:", response.text)

def test_domain_similarity():
    response = requests.post(f"{base_url}/predictsimilarity", json=domain_test_data)
    if response.status_code == 200:
        print(f"{response.json()}")
    else:
        print(f"Request failed with status code: {response.status_code}")
        print(f"Error message: {response.text}")

def test_domain_combined():
    response = requests.post(f"{base_url}/predictcombined", json=domain_test_data)
    if response.status_code == 200:
        print(f"Non Phishing Probability: {response.json()}")
    else:
        print(f"Request failed with status code: {response.status_code}")
        print(f"Error message: {response.text}")

if __name__ == "__main__":
    # test_url_classification()
    # test_sms_classification()
    # test_content_extraction()
    # test_url_content_prediction()
    # test_domain_prediction()
    test_domain_similarity()
    # test_domain_combined()