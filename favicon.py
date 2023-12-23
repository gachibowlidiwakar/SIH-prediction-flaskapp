from flask import Flask, jsonify, request
from PIL import Image
import numpy as np
from skimage.metrics import structural_similarity as ssim
import cv2
import requests
from bs4 import BeautifulSoup
from io import BytesIO
from urllib.parse import urljoin

app = Flask(__name__)

def get_favicon_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        favicon_tag = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')

        if favicon_tag and 'href' in favicon_tag.attrs:
            favicon_url = favicon_tag['href']

            if not favicon_url.startswith(('http:', 'https:')):
                favicon_url = urljoin(url, favicon_url)
            return favicon_url

    except requests.exceptions.RequestException as e:
        return f"Error fetching {url}: {e}"

def load_image(url):
    response = requests.get(url)
    return Image.open(BytesIO(response.content))

def resize_image(image, size):
    return image.resize(size, Image.ANTIALIAS)

def pil_to_opencv(image_pil):
    return np.array(image_pil)

def get_ssi_index(image1, image2):
    size = (3000, 3000)
    image1 = resize_image(image1, size)
    image2 = resize_image(image2, size)

    # Convert images to NumPy arrays
    array1 = pil_to_opencv(image1)
    array2 = pil_to_opencv(image2)

    # Convert images to grayscale if they have multiple channels
    if len(array1.shape) == 3:
        gray1 = cv2.cvtColor(array1, cv2.COLOR_RGB2GRAY)
    else:
        gray1 = array1

    if len(array2.shape) == 3:
        gray2 = cv2.cvtColor(array2, cv2.COLOR_RGB2GRAY)
    else:
        gray2 = array2

    # Compute Structural Similarity Index (SSI)
    ssi_index, _ = ssim(gray1, gray2, full=True)

    # Compute Mean Squared Error (MSE)
    # mse = mean_squared_error(gray1, gray2)
    return ssi_index

def compare_favicon(url1, url2):
    favicon_url1 = get_favicon_url(url1)
    favicon_url2 = get_favicon_url(url2)
    try:
        favicon1 = load_image(favicon_url1)
        favicon2 = load_image(favicon_url2)
        ssi_index = get_ssi_index(favicon1, favicon2)
        return ssi_index
    except Exception as e:
        return f"Error comparing favicons: {str(e)}"

@app.route('/compareFavicon', methods=['POST'])
def compare_favicon_route():
    try:
        data = request.get_json()
        url1 = data.get('url1')
        url2 = data.get('url2')

        if not url1 or not url2:
            return jsonify({'error': 'Please provide both URLs'}), 400

        result = compare_favicon(url1, url2)

        if isinstance(result, str):
            return jsonify({'error': result}), 500

        return jsonify({'ssi_index': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


