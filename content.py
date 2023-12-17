import requests
from bs4 import BeautifulSoup

def extract_website_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            return f"Failed to fetch content. Status code: {response.status_code}"
    except requests.RequestException as e:
        return f"Error: {e}"

def extract_title_and_body(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    title = soup.title.text if soup.title else "No title found"
    body = soup.body.text if soup.body else "No body found"
    body_with_single_space = ' '.join(body.split())  # Adding a single space after every word
    return title, body_with_single_space

# Replace 'example.com' with the domain you want to extract content from
website_url = 'https://cryptonite.live'

# Call the function with the URL
content = extract_website_content(website_url)

if content:
    title, body = extract_title_and_body(content)
    print("Title:", title)
    print("Body with single space after every word:\n\n", body)
else:
    print("Content extraction failed.")

#This code is getting the title and body of a website