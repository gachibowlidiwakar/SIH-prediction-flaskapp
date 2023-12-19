from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
import pandas as pd
from urllib.parse import urlparse, unquote
import re
import socket
import whois
from datetime import datetime
import time
import numpy as np
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from keras.models import load_model
import requests
from bs4 import BeautifulSoup
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from transformers import BertTokenizer, BertModel
import torch
from scipy.spatial.distance import cosine
from bs4 import BeautifulSoup
import requests



# Load the GBC model for domain prediction
file = open("./model.pkl", "rb")
gbc = pickle.load(file)
file.close()

# gbc = joblib.load('model.pkl')

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass


        

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())


     # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
    
    # 13. RequestURL
    def RequestURL(self):
        try:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i,success = 0,0
        
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
             return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording    
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                return 1
            return 0
        except :
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})

            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1
            

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1
    
    def getFeaturesList(self):
        return self.features




# Initialize Flask App
app = Flask(__name__)
CORS(app)

# Load URL classification model
classifier = joblib.load('./url_model.sav')  # Adjust the path if necessary

# Similarity
def analyze_website_similarity(domain, threshold=0.6):
    model_name = 'bert-base-uncased'
    tokenizer = BertTokenizer.from_pretrained(model_name)
    model = BertModel.from_pretrained(model_name)

    def extract_website_content(url):
        if not url.startswith('http'):
            url = 'https://' + url
        
        try:
            response = requests.get(url, timeout=10)
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

    def get_bert_embedding(text):
        tokens = tokenizer.encode(text, return_tensors='pt', truncation=True, max_length=512)

        with torch.no_grad():
            outputs = model(tokens)
            embeddings = outputs.last_hidden_state.mean(dim=1).squeeze()

        return embeddings

    def check_similarity(title, body):
        title_embedding = get_bert_embedding(title)
        body_embedding = get_bert_embedding(body)

        similarity_score = 1 - cosine(title_embedding, body_embedding)
        return similarity_score

    content = extract_website_content(domain)

    if content:
        title, body = extract_title_and_body(content)
#         print(body)
        if title.strip() =="No title found" or body.strip() == "No body found":
            print('Phishing: Title or Body is empty.')
            return 0
#         print(body)
        similarity = check_similarity(title, body)
        return similarity
    else:
        print("Content extraction failed.")

whitelist = pd.read_csv("whitelist.csv")
whitelist["domain"] = whitelist["domain"].str.strip()
whitelist_array = whitelist["domain"].values

# Removing 'www.' prefix from the whitelist domains if present
whitelist_array = np.array([re.sub(r'https?://(www\.)?', '', domain.strip()) for domain in whitelist_array])

def isPresent(url):
    # Removing 'www.' prefix from sitename if present
    url = url.lstrip('www.')
    url = url.lstrip('https?://')

    if url not in whitelist_array:
        return -1
    return 1

def check_top_level_domain_presence(url):
    top_level_domains = ['.org', '.edu', '.gov', '.mil', '.net', '.int', '.gov.in']

    if not url.startswith('http'):
            url = 'https://' + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    for tld in top_level_domains:
        if domain.endswith(tld):
            return 1

    return -1



import pickle

# Load the model using pickle
# with open('sms_model_pickle.pkl', 'rb') as file:
#     model = pickle.load(file)


# # Load SMS classification model
model = load_model('./sms_model5.h5')

def extract_website_content(url):
    if not url.startswith('http'):
        url = 'http://' + url
            
    try:
        response = requests.get(url, timeout=10)
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

# URL Feature Extraction Functions
# (Include all the helper functions here, like age_of_domain, dns_record, etc.)

@app.route('/')
def hello_world():
    return 'Hello World!'



@app.route("/predictdomain", methods=["POST"])
def predict_domain():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')
        if url:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
            pred = "It is {0:.2f} % safe to go ".format(y_pro_non_phishing * 100)
            return jsonify({"prediction": pred, "phishing_probability": y_pro_phishing, "non_phishing_probability": y_pro_non_phishing}), 200
        else:
            return jsonify({"error": "No URL provided"}), 400
    else:
        return jsonify({"error": "Request must be JSON"}), 400

@app.route('/getcontent', methods=['POST'])
def get_content():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')
        if url:
            content = extract_website_content(url)
            if content:
                title, body = extract_title_and_body(content)
                return jsonify({"ok": True, "title": title, "body": body}), 200
            else:
                return jsonify({"ok": False, "error": "Content extraction failed"}), 400
        else:
            return jsonify({"ok": False, "error": "No URL provided"}), 400
    else:
        return jsonify({"ok": False, "error": "Request must be JSON"}), 400


@app.route('/predictsimilarity', methods=['POST'])
def predict_similarity():
    data = request.get_json()
    sitename = data.get('url')
    sitename = re.sub(r'https?://(www\.)?', '', sitename.strip())
    if isPresent(sitename) == 1:
        phish_prob=0
        message = "Domain is safe"
        return jsonify({"phishing_probability": phish_prob, "message": message})
    elif check_top_level_domain_presence(sitename) == 1:
        phish_prob = 0
        message = "Restricted top level domain"
        return jsonify({"phishing_probability": phish_prob, "message": message})
    else:
    #     phish_prob=1-(analyze_website_similarity(sitename))
        model_name = 'bert-base-uncased'
        tokenizer = BertTokenizer.from_pretrained(model_name)
        model = BertModel.from_pretrained(model_name)

        def extract_website_content(url):
            if not url.startswith('http'):
                url = 'http://' + url
            
            try:
                response = requests.get(url, timeout=10)
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

        def get_bert_embedding(text):
            tokens = tokenizer.encode(text, return_tensors='pt', truncation=True, max_length=512)

            with torch.no_grad():
                outputs = model(tokens)
                embeddings = outputs.last_hidden_state.mean(dim=1).squeeze()

            return embeddings

        def check_similarity(title, body):
            title_embedding = get_bert_embedding(title)
            body_embedding = get_bert_embedding(body)

            similarity_score = 1 - cosine(title_embedding, body_embedding)
            return similarity_score

        content = extract_website_content(sitename)

        if content:
            title, body = extract_title_and_body(content)
    #         print(body)
            if title.strip() =="No title found" and body.strip() == "No body found":
               message = 'Title and Body is empty.'
               phish_prob = 1
               return jsonify({"phishing_probability": phish_prob, "message": message})
            elif title.strip() =="No title found":
               message = 'Title is empty.'
               phish_prob = 1
               return jsonify({"phishing_probability": phish_prob, "message": message})
            elif title.strip() ==body.strip() == "No body found":
               message = 'Body is empty.'
               phish_prob = 1
               return jsonify({"phishing_probability": phish_prob, "message": message})

            similarity = check_similarity(title, body)
            # return similarity
            phish_prob = 1 - similarity
            if phish_prob >= 0.5:
                message = "Domain is unsafe"
            else:
                message = "Domain is safe"
            return jsonify({"phishing_probability": phish_prob, "message": message})
        else:
            print("Content extraction failed.")

        

    # if phish_prob>=0.5:
    #     return jsonify({"phishing_probability": phish_prob})
    # else:
    #     return jsonify({"phishing_probablility": phish_prob})

@app.route('/predictcombined', methods=['POST'])
def predict_combined():
    if request.is_json:
        data = request.get_json()
        url = data.get('url')
        if url:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
            pred = y_pro_non_phishing * 100
        
    model_name = 'bert-base-uncased'
    tokenizer = BertTokenizer.from_pretrained(model_name)
    model = BertModel.from_pretrained(model_name)

    # Extracting 'domain' and 'threshold' from the request data
    request_data = request.json
    url = request_data.get('url')
    threshold = request_data.get('threshold', 0.6)  # Default threshold as 0.6 if not provided

    def extract_website_content(url):
        if not url.startswith('http'):
            url = 'https://' + url
        
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

    def get_bert_embedding(text):
        tokens = tokenizer.encode(text, return_tensors='pt', truncation=True, max_length=512)

        with torch.no_grad():
            outputs = model(tokens)
            embeddings = outputs.last_hidden_state.mean(dim=1).squeeze()

        return embeddings

    def check_similarity(title, body):
        title_embedding = get_bert_embedding(title)
        body_embedding = get_bert_embedding(body)

        similarity_score = 1 - cosine(title_embedding, body_embedding)
        return similarity_score

    content = extract_website_content(url)

    if content:
        title, body = extract_title_and_body(content)
        if title.strip() == "No title found" or body.strip() == "No body found":
            similarity = 0

        similarity = check_similarity(title, body) * 100

    non_phishing_probability = ((2 * similarity) + (pred)) / 3
    return jsonify({"non_phishing_probability":non_phishing_probability})
    

@app.route('/predictURL', methods=['POST'])
def predict_url():
    if request.is_json:
        try:
            data = request.get_json()
            print(data)
            classifier = joblib.load('./url_model.sav')
            Sample = extractfeature(data['url'])
            print(Sample)
            df = pd.DataFrame([Sample],columns=['Prefix_suffix_separation','Sub_domains','URL_Length','age_domain','dns_record','domain_registration_length','statistical_report','tiny_url','slashes','dots'])
            prediction = classifier.predict(df)
            print(prediction)
            
            if(prediction[0]==1):
               return jsonify({"ok":True,"detectionResult":1,"score":0.9}), 200
            else:
               return jsonify({"ok":True,"detectionResult":0,"score":0.9}), 200
        except Exception as e:
            print(e)
            return jsonify({"ok":False,"detectionResult":0,"score":0}), 400    
    else:
        print("hello")
        return jsonify({"ok":False,"detectionResult":0,"score":0}), 400


def age_of_domain(domain):
  print("age_of_domain")
  dns = 0
  try:
        domain_name = whois.whois(domain)
  except Exception as e:
        print(e)
        return 1

  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if ((expiration_date is None) or (creation_date is None)):
        return 1
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 2
  else:
      ageofdomain = abs((expiration_date - creation_date).days)
      print(ageofdomain)
      if ((ageofdomain/30) < 6):
        return 1
      else:
        return 0

def domain_registration_length_sub(domain):
    dns = 0
    try:
        domain_name = whois.whois(domain)
    except:
        return 1

    expiration_date = domain_name.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')
    if expiration_date is None:
        return 1
    elif type(expiration_date) is list or type(today) is list :
        return 2             #If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website
    else:
        registration_length = abs((expiration_date - today).days)
        if registration_length / 365 <= 1:
            return 1
        else:
            return 0

def dns_record(domain):
    dns = 0
    try:
        domain_name = whois.whois(domain)
        # print(domain_name)
    except:
        dns = 1

    if dns == 1:
        return 1
    else:
        return dns


def statistical_report(url):
    hostname = url
    h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
    z = int(len(h))
    if z != 0:
        y = h[0][1]
        hostname = hostname[y:]
        h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
        z = int(len(h))
        if z != 0:
            hostname = hostname[:h[0][0]]
    url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
    try:
        ip_address = socket.gethostbyname(hostname)
        ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
    except:
        return 1

    if url_match:
        return 1
    else:
        return 0


def extractfeature(url):
  feature=[]
  seperation_of_protocol = url.split("://")
  seperation_domain_name = seperation_of_protocol[1].split("/",1)
  domain_name=seperation_domain_name[0]


  #Prefix_suffix_separation
  if '-' in domain_name:
    feature.append(1)
  else:
    feature.append(0)

  #Sub_domains
  if domain_name.count('.') < 3:
    feature.append(0)
  elif domain_name.count('.') == 3:
    feature.append(2)
  else:
    feature.append(1)

  #URL_Length
  if len(url) < 54:
    feature.append(0)
  elif len(url) >= 54 and len(url) <= 75:
    feature.append(2)
  else:
    feature.append(1)

  #age_domain
  feature.append(age_of_domain(domain_name))

  #dns_record
  feature.append(dns_record(domain_name))

  #domain_registration_length
  feature.append(domain_registration_length_sub(domain_name))

  #statistical_report
  feature.append(statistical_report(domain_name))

  #tiny_url
  match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
  if match:
      feature.append(1)
  else:
      feature.append(0)
  
  #slashes
  if len(url.split("/"))>5:
    feature.append(1)
  else:
    feature.append(0)

  #dots
  pattern=re.compile(r"\.")
  # matched = re.search(dot_pattern, url)
  if len(pattern.findall(url))>3:
    feature.append(1)
  else:
    feature.append(0)
  
  return feature


@app.route('/predictsms', methods=['POST'])
def predict_sms():
    # Load the dataset
    data = pd.read_csv('./SMS.csv')
    # Map labels to numerical values
    data['LABEL'] = data['LABEL'].map({'Smishing': 1, 'ham': 0})
    data.dropna(subset=['LABEL'], inplace=True)
    data.reset_index(drop=True, inplace=True)
    # Prepare data for training
    X = data['TEXT']
    y = data['LABEL']
    # print(y.unique())

    # Tokenize text
    max_words = 10000  # Define the maximum number of words to keep
    max_length = 200  # Define the sequence length
    tokenizer = Tokenizer(num_words=max_words)
    tokenizer.fit_on_texts(X)
    X_sequences = tokenizer.texts_to_sequences(X)

    
    data = request.json
    new_message = data.get("body")  # Get 'body' from the parsed JSON
    if not new_message:
        return jsonify({'error': 'No message provided'}), 400

    new_message_sequence = tokenizer.texts_to_sequences([new_message])
    new_message_padded = pad_sequences(new_message_sequence, maxlen=max_length)
    prediction = model.predict(new_message_padded)
    predicted_label = np.argmax(prediction)
    label_mapping = {0: 'ham', 1: 'Smishing'}
    predicted_class = label_mapping[predicted_label]
    return jsonify({'prediction': predicted_class})

if __name__ == "__main__":
    app.run()
