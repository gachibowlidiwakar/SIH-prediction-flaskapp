from flask import Flask,jsonify,request
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


app = Flask(__name__)
CORS(app)

@app.route('/')
def hello_world():
    print("hello")
    return 'Hello World!'

@app.route('/Predict', methods=['POST'])
def Predict():
    if request.is_json:
        try:
            data = request.get_json()
            print(data)
            classifier = joblib.load('model.sav')
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

if __name__ == "__main__":
    app.run()
