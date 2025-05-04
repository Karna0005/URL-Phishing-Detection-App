from datetime import date
import ipaddress
import re
import socket
from altair import Url
import streamlit as st
import pickle
import numpy as np
import requests
from bs4 import BeautifulSoup
import urllib3
import whois
from urllib.parse import urlparse
from googlesearch import search
import joblib


class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None
        self.features = []

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
            self.whois_response = whois.whois(self.domain)
        except:
            pass

    def extract_features(self):
        self.features.append(self.using_ip())
        self.features.append(self.long_url())
        self.features.append(self.short_url())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefix_suffix())
        self.features.append(self.sub_domains())
        self.features.append(self.HTTPS())
        self.features.append(self.domain_reg_len())
        self.features.append(self.favicon())
        self.features.append(self.non_std_port())
        self.features.append(self.https_domain_url())
        self.features.append(self.request_url())
        self.features.append(self.anchor_url())
        self.features.append(self.links_in_script_tags())
        self.features.append(self.server_form_handler())
        self.features.append(self.info_email())
        self.features.append(self.abnormal_url())
        self.features.append(self.website_forwarding())
        self.features.append(self.status_bar_cust())
        self.features.append(self.disable_right_click())
        self.features.append(self.using_popup_window())
        self.features.append(self.iframe_redirection())
        self.features.append(self.age_of_domain())
        self.features.append(self.dns_recording())
        self.features.append(self.website_traffic())
        self.features.append(self.page_rank())
        self.features.append(self.google_index())
        self.features.append(self.links_pointing_to_page())
        self.features.append(self.stats_report())

        return self.features

    def using_ip(self):
        try:
            ipaddress.ip_address(self.urlparse.netloc)
            return -1
        except:
            return 1

        # 2.longUrl
    def long_url(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def short_url(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1


    def symbol(self):
        if '@' in self.url:
            return -1
        return 1

    def redirecting(self):
        if self.url.count('//') > 1:
            return -1
        return 1

    def prefix_suffix(self):
        if '-' in self.domain:
            return -1
        return 1

    def sub_domains(self):
        if self.urlparse.netloc.count('.') <= 1:
            return 1
        elif self.urlparse.netloc.count('.') == 2:
            return 0
        return -1

    def HTTPS(self):
        if self.urlparse.scheme == 'https':
            return 1
        return -1

    def domain_reg_len(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date

            if expiration_date is not None and creation_date is not None:
                age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
                if age >= 12:
                    return 1
            return -1
        except:
            return -1

    def favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if 'icon' in link['href']:
                    if self.url in link['href'] or self.domain in link['href'] or len(link['href'].split('.')) == 1:
                        return 1
            return -1
        except:
            return -1

    def non_std_port(self):
        if ':' in self.urlparse.netloc:
            return -1
        return 1

    def https_domain_url(self):
        if 'https' in self.urlparse.netloc:
            return -1
        return 1

    def request_url(self):
        try:
            success, total = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for item in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.domain in item['src'] or self.urlparse.netloc in item['src']:
                        success += 1
            if total == 0:
                return -1
            percentage = (success / total) * 100
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            else:
                return -1
        except:
            return -1

    def anchor_url(self):
        try:
            unsafe_count, total = 0, 0
            for a in self.soup.find_all('a', href=True):
                total += 1
                if '#' in a['href'] or 'javascript' in a['href'].lower() or 'mailto' in a['href'].lower() \
                        or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe_count += 1
            if total == 0:
                return -1
            percentage = (unsafe_count / total) * 100
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            else:
                return -1
        except:
            return -1

    def links_in_script_tags(self):
        try:
            total, success = 0, 0
            for tag in ['link', 'script']:
                for item in self.soup.find_all(tag, href=True):
                    total += 1
                    if self.domain in item['href'] or self.urlparse.netloc in item['href']:
                        success += 1
            if total == 0:
                return -1
            percentage = (success / total) * 100
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1
        except:
            return -1

    def server_form_handler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1
            for form in forms:
                action = form['action'].strip()
                if action == '' or action.lower() == 'about:blank':
                    return -1
                elif self.domain not in action and self.urlparse.netloc not in action:
                    return 0
            return 1
        except:
            return -1

    def info_email(self):
        try:
            if re.findall(r"[\w\.-]+@[\w\.-]+", self.response.text):
                return -1
            else:
                return 1
        except:
            return -1

    def abnormal_url(self):
        try:
            if self.response.text == self.whois_response.text:
                return 1
            else:
                return -1
        except:
            return -1

    def website_forwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif 1 < len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
            return -1

    def status_bar_cust(self):
        try:
            if re.findall(r"<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def disable_right_click(self):
        try:
            if re.findall(r"event\.button\s?==\s?2", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def using_popup_window(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def iframe_redirection(self):
        try:
            if re.findall(r"<iframe>|<frameBorder>", self.response.text):
                return 1
            else:
                return -1
        except:
            return -1

    def age_of_domain(self):
        try:
            creation_date = self.whois_response.creation_date
            if creation_date:
                today = date.today()
                age = (today.year - creation_date.year) * 12 + (today.month - creation_date.month)
                if age >= 6:
                    return 1
            return -1
        except:
            return -1

    def dns_recording(self):
        try:
            return self.age_of_domain()  # Same logic as age_of_domain
        except:
            return -1

    def website_traffic(self):
        try:
            rank = BeautifulSoup(urllib3.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={self.url}").read(), "xml").find("REACH")['RANK']
            if int(rank) < 100000:
                return 1
            return 0
        except:
            return -1

    def page_rank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", prank_checker_response.text)[0])
            if 0 < global_rank < 100000:
                return 1
            return -1
        except:
            return -1

    def google_index(self):
        try:
            results = list(search(self.url, num=1, stop=1, pause=2))
            if results:
                return 1
            else:
                return -1
        except:
            return 1

    def links_pointing_to_page(self):
        try:
            num_links = len(re.findall(r"<a href=", self.response.text))
            if num_links == 0:
                return 1
            elif num_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    def stats_report(self):
        try:
            url_match = re.search( r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', Url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1


def main():

    
    st.title("Phishing Detection ")
    input_url = st.text_input(" Enter The URL With HTTP/HTTPS & WWW ")

    if st.button('Predict'):
        # Extract features from the input URL
        fe = FeatureExtraction(input_url)
        features = fe.extract_features()

        # Load the trained Random Forest model
        rfc = pickle.load(open('XGboost.pkl', 'rb'))

        # Make prediction with the Random Forest model
        rfc_prediction = rfc.predict([features])[-1]  # Corrected indexing

        # Print the prediction
        if rfc_prediction == 1:
            st.header("The URL Is Not Phishing")
        else:
            st.header("The URL Is Phishing")

if __name__ == "__main__":
    main()


import json
import os
import streamlit as st
from streamlit_lottie import st_lottie

import streamlit as st
from streamlit_option_menu import option_menu

# Define the function to display the paragraph about the author
def show_about_paragraph():
    st.title("About")
    st.write("""
    Intrusion Detection System is a project that came into existence from a final year project Detection of Phishing Website.
    Using Machine Learning.
    """)

import streamlit as st

def show_reference_read():
    # Define FAQ list
    faq_list = [
        {"question": "Domain", "answer": "Domain name system e.g facebook.com, bowen.edu.ng"},
        {"question": "Have_IP", "answer": "If an IP address is used as an alternative of the domain name in the URL, such as 'http://125.98.3.123/fake.html'"},
        {"question": "Have_AT", "answer": "Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol"},
        {"question": "URL_Length", "answer": "URL length<54 → feature=Legitimate@ else if URL length≥54 and ≤75 → feature=Suspicious @otherwise→ feature=Phishing"},
        {"question": "URL_Depth", "answer": "Let us assume we have the following link: http://www.hud.ac.uk/students/.) the .ac, .uk, /students are subdomains. Also, if the number of dots is greater than one, then the URL is classified as “Suspicious” since it has one sub domain. However, if the dots are greater than two, it is classified as “Phishing” since it will have multiple sub domains"},
        {"question": "Redirection", "answer": "a legitimate websites will be redirected one time max. On the other hand, phishing websites containing this feature have been redirected at least 4 times."},
        {"question": "HTTP_Domain", "answer": "The existence of HTTPS is very important in giving the impression of website legitimacy that is if a Website has Https or not"},
        {"question": "Tiny_URL", "answer": "it means a domain name that is short, which links to the webpage that has a long URL. For example, the URL “http://portal.hud.ac.uk/” can be shortened to “bit.ly/19DXSk4”.} which can be Phishing"},
        {"question": "Prefix/Suffix", "answer": "Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. For example http://www.Confirme-paypal.com/"},
        {"question": "DNS_Record", "answer": "If the DNS record is empty or not found then the website is classified as “Phishing”, otherwise it is classified as “Legitimate”."},
        {"question": "Web_Traffic", "answer": "If the DNS record is empty or not found then the website is classified as “Phishing”, otherwise it is classified as “Legitimate”. if the domain has no traffic or is not recognized by the Alexa database, it is classified as “Phishing”. Otherwise, it is classified as “Suspicious"},
        {"question": "Domain_Age", "answer": "Most phishing websites live for a short period of time. By reviewing our dataset, we find that the minimum age of the legitimate domain is 6 months. } (Age Of Domain≥6 months → Legitimate@Otherwise → Phishing)"},
        {"question": "Domain_End", "answer": "(Domain Registration Length) █(Domains Expires on≤ 1 years → Phishing@Otherwise→ Legitimate)"},
        {"question": "iFrame", "answer": "IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible } {(Using iframe→ Phishing@Otherwise → Legitimate)"},
        {"question": "Mouse_Over", "answer": "{Phishers may use JavaScript to show a fake URL in the status bar to users. To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event, and check if it makes any changes on the status bar. } Rule: IF{█(onMouseOver Changes Status Bar→ Phishing@It Does't Change Status Bar→Legitimate)"},
        {"question": "Right_Click", "answer": "Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled. Rule: IF{(Right Click Disabled → Phishing @Otherwise→Legitimate)"},
        {"question": "Web_Forwards", "answer": "Submitting Information to Email Web form allows a user to submit his personal information that is directed to a server for processing. A phisher might redirect the users information to his personal email. To that end, a server-side script language might be used such as mail() function in PHP. One more client-side function that might be used for this purpose is the mailto: function. (Using mail()\ or \mailto:\ Function to Submit User Information → Phishing@Otherwise → Legitimate)"}
    ]

    # Display FAQ list
    st.title("Reference")

    for faq in faq_list:
        with st.expander(faq["question"]):
            st.write(faq["answer"])

# Call the function to display the FAQ list
#show_reference_read()



with st.sidebar:
    selected = option_menu("Main Menu", ["Home", "About", "Reference"], 
        icons=['house', 'person', 'book'], menu_icon="cast", default_index=0)

# Check the selected option and show the corresponding content
if selected == "Home":
    # Display the Lottie animation
    st.write("")
elif selected == "About":
    # Display the paragraph about the author
    show_about_paragraph()
elif selected == "Reference":
    # Display the paragraph about the author
    show_reference_read()    

    

# Function to load Lottie animation from a JSON file
def load_lottiefile(filepath: str):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        st.error(f"File '{filepath}' not found.")
    except json.JSONDecodeError:
        st.error(f"Error decoding JSON file '{filepath}'.")

# File path to the Lottie animation JSON file
file_path = "phishing-detection-streamlit-app-main/lottie animation.json"

# Streamlit app title
#st.title("Lottie Animation")

# Load the Lottie animation file
lottie_coding = load_lottiefile(file_path)

# Display the Lottie animation using st_lottie
if lottie_coding is not None:
    st_lottie(lottie_coding, speed=1, loop=True, quality="medium")
else:
    st.error("Failed to load Lottie animation.")


def markdown_center(text):
    return f'<div style="text-align: center;">{text}</div>'

# Your Streamlit app content goes here

# Add centered markdown text
st.markdown(markdown_center("Project by Karunakar S"), unsafe_allow_html=True)    
