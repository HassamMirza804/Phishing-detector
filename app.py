import os
import io
import re
from urllib.parse import urlparse, parse_qs
from flask import Flask, request, jsonify, render_template
import PyPDF2
from PIL import Image
import pytesseract

# You may need to set the path to your Tesseract executable
# If it's not in your system's PATH.
# Example for Windows: pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

app = Flask(__name__)

# --- Heuristic and Safe Browse Functions ---
def is_heuristically_phishing(url):
    phishing_keywords = ['login', 'verify', 'account', 'security', 'update', 'signin', 'webscr', 'password']
    suspicious_tlds = ['.online', '.xyz', '.site', '.live', '.info', '.top', '.co']
    url = url.lower()
    suspiciousness_score = 0
    reasons = []

    path = urlparse(url).path
    if any(keyword in path for keyword in phishing_keywords):
        suspiciousness_score += 1
        reasons.append("Path contains a suspicious keyword.")

    domain = urlparse(url).netloc
    if any(keyword in domain for keyword in phishing_keywords):
        suspiciousness_score += 1
        reasons.append("Domain contains a suspicious keyword.")

    # Check for IP address in domain
    if all(c.isdigit() or c == '.' for c in domain) and domain.count('.') == 3:
        suspiciousness_score += 1
        reasons.append("Domain is an IP address.")

    if len(url) > 75:
        suspiciousness_score += 1
        reasons.append("URL is unusually long.")

    tld = domain.split('.')[-1]
    if tld in suspicious_tlds:
        suspiciousness_score += 1
        reasons.append("URL uses a suspicious TLD.")

    if any(str(year) in domain for year in range(2020, 2030)):
        suspiciousness_score += 1
        reasons.append("Domain contains a year that may be used to feign legitimacy.")

    query_params = parse_qs(urlparse(url).query)
    if 'utm_source' in query_params or 'utm_medium' in query_params or 'gclid' in query_params:
        suspiciousness_score += 1
        reasons.append("URL contains suspicious tracking parameters.")
    
    if domain.count('.') > 3:
        suspiciousness_score += 1
        reasons.append("URL has too many subdomains, a common phishing tactic.")

    is_phishing = suspiciousness_score > 0
    reason_string = ", ".join(reasons) if reasons else "No heuristic indicators of phishing found."
    
    return is_phishing, reason_string, suspiciousness_score

def is_safe_browse_safe(url):
    phishing_database = [
        "secure-bank.co",
        "moradacerta.site",
        "consultefinanceiro.services"
    ]
    domain = urlparse(url).netloc
    if domain in phishing_database:
        return "Unsafe: The URL is in the phishing database.", 100
    return "Safe: The URL is not in the phishing database.", 0

def find_urls_in_text(text):
    url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def analyze_urls_from_text(text):
    urls = find_urls_in_text(text)
    if not urls:
        return [{
            "url": "No URLs found", 
            "heuristic_check": {"result": "N/A", "reason": ""}, 
            "safe_browse_check": "N/A", 
            "accuracy_percentage": "0.00%"
        }]

    results = []
    MAX_HEURISTIC_SCORE = 8

    for url in set(urls):
        is_phishing, heuristic_reason, heuristic_score = is_heuristically_phishing(url)
        safe_browse_result, safe_browse_score = is_safe_browse_safe(url)
        
        # Calculate the overall accuracy score
        if safe_browse_score == 100:
            accuracy_score = 100.0
        else:
            accuracy_score = (heuristic_score / MAX_HEURISTIC_SCORE) * 100
        
        results.append({
            "url": url,
            "heuristic_check": {
                "result": "Suspicious" if is_phishing else "Safe",
                "reason": heuristic_reason
            },
            "safe_browse_check": safe_browse_result,
            "accuracy_percentage": f"{accuracy_score:.2f}%"
        })
    return results

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'url' in request.form:
        url = request.form['url']
        results = analyze_urls_from_text(url)
        print(f"Prediction Results: {results}")
        return jsonify(results)
    
    if 'text_input' in request.form:
        text = request.form['text_input']
        results = analyze_urls_from_text(text)
        print(f"Prediction Results: {results}")
        return jsonify(results)
    
    if 'file' in request.files:
        file = request.files['file']
        file_content = file.read()
        
        all_urls = []
        text_content = ""

        if file.filename.endswith('.pdf'):
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(file_content))
                for page in reader.pages:
                    text_content += page.extract_text() or ""
                all_urls.extend(find_urls_in_text(text_content))
                
                for page_num in range(len(reader.pages)):
                    page = reader.pages[page_num]
                    if '/XObject' in page['/Resources']:
                        xobjects = page['/Resources']['/XObject'].get_object()
                        for obj in xobjects:
                            if xobjects[obj]['/Subtype'] == '/Image':
                                try:
                                    image_data = xobjects[obj].get_data()
                                    image = Image.open(io.BytesIO(image_data))
                                    text_from_image = pytesseract.image_to_string(image)
                                    all_urls.extend(find_urls_in_text(text_from_image))
                                except Exception as e:
                                    print(f"Could not process image: {e}")
                                    continue

            except PyPDF2.errors.PdfReadError:
                return jsonify({"error": "Invalid PDF file"}), 400
        else: # For .txt files
            text_content = file_content.decode('utf-8', errors='ignore')
            all_urls.extend(find_urls_in_text(text_content))

        if not all_urls:
            return jsonify([{"url": "No URLs found", 
                             "heuristic_check": {"result": "N/A", "reason": ""}, 
                             "safe_browse_check": "N/A", 
                             "accuracy_percentage": "0.00%"}])

        results = []
        MAX_HEURISTIC_SCORE = 8

        for url in set(all_urls):
            is_phishing, heuristic_reason, heuristic_score = is_heuristically_phishing(url)
            safe_browse_result, safe_browse_score = is_safe_browse_safe(url)
            
            if safe_browse_score == 100:
                accuracy_score = 100.0
            else:
                accuracy_score = (heuristic_score / MAX_HEURISTIC_SCORE) * 100
            
            results.append({
                "url": url,
                "heuristic_check": {
                    "result": "Suspicious" if is_phishing else "Safe",
                    "reason": heuristic_reason
                },
                "safe_browse_check": safe_browse_result,
                "accuracy_percentage": f"{accuracy_score:.2f}%"
            })
        
        print(f"Prediction Results: {results}")
        return jsonify(results)
    
    return jsonify({"error": "Invalid request. Please provide a URL, text, or a file."}), 400

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)