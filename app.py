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

app = Flask(_name_)

# --- Heuristic and Safe Browse Functions ---
def is_heuristically_phishing(url):
    phishing_keywords = ['login', 'verify', 'account', 'security', 'update', 'signin', 'webscr', 'password']
    suspicious_tlds = ['.online', '.xyz', '.site', '.live', '.info', '.top', '.co']
    url = url.lower()
    
    path = urlparse(url).path
    if any(keyword in path for keyword in phishing_keywords):
        return True, "Path contains a suspicious keyword."

    domain = urlparse(url).netloc
    if any(keyword in domain for keyword in phishing_keywords):
        return True, "Domain contains a suspicious keyword."

    if any(c.isdigit() for c in domain.replace('.', '')) and domain.replace('.', '').isdigit():
        return True, "Domain is an IP address."

    if len(url) > 75:
        return True, "URL is unusually long."

    tld = domain.split('.')[-1]
    if tld in suspicious_tlds:
        return True, "URL uses a suspicious TLD."

    if any(str(year) in domain for year in range(2020, 2030)):
        return True, "Domain contains a year that may be used to feign legitimacy."

    query_params = parse_qs(urlparse(url).query)
    if 'utm_source' in query_params or 'utm_medium' in query_params or 'gclid' in query_params:
        return True, "URL contains suspicious tracking parameters."
    
    if domain.count('.') > 3:
        return True, "URL has too many subdomains, a common phishing tactic."

    return False, "No heuristic indicators of phishing found."

def is_safe_Browse_safe(url):
    phishing_database = [
        "secure-bank.co",
        "moradacerta.site",
        "consultefinanceiro.services"
    ]
    domain = urlparse(url).netloc
    if domain in phishing_database:
        return "Unsafe: The URL is in the phishing database."
    return "Safe: The URL is not in the phishing database."

def find_urls_in_text(text):
    url_pattern = r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def analyze_urls_from_text(text):
    urls = find_urls_in_text(text)
    if not urls:
        return [{"url": "No URLs found", "heuristic_check": {"result": "N/A", "reason": ""}, "safe_Browse_check": "N/A"}]

    results = []
    for url in urls:
        heuristic_result, heuristic_reason = is_heuristically_phishing(url)
        safe_Browse_result = is_safe_Browse_safe(url)
        results.append({
            "url": url,
            "heuristic_check": {
                "result": "Suspicious" if heuristic_result else "Safe",
                "reason": heuristic_reason
            },
            "safe_Browse_check": safe_Browse_result
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
        return jsonify(results)
    
    if 'text_input' in request.form:
        text = request.form['text_input']
        results = analyze_urls_from_text(text)
        return jsonify(results)
    
    if 'file' in request.files:
        file = request.files['file']
        file_content = file.read()
        
        all_urls = []
        text_content = ""

        # Use PyPDF2 to extract text from the PDF text layer
        if file.filename.endswith('.pdf'):
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(file_content))
                for page in reader.pages:
                    text_content += page.extract_text() or ""
                all_urls.extend(find_urls_in_text(text_content))
                
                # *NEW: Logic to handle images and OCR*
                for page_num in range(len(reader.pages)):
                    page = reader.pages[page_num]
                    # This is a simplified way to check for images; more robust methods exist
                    if '/XObject' in page['/Resources']:
                        xobjects = page['/Resources']['/XObject'].get_object()
                        for obj in xobjects:
                            if xobjects[obj]['/Subtype'] == '/Image':
                                try:
                                    image_data = xobjects[obj].get_data()
                                    image = Image.open(io.BytesIO(image_data))
                                    # Use pytesseract to perform OCR on the image
                                    text_from_image = pytesseract.image_to_string(image)
                                    all_urls.extend(find_urls_in_text(text_from_image))
                                except Exception as e:
                                    # Handle cases where image format isn't supported by Pillow
                                    print(f"Could not process image: {e}")
                                    continue

            except PyPDF2.errors.PdfReadError:
                return jsonify({"error": "Invalid PDF file"}), 400
        else: # For .txt files
            text_content = file_content.decode('utf-8', errors='ignore')
            all_urls.extend(find_urls_in_text(text_content))

        # *NEW: Analyze all collected URLs at once*
        if not all_urls:
            return jsonify([{"url": "No URLs found", "heuristic_check": {"result": "N/A", "reason": ""}, "safe_Browse_check": "N/A"}])

        results = []
        for url in set(all_urls): # Use set to avoid duplicate URLs
            heuristic_result, heuristic_reason = is_heuristically_phishing(url)
            safe_Browse_result = is_safe_Browse_safe(url)
            results.append({
                "url": url,
                "heuristic_check": {
                    "result": "Suspicious" if heuristic_result else "Safe",
                    "reason": heuristic_reason
                },
                "safe_Browse_check": safe_Browse_result
            })
        
        return jsonify(results)
    
    return jsonify({"error": "Invalid request. Please provide a URL, text, or a file."}), 400

if _name_ == '_main_':
    app.run(debug=True)