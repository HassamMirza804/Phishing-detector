from flask import Flask, render_template, request, jsonify
import joblib
import re
from PyPDF2 import PdfReader
import io

# Load the models
model = joblib.load('url_phish/phishing_model.joblib')
vectorizer = joblib.load('url_phish/phishing_vectorizer.joblib')

text_model = joblib.load('text_phish/phishing_text_model.joblib')
text_vectorizer = joblib.load('text_phish/phishing_text_vectorizer.joblib')

# Create the Flask application
app = Flask(__name__)

def get_url_features(url):
    return re.findall(r'[a-zA-Z0-9]+', url)

def is_url(text):
    return re.match(r'https?://', text) is not None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    text_input = request.form.get('text_input', '')
    
    result = ""
    is_phishing = False
    
    if is_url(text_input):
        input_features = [' '.join(get_url_features(text_input))]
        vectorized_input = vectorizer.transform(input_features)
        prediction = model.predict(vectorized_input)
        if prediction[0] == 1:
            result = "Warning: This appears to be a phishing URL."
            is_phishing = True
        else:
            result = "This appears to be a legitimate URL."
    else:
        input_text_vectorized = text_vectorizer.transform([text_input])
        prediction = text_model.predict(input_text_vectorized)
        if prediction[0] == 1:
            result = "Warning: This appears to be a phishing text message."
            is_phishing = True
        else:
            result = "This appears to be a legitimate text message."
    
    return jsonify(result=result, is_phishing=is_phishing)

@app.route('/upload', methods=['POST'])
def upload():
    if 'pdf_file' not in request.files:
        return jsonify(result="No PDF file was uploaded.", is_phishing=False), 400

    file = request.files['pdf_file']
    if file.filename == '':
        return jsonify(result="No PDF file was selected.", is_phishing=False), 400

    try:
        reader = PdfReader(io.BytesIO(file.read()))
        pdf_text = ""
        for page in reader.pages:
            pdf_text += page.extract_text()
            
        if not pdf_text:
            return jsonify(result="The PDF file is empty or could not be read.", is_phishing=False)
            
        input_text_vectorized = text_vectorizer.transform([pdf_text])
        prediction = text_model.predict(input_text_vectorized)
        if prediction[0] == 1:
            result = "Warning: The text within the PDF appears to be a phishing attempt."
            is_phishing = True
        else:
            result = "The text within the PDF appears to be legitimate."
            
        return jsonify(result=result, is_phishing=is_phishing)
    except Exception as e:
        return jsonify(result=f"An error occurred while processing the PDF: {str(e)}", is_phishing=False), 500

if __name__ == '__main__':
    app.run(debug=True)