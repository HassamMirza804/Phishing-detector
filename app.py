import streamlit as st
import joblib
from PyPDF2 import PdfReader
import io

# Load your model from the file
model = joblib.load('url_phish/phishing_model.joblib')

st.title("Phishing URL & PDF Detector")
st.write("Upload a PDF file to scan its content, or enter a URL below to test it.")

# --- URL Scanner ---
st.header("URL Scanner")
user_input = st.text_input("Enter a URL here:")

if st.button("Scan URL"):
    if user_input:
        prediction = model.predict([user_input])[0]
        if prediction == 1:
            st.error(f"**{user_input}** is a phishing URL.")
        else:
            st.success(f"**{user_input}** is likely safe.")

# --- PDF Scanner ---
st.header("PDF Scanner")
uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

if uploaded_file:
    st.write("Scanning PDF...")
    
    # Read the file and process it with PyPDF2
    pdf_reader = PdfReader(io.BytesIO(uploaded_file.read()))
    full_text = ""
    for page in pdf_reader.pages:
        full_text += page.extract_text()
        
    # Scan the extracted full text
    text_prediction = model.predict([full_text])[0]
    
    st.subheader("Overall PDF Scan")
    if text_prediction == 1:
        st.error("The overall text content of this PDF is suspicious.")
    else:
        st.success("The overall text content of this PDF appears safe.")