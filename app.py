import streamlit as st
import joblib
import fitz  # PyMuPDF

# Load your model from the file
model = joblib.load('url_phish/phishing_model.joblib')

st.title("Phishing URL & PDF Detector")
st.write("Upload a PDF file to scan its content and links, or enter a URL below to test it.")

# --- URL Scanner ---
st.header("URL Scanner")
user_input = st.text_input("Enter a URL here:")

if st.button("Scan URL"):
    if user_input:
        # Get the model's prediction
        prediction = model.predict([user_input])[0]
        if prediction == 1:
            st.error(f"**{user_input}** is a phishing URL.")
        else:
            st.success(f"**{user_input}** is likely safe.")

# --- PDF Scanner ---
st.header("PDF Scanner")
uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

if uploaded_file:
    # Read the file and process it
    st.write("Scanning PDF...")
    pdf_document = fitz.open(stream=uploaded_file.read(), filetype="pdf")
    
    # Extract text and links
    full_text = ""
    links = []
    for page_num in range(len(pdf_document)):
        page = pdf_document.load_page(page_num)
        full_text += page.get_text()
        links.extend([link for link in page.get_links() if link['kind'] == fitz.LINK_URI])
        
    # Scan the extracted full text
    text_prediction = model.predict([full_text])[0]
    
    st.subheader("Overall PDF Scan")
    if text_prediction == 1:
        st.error("The overall text content of this PDF is suspicious.")
    else:
        st.success("The overall text content of this PDF appears safe.")
        
    # Scan all extracted links
    if links:
        st.subheader("Links Found in PDF")
        for link in links:
            url = link['uri']
            link_prediction = model.predict([url])[0]
            if link_prediction == 1:
                st.error(f"**PHISHING LINK DETECTED:** {url}")
            else:
                st.write(f"**SAFE LINK:** {url}")
    else:
        st.write("No links were found in this PDF.")