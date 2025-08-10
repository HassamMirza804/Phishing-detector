import streamlit as st
import joblib

# Load your model from the file
model = joblib.load('phishing_model.joblib')

st.title("Phishing URL Detector")
st.write("Enter a URL below to see if it's a phishing attempt.")

# Create an input box for the user
user_input = st.text_input("Enter a URL here:")

if user_input:
    # Get the model's prediction
    prediction = model.predict([user_input])[0]

    # Display the result
    if prediction == 1:
        st.error("This is a phishing URL.")
    else:
        st.success("This URL is likely safe.")