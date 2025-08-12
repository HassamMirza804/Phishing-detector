# 🛡️ Phishing Detector

A real-time web application to identify and mitigate phishing threats in URLs, text, and files.

---

### 🎥 Demo Video



---

### ✨ Features

* **URL Scanning**: Analyzes public and private URLs for suspicious keywords and structures.
* **Text Analysis**: Scans text from emails or messages to identify embedded phishing links.
* **File Scanning**: Processes `.txt` and `.pdf` files, using OCR to extract and analyze URLs, including those in images.
* **Deployment**: Hosted on Render for continuous availability and easy access.

---

### ⚙️ Technologies Used

* **Backend**: Python, Flask
* **Models**: Heuristic analysis, predefined phishing database
* **File Processing**: PyPDF2, pytesseract (OCR)
* **Deployment**: Render
* **Frontend**: HTML, CSS, JavaScript

---

### 🚀 Getting Started

To run this application locally, follow these steps:

1.  **Clone the repository**:
    ```sh
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    cd your-repo-name
    ```

2.  **Install the dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3.  **Run the Flask application**:
    ```sh
    gunicorn app:app
    ```
    The application will be accessible at `http://localhost:5000`.
