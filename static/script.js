document.addEventListener('DOMContentLoaded', () => {
    const urlForm = document.getElementById('url-form');
    const textForm = document.getElementById('text-form');
    const fileForm = document.getElementById('file-form');

    const loadingSpinner = document.getElementById('loading');
    const resultsContainer = document.getElementById('results-container');

    urlForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const formData = new FormData(urlForm);
        await sendData(formData);
    });

    textForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const textInput = document.getElementById('text-input').value;
        if (!textInput.trim()) {
            alert("Please paste text to analyze.");
            return;
        }
        const formData = new FormData(textForm);
        await sendData(formData);
    });

    fileForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        const fileInput = document.getElementById('file-input').files[0];
        if (!fileInput) {
            alert("Please select a file to analyze.");
            return;
        }
        const formData = new FormData(fileForm);
        await sendData(formData);
    });

    async function sendData(formData) {
        resultsContainer.innerHTML = '<h2>Analysis Results</h2>';
        resultsContainer.classList.add('hidden');
        loadingSpinner.classList.remove('hidden');

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            
            loadingSpinner.classList.add('hidden');
            resultsContainer.classList.remove('hidden');

            if (data.error) {
                resultsContainer.innerHTML += `<p class="error">${data.error}</p>`;
                return;
            }

            // New logic to determine if a scan is clean or not
            let isSuspicious = false;
            if (data.length > 0 && data[0].url !== "No URLs found") {
                data.forEach(result => {
                    if (result.heuristic_check.result === 'Suspicious' || result.safe_Browse_check.startsWith('Unsafe')) {
                        isSuspicious = true;
                    }
                });
            }

            const resultDiv = document.createElement('div');
            resultDiv.classList.add('result-item');

            // Determine the scan type and display the appropriate message
            if (formData.has('url')) {
                if (isSuspicious) {
                    resultDiv.innerHTML = `<p class="phishing">🔴 Phishing link found with red alerts</p>`;
                } else {
                    resultDiv.innerHTML = `<p class="safe">🟢 Safe link found with green safe sign</p>`;
                }
            } else if (formData.has('text_input')) {
                if (isSuspicious) {
                    resultDiv.innerHTML = `<p class="phishing">🔴 Spam text with red alerts</p>`;
                } else {
                    resultDiv.innerHTML = `<p class="safe">🟢 Not spam with green safe sign</p>`;
                }
            } else if (formData.has('file')) {
                if (isSuspicious) {
                    resultDiv.innerHTML = `<p class="phishing">🔴 File is injected or suspicious links found</p>`;
                } else {
                    resultDiv.innerHTML = `<p class="safe">🟢 File is clean</p>`;
                }
            }

            resultsContainer.appendChild(resultDiv);

        } catch (error) {
            console.error('Error:', error);
            loadingSpinner.classList.add('hidden');
            resultsContainer.innerHTML = `<p class="error">An error occurred while analyzing the data.</p>`;
        }
    }
});