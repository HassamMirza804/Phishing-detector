# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code to the working directory
COPY . .

# Expose the port Gunicorn will listen on
EXPOSE 8000

# Run gunicorn to serve the app when the container starts
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]