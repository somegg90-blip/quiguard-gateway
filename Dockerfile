FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y gcc python3-dev

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download the Spacy model (Crucial for offline/air-gapped use)
RUN python -m spacy download en_core_web_sm

# Copy the application code
COPY app ./app
COPY policy.yaml .

# Expose the port
EXPOSE 8000

# Run the server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]