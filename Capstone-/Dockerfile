FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Run the training script first to generate the dummy model weights (for demonstration)
# In a real scenario, you'd mount a volume with pre-trained weights.
RUN python train.py

# The default command runs the prediction script
CMD ["python", "predict.py"]
