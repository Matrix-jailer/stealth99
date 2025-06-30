# Base image with Python and Chromium support
FROM python:3.10-slim

# Set environment
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y \
    wget curl unzip git \
    libnss3 libatk-bridge2.0-0 libgtk-3-0 libxss1 libasound2 libx11-xcb1 \
    libxcb1 libxcomposite1 libxdamage1 libxrandr2 libgbm-dev \
    chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Install Playwright browsers
RUN playwright install --with-deps

# Copy app files
COPY . /app
WORKDIR /app

# Expose FastAPI port
EXPOSE 8000

# Run the API server
CMD ["uvicorn", "stealth_gateway_api:app", "--host", "0.0.0.0", "--port", "8000"]
