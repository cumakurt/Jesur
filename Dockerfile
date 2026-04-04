# JESUR - Enhanced SMB Share Scanner Docker Image
FROM python:3.9-slim

# Set metadata
LABEL maintainer="cumakurt"
LABEL description="Professional Penetration Testing Tool for SMB Share Discovery and Analysis"
LABEL version="2.1.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libmagic-dev \
    file \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create output directory for downloads and reports
RUN mkdir -p /app/out_download /app/reports

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Default command
ENTRYPOINT ["python3", "Jesur.py"]
CMD ["--help"]

