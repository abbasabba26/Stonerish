FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libxrender1 \
    libxrandr2 \
    libxss1 \
    libgtk-3-0 \
    libgconf-2-4 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create non-root user for security
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

# Create directories for data and results
RUN mkdir -p /app/data /app/results

# Expose port for web interface (if added later)
EXPOSE 8080

# Set environment variables
ENV PYTHONPATH=/app
ENV SCANNER_EXPORT_DIR=/app/results
ENV SCANNER_TEMP_DIR=/app/temp

# Default command
CMD ["python", "enhanced_scanner.py"]
