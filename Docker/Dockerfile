# Use a Debian-based image for better package compatibility
FROM python:3.9-slim AS builder

# Set working directory
WORKDIR /app

# Install system dependencies needed for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libffi-dev \
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf-2.0-dev \
    libxml2-dev \
    libxslt1-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install mkdocs (if not already in requirements.txt)
RUN pip install mkdocs

# Final lightweight image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies for WeasyPrint and other packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi8 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy installed dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy MkDocs project files
COPY docs /app/docs
COPY mkdocs.yml /app/mkdocs.yml

# Expose MkDocs default port
EXPOSE 8000

# Run MkDocs server
CMD ["mkdocs", "serve", "--dev-addr=0.0.0.0:8000"]
