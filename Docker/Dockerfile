# Use a lightweight base image
FROM python:3.14.0rc1-alpine AS builder

# Set working directory
WORKDIR /app

# Install necessary build tools and dependencies
RUN apk add --no-cache \
    gcc g++ make musl-dev libffi-dev \
    pango gdk-pixbuf cairo gobject-introspection-dev

# Copy and install Python dependencies
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install mkdocs
RUN pip install mkdocs

# Final lightweight image
FROM python:3.14.0rc1-alpine

# Set working directory
WORKDIR /app

# Install runtime dependencies for WeasyPrint
RUN apk add --no-cache \
    pango gdk-pixbuf cairo gobject-introspection

# Copy installed dependencies from builder stage
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy MkDocs project files
COPY ./docs /app/docs
COPY ./mkdocs.yml /app/mkdocs.yml

# Expose MkDocs default port
EXPOSE 8000

# Run MkDocs server
CMD ["mkdocs", "serve", "--dev-addr=0.0.0.0:8000"]
