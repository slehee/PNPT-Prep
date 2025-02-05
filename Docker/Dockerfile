# Use Python as the base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Copy the MkDocs project files from the parent directory
COPY ../docs /app/docs
COPY ../mkdocs.yml /app/mkdocs.yml
COPY ../requirements.txt /app/requirements.txt

# Install all required Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose MkDocs' default port
EXPOSE 8000

# Start the MkDocs server
CMD ["mkdocs", "serve", "--dev-addr=0.0.0.0:8000"]
