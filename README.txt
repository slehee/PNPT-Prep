# 📖 Linux Privilege Escalation Docs

Welcome to the **Linux Privilege Escalation Documentation**, powered by **MkDocs**.

This project provides:
- A structured **knowledge base** for Linux privilege escalation techniques based on TCM academy course.
- Links to repository of **scripts and tools** for enumeration and exploitation.
- A **self-hosted MkDocs site** in Docker for quick access and search.

🐳 Running MkDocs in Docker

 Run the MkDocs server inside a container:

docker-compose up --build

or manually:

cd Linux-PrivEsc

docker build -t linux-privesc-docs -f Docker/Dockerfile .
docker run -d -p 8000:8000 linux-privesc-docs

Then, visit http://localhost:8000.

Or you can pull down the image : `docker pull ghcr.io/slehee/linux-privesc:latest` 

then run `docker run -d -p 8000:8000 --name priv ghcr.io/slehee/linux-privesc`
