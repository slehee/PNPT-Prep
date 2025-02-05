# 📖 Linux Privilege Escalation Docs

Welcome to the **Linux Privilege Escalation Documentation**, powered by **MkDocs**.

This project provides:
- A structured **knowledge base** for Linux privilege escalation techniques.
- A repository of **scripts and tools** for enumeration and exploitation.
- A **self-hosted MkDocs site** in Docker for quick access and search.

For full MkDocs documentation, visit **[mkdocs.org](https://www.mkdocs.org)**.

---

## 🛠️ MkDocs Quick Commands
Use the following commands to manage the documentation:

| Command | Description |
|---------|------------|
| `mkdocs new [dir-name]` | Create a new MkDocs project. |
| `mkdocs serve` | Start a live-reloading development server. |
| `mkdocs build` | Generate a static site in the `site/` directory. |
| `mkdocs -h` | Show help and options. |

To serve the MkDocs site locally, run:
```sh
mkdocs serve



📌 Cloning the Repository

To get started with this project:

git clone https://github.com/slehee/Linux-PrivEsc.git
cd Linux-PrivEsc

📌 Making Changes

    Create a new branch:

git checkout -b feature-update

Make your changes, then commit:

git add .
git commit -m "Updated documentation"

Push to GitHub:

    git push origin feature-update

    Open a Pull Request (PR) in GitHub.

🐳 Running MkDocs in Docker

If you prefer using Docker, you can run the MkDocs server inside a container:

docker-compose up --build

or manually:

cd Linux-PrivEsc

docker build -t linux-privesc-docs -f Docker/Dockerfile .
docker run -d -p 8000:8000 linux-privesc-docs

Then, visit http://localhost:8000.

Or you can pull down the image : `docker pull ghcr.io/slehee/linux-privesc:latest` then run `docker run -d -p 8000:8000 --name priv ghcr.io/slehee/linux-privesc 
`
