# 🔥 Firegod AI

Autonomous bug bounty hunting and OSINT agent powered by a local Ollama LLM. Runs entirely in Docker on Kali Linux.

## Features

- **⚡ Pentest** — Nmap, Nikto, SQLMap, Gobuster, Hydra, WFuzz, Nuclei, Dalfox
- **🧠 AI Assistant** — Chat with local Ollama LLM (qwen2.5:7b-instruct) with tool use
- **💰 Bug Bounty** — Auto-scan HackerOne / Bugcrowd / Intigriti targets, SSE streaming results
- **🔍 Shodan** — AI-driven Shodan search and host recon via natural language
- **🌐 Translate** — Upload any file (Excel, Word, PDF, PowerPoint, CSV, TXT) → auto-detect language → translate to English via Ollama → download ZIP
- **🕵️ OSINT** — theHarvester, Sherlock, holehe, maigret, h8mail, Photon, gowitness
- **📡 CVE Feed** — Live NIST NVD critical CVE ingestion on startup

## Requirements

- Docker Desktop
- [Ollama](https://ollama.ai) running on the host with `OLLAMA_HOST=0.0.0.0`
- Shodan API key (optional)

## Quick Start

```bash
# 1. Clone
git clone https://github.com/Firegod1991/firegod-ai.git
cd firegod-ai

# 2. Copy env and add your keys
cp .env.example .env

# 3. Start Ollama on host (Windows PowerShell)
$env:OLLAMA_HOST = "0.0.0.0"
ollama serve
ollama pull qwen2.5:7b-instruct

# 4. Build and run
docker compose up --build -d

# 5. Open
start http://localhost:5000
```

## One-Command Startup (Windows)

Add to your PowerShell profile then just type `firegod`:

```powershell
function firegod { & 'C:\local-agent\firegod.ps1' }
```

## Environment Variables

| Variable | Description |
|---|---|
| `OLLAMA_URL` | Ollama API endpoint (default: `http://host.docker.internal:11434/api/chat`) |
| `MODEL` | Ollama model name (default: `qwen2.5:7b-instruct`) |
| `SHODAN_API_KEY` | Your Shodan API key |
| `SEARX_URL` | SearXNG search endpoint (auto-configured via compose) |

## File Translation

Go to the **🌐 Translate** tab, drop in files up to 2 GB — Excel, Word, PowerPoint, PDF, CSV, plain text. Detects language, translates to English via Ollama, download as ZIP.

## Legal

Only test systems you own or have explicit written authorization to test. This tool is for authorized security research only.
