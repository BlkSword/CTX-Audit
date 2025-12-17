# DeepAudit Nexus

Advanced LLM Code Audit Tool with MCP Support.

## Architecture

- **Frontend**: React + TypeScript + Vite + Tauri
- **Backend**: Rust (Tauri Host)
- **Sidecar**: Python (LangGraph + MCP)

## Prerequisites

- Node.js
- Rust (Cargo)
- Python 3.8+
- Tauri CLI (`npm install -g @tauri-apps/cli` recommended)

## Setup

1. Install Frontend Dependencies:
   ```bash
   npm install
   ```

2. Install Python Dependencies:
   ```bash
   pip install -r python-sidecar/requirements.txt
   ```

## Running Development

```bash
npm run tauri dev
```

## Usage

1. Click "Open Project Folder".
2. Select a directory to audit.
3. Watch the logs as the Python Agent analyzes the code via MCP protocol.
