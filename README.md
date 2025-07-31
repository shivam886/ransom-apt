# Cyber RAG Detector

An AI-powered cybersecurity product that uses Retrieval-Augmented Generation (RAG) + MITRE ATT&CK framework + CIA triad severity scoring to detect and visualize early-stage ransomware and APT attack paths.

## 🧠 Core Features

- Semantic mapping of logs and IOCs to MITRE ATT&CK techniques using Ollama LLM
- Severity classification using the CIA Triad (Confidentiality, Integrity, Availability)
- Attack graph construction and shortest path analysis using Dijkstra’s algorithm
- PDF report generation with TTP summary, risk score, and recommendations
- Streamlit-based dashboard for analyst interaction

## 🚀 Getting Started

```bash
git clone https://github.com/your-org/cyber-rag-detector.git
cd cyber-rag-detector
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
