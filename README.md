# Centralized Network Access Control System for Computer Labs

A centralized network access management system tailored for computer labs. It provides real-time monitoring, network policy (whitelist) management, and role-based access control (RBAC).

## 🏗 Architecture

The project is built on a **Modular Monolith** and **Client-Server** real-time architecture:

- **Server (Controller):** A centralized Flask application using `gevent` and `Flask-SocketIO` to manage agents, authenticate users, and synchronize network policies.
- **Agent (Client):** A Windows-native application running on lab workstations. It uses a PySide6/Qt GUI, synchronizes policies from the Server, applies whitelist enforcement through Windows Firewall (`netsh`), and uses Scapy/DNS helpers for passive monitoring and domain resolution.

## ✨ Key Features

- **Real-time Monitoring:** Track the online/offline status of all computers in the lab via WebSockets.
- **Centralized Whitelist Management:** Manage a list of allowed websites/IPs and automatically push policies to each agent instantly.
- **Role-Based Access Control (RBAC):** Clear role division (Admin, Teacher). Teachers can only manage the labs assigned to them.
- **Network Logging:** Collect logs of allowed and blocked network access attempts from workstations for analysis.
- **Group Management:** Group computers logically (e.g., Lab 1, Lab 2) to apply network policies in bulk easily.

## 🛠 Tech Stack

- **Server:** Python 3.11, Flask, Flask-SocketIO (gevent), MongoDB (PyMongo), JWT, Pydantic.
- **Agent:** Python, PySide6/Qt, Scapy, PyWin32, Windows Firewall (`netsh`), Requests, Cryptography, dnspython/aiodns.
- **Infrastructure / Deployment:** Docker & Docker Compose.

---

## 🚀 Getting Started

### 1. Server Setup (via Docker)

The Server component is fully dockerized for easy deployment anywhere.

1. Navigate to the server directory:
   ```bash
   cd server
   ```
2. Create your environment file from the example:
   ```bash
   cp .env-example .env
   ```
3. Edit the `.env` file and provide your MongoDB connection string (`MONGO_URI`) and secret keys.
4. Build and run the server using Docker Compose:
   ```bash
   docker-compose up -d --build
   ```
   *The server will be available at `http://localhost:5000`.*

### 2. Agent Setup (Windows Only)

The Agent must be run directly on the Windows workstations.

1. Navigate to the agent directory:
   ```bash
   cd agent
   ```
2. Install the necessary dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Agent **(Must be run as Administrator)** so it can intercept network traffic:
   ```bash
   python agent_gui.py
   ```
   *(Alternatively, build the Agent into one file at `dist/SAINT.exe` with PyInstaller using `agent/saint_agent.spec` for easier deployment across multiple machines).*
