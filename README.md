# ReconX: Automated Cybersecurity Reconnaissance Engine
An integrated, multi-threaded asset exploration and attack-surface mapping framework optimized for Python 3 environments on Linux and Windows. Developed for the NCERT Academic Framework.

## Features
* **Host Discovery Engine**: Low-overhead ICMP network layer presence validation.
* **Concurrent Scanner Pool**: Asynchronous multi-threaded TCP socket scanning utilizing a configurable `ThreadPoolExecutor`.
* **Service Interrogator**: Low-overhead banner grabbing to pull application version signatures.
* **Passive Intelligence Routing**: Automatic target parsing—runs domain registry lookups for public targets while automatically bypassing internal networks (RFC 1918) to avoid timeouts.
* **Reporting Fabric**: Simultaneous compilation of plaintext charts, structured machine-readable JSON matrices, and an executive HTML management dashboard.

---

## Installation & Deployment Guide

Follow these steps to deploy and run ReconX in your environment.

### Step 1: Clone the Repository
Open your terminal and clone the project directory down from GitHub:

```bash
git clone https://github.com/chaudharyharis835-pixel/ReconX.git
cd ReconX
chmod +x Reconx.py
python3 Reconx.py
### step 2: see output on browser
after scanning complete run the below commands and it will redirect you to browser automatically:
cd reports
xdg-open recon_output.html

