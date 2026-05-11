# Cyber-Lens

CyberLens is an open-source Cyber Threat Intelligence (CTI) web application built using Python and MySQL. It collects, stores, and visualizes cyber attack datasets including phishing, malware, ransomware, and other security threats.

## Features
* **Phishing dataset integration** - Seamlessly ingest phishing data.
* **Malware attack database** - Centralized storage for malware threats.
* **Search functionality** - Quickly find specific threat actors or indicators.
* **Cyber attack categorization** - Automatic grouping of threat types.
* **Secure login system** - Protected access for researchers.
* **Dataset visualization** - Graphical representation of attack trends.
* **Open-source deployment** - Easy to host and contribute.

## Tech Stack
* **Backend:** Python (Flask)
* **Database:** MySQL
* **Frontend:** HTML, CSS, JavaScript

## Installation and Setup

```bash
# Clone the repository
git clone [https://github.com/Trixy-OppA/Cyber-Lens.git](https://github.com/Trixy-OppA/Cyber-Lens.git)

# Enter the project directory
cd Cyber-Lens

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## Project Roadmap (Future Plans)

To make **Cyber-Lens** a more robust CTI tool, the following enhancements are planned:

### 🛡️ Phase 1: Core Enhancements
- [ ] **Real-time Threat Feeds:** Automating data collection using open-source feeds like OTX AlienVault.
- [ ] **API Integration:** Adding support for VirusTotal API to scan suspicious URLs/Files.
- [ ] **Advanced Filtering:** Multi-criteria search (by IP, Country, or Attack Type).

### 🤖 Phase 2: Intelligence & Automation
- [ ] **ML-based Detection:** Implementing Random Forest or XGBoost models to predict phishing trends.
- [ ] **SHAP Integration:** Adding model explainability to understand *why* a specific threat was flagged.
- [ ] **Automated Reports:** Exporting daily threat summaries in PDF/CSV format.

### 📊 Phase 3: Visualization & UI
- [ ] **Interactive Geo-Maps:** Visualizing attack origins on a world map using Leaflet.js.
- [ ] **Dark Mode UI:** A more "hacker-style" interface for SOC analysts.
- [ ] **Role-Based Access (RBAC):** Different access levels for Admins and Researchers.
