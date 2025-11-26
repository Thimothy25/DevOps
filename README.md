# 🛡️ AutoSSH Monitor - Jenkins Integrated

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Jenkins](https://img.shields.io/badge/Automation-Jenkins-red) ![SSH](https://img.shields.io/badge/Protocol-SSH-grey) ![License](https://img.shields.io/badge/License-MIT-green)

## 📖 Overview

This repository contains a Python-based monitoring tool designed to track the health and status of remote servers via **SSH**. The project includes a web-based dashboard for visualization and is fully integrated with **Jenkins** for automated, scheduled execution.

Instead of manual server checks, this tool automates the process of retrieving vital metrics (CPU usage, RAM, Disk space, Service status) and presents them in a user-friendly format.

## 📂 Project Structure

```text
SSH-MONITORING/
├── monitoring.py      # Core script to handle SSH connections & metric retrieval
├── monitoring_web.py  # Web dashboard to visualize server status (Flask/Streamlit)
├── requirements.txt   # List of Python dependencies
└── README.md          # Documentation
