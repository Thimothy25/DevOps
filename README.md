# 🛡️ AutoSSH Monitor - Jenkins Integrated

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Jenkins](https://img.shields.io/badge/Automation-Jenkins-red) ![SSH](https://img.shields.io/badge/Protocol-SSH-grey) ![License](https://img.shields.io/badge/License-MIT-green)

## 📖 Overview

This repository contains a Python-based monitoring tool designed to track the health and status of remote servers via **SSH**. The project includes a web-based dashboard for visualization and is fully integrated with **Jenkins** for automated, scheduled execution.

Instead of manual server checks, this tool automates the process of retrieving vital metrics (CPU usage, RAM, Disk space, Service status) and presents them in a user-friendly format.

## ✨ Key Features
Remote Monitoring: Connects to multiple servers securely using SSH (via paramiko or similar libraries).

Metric Collection: Automatically fetches CPU load, Memory usage, Disk storage, and Uptime.

Web Dashboard: Real-time visual representation of server health via monitoring_web.py.

## Jenkins Automation:

Automated periodic checks (Cron-like scheduling).

Alert triggering on failure.

CI/CD pipeline integration.

## 🚀 Getting Started
Prerequisites
Python 3.x installed.

Jenkins Server up and running.

SSH Access (Private/Public keys) to the target servers.

## 📂 Project Structure

```text
SSH-MONITORING/
├── monitoring.py      # Core script to handle SSH connections & metric retrieval
├── monitoring_web.py  # Web dashboard to visualize server status (Flask/Streamlit)
├── requirements.txt   # List of Python dependencies
└── README.md          # Documentation
