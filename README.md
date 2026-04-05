# TRACE - Security Risk Assessment Tool

## Overview
TRACE is an automated security auditing and monitoring system that evaluates system configurations based on CIS benchmarks.

## Features
- Agent-based architecture
- Real-time monitoring
- Security misconfiguration detection
- Centralized dashboard

## Architecture
- Agents (Linux & Windows)
- Backend API
- Dashboard UI

## Setup

### 1. Clone repo
git clone https://github.com/infogoat/trace-security-dashboard.git

### 2. Install dependencies
pip install -r requirements.txt

### 3. Run backend
uvicorn app.main:app --reload

### 4. Run agent
python agents/agent_linux.py

## Notes
System identification is dynamically generated using OS-level identifiers.
