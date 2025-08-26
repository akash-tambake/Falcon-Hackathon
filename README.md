# Falcon-Hackathon

# ================================
# Auxia SecureCampus — Auxia Hackathon Project
# ================================

**Campus SafeNet** is a campus-focused web application that helps management understand browsing safety patterns while giving students a simple portal to view their activity. It combines a student/manager portal, a real-time network listener that classifies visited domains as benign/unsafe, and a domain feature pipeline for threat insights.

This README consolidates the key components, including the domain-feature scraper and DNS-feature pipeline used by your threat dashboard.

---

## 1) Our Idea

Build a software solution for a college campus that:

- Works even in colleges without advanced infrastructure.
- Surfaces actionable safety insights about the top websites students visit on campus Wi-Fi.
- Lets students view their browsing activity for transparency.
- Stores everything in a database for auditing and reporting.

---

## 2) What the Project Delivers

### Manager Portal
- **Secure login** for management.
- Overview of students; select a student to view their **Top 5 visited websites** during a session.
- Per-website **threat status (benign/unsafe)** derived from the network listener and DNS features.
- **CSV export** of visits and risk summaries.

### Student Portal
- **Secure login** for students.
- Optional view of their **browsing summary** for transparency.

### Network Threat Listener (Python)
- **Real-time passive listener** that logs DNS/HTTP/HTTPS domain visits from the client machine or gateway.
- Classification of domains as **benign/unsafe** using DNS-level and lexical features, including:
    - Entropy of the domain name
    - SPF/DKIM/DMARC presence
    - MX/TXT record availability
    - Character ratios/sequences
- Writes structured records to **PostgreSQL** for the manager portal.
- For the hackathon demo, runs on a **laptop hotspot** instead of campus Wi-Fi.

### Domain Feature Scraper
- Script to automaticßally discover websites by crawling from seed URLs.
- Emits a **CSV** with the exact DNS/lexical feature columns used by the network listener pipeline.
- Useful for creating synthetic domain datasets and testing the pipeline end-to-end without hitting the live listener.

---

## 3) Tech Stack
- **Backend:** Python, Flask/FastAPI (for API and listener)
- **Database:** PostgreSQL
- **Frontend:** React / HTML-CSS-JS
- **Other Tools:** DNS/HTTP libraries for domain monitoring, CSV utilities for feature scraping

---
