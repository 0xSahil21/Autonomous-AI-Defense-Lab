# Autonomous AI Defense Lab

A high-fidelity security research environment focused on the convergence of **Artificial Intelligence** and **Network Defense**. This project implements a self-evolving SOC framework that transitions from traditional telemetry to autonomous, model-driven threat response.



### 🏗️ Technical Architecture
* **Data Orchestration**: A containerized pipeline utilizing **Zeek** and **Suricata** for deep packet inspection and signature-based detection.
* **Telemetry Pipeline**: Real-time log ingestion and parsing via the **ELK Stack**, providing the data foundation for machine learning models.
* **Analytics Engine**: Integration of **Scikit-Learn** for behavioral baselining, using Logistic Regression for classification and K-Means for unsupervised anomaly detection.



### 📂 Repository Overview
* `docker-compose.yml`: Infrastructure-as-Code for the laboratory environment.
* `notebooks/`: Research and development of ML models, including training, validation, and performance metrics.
* `elk/` & `logstash-cyberai.conf`: Logic for transforming raw network telemetry into structured data features.
* `zeek/` & `suricata/`: Custom monitoring policies and threat detection rulesets.

---
*Developed as part of the AI in Cyber Security Internship Program by EduSkills (2026).*
