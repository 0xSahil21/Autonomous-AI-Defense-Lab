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


### ⚙️ Infrastructure Orchestration (`docker-compose.yml`)

The laboratory environment is defined as an automated multi-container stack, handling everything from raw packet capture to interactive machine learning development.

#### **Service Stack Breakdown**

* **Threat Intelligence (MISP)**: A dedicated instance for collecting and sharing Indicators of Compromise (IoCs). It runs with a **MariaDB** backend and **Redis** for performance-intensive task queuing.
* **Network Analysis (Zeek)**: Configured with `NET_ADMIN` and `NET_RAW` capabilities to perform deep packet inspection and generate structured connection logs.
* **Intrusion Detection (Suricata)**: Operates in host-networking mode for real-time signature-based threat detection across the specified network interface.
* **Log Management (ELK)**: A unified Elasticsearch, Logstash, and Kibana instance. It ingests telemetry using a custom `logstash-cyberai.conf` to map network data into features for model consumption.
* **ML Workspace (Jupyter)**: A `scipy-notebook` environment with persistent volume mapping to the lab's telemetry, allowing for direct model training on live network data.



#### **Deployment & Usage**

1.  **Environment Provisioning**: Run the following to build and launch the entire stack in detached mode:
    ```bash
    docker-compose up -d
    ```
2.  **Access Points**:
    * **SOC Dashboard (Kibana)**: `http://localhost:5601`
    * **Threat Intel (MISP)**: `http://localhost:80`
    * **ML Development (Jupyter)**: `http://localhost:8888`
3.  **Data Persistence**: Security telemetry is mapped to local directories (`./zeek-live` and `./suricata`), ensuring logs and models are preserved across container restarts.
---
*Developed as part of the AI in Cyber Security Internship Program by EduSkills (2026).*
