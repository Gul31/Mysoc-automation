# 🤖 AI-Powered SOAR Workflow: Splunk, N8N, & ChatGPT

## 🌟 Overview
This project demonstrates a functional **Security Orchestration, Automation, and Response (SOAR)** workflow designed to automate the triage and enrichment of security alerts. By integrating a **Security Information and Event Management (SIEM)** solution (Splunk) with an automation platform (N8N) and an **Large Language Model (LLM)** (OpenAI's ChatGPT), the system autonomously analyzes an alert, enriches it with threat intelligence, assesses its severity against the **MITRE ATT&CK** framework, and posts a summarized, action-ready report to Slack for a Tier 1 Analyst.



### Key Features
* **Automated Alert Ingestion:** Splunk alert triggered by **Windows Event ID 4625** (Failed Logon).
* **Enhanced Telemetry:** Ingests security logs, security, and audit logs.
* **Dual Threat Intelligence:** Enrichment for **IP addresses (AbuseIPDB)** and **File Hashes (VirusTotal)**.
* **LLM-Based Analysis:** ChatGPT summarizes, assesses severity, and recommends actions using the **System** and **User** roles.
* **Structured Reporting:** Final output in Slack is formatted clearly for immediate analyst review.

### Technologies Used
| Category | Tool / Component | Function |
| :--- | :--- | :--- |
| **SIEM** | **Splunk Enterprise** | Log Ingestion, Search, and Alerting. |
| **Automation** | **N8N** | The orchestration platform connecting all components via a workflow. |
| **Telemetry** | **Windows 10 VM** | Source of security logs via the Universal Forwarder. |
| **AI/LLM** | **OpenAI's ChatGPT API** | Natural Language Processing for alert analysis and summarization. |
| **Threat Intel** | **AbuseIPDB API** | External enrichment for Source IP reputation. |
| **Threat Intel** | **VirusTotal API** | External enrichment for File Hash reputation. |
| **Endpoint** | **Slack** | Notification channel for final, summarized alerts. |

---

## 🛠️ Environment Setup (Step-by-Step Guide)

**Requirement:** A machine with **$\ge 32$ GB of RAM** is highly recommended.

### 1. Virtual Machine Setup and IP Configuration

Create the following VMs in VMware (or your chosen hypervisor). The following **IP Addresses** were used in the project configuration:

| VM Name | OS | RAM | Purpose | IP Address |
| :--- | :--- | :--- | :--- | :--- |
| **`mysoc-Windows10`** | Windows 10 Pro | 4 GB | Log Source / Target | `192.168.3.131` |
| **`mysoc-splunk`** | Ubuntu Server | 8 GB | SIEM Host | `192.168.3.129` |
| **`mysoc-n8n-vm`** | Ubuntu Server | 4 GB | Automation Host | `192.168.3.130` |

**Key Setup Points:**
* Use **`mysoc`** as the username/host prefix.
* Enable **OpenSSH Server** on Ubuntu VMs for remote access.
* Take a **`base-VM`** snapshot of the Windows 10 machine once RDP is enabled.

### 2. Splunk Installation and Configuration

#### A. Install Splunk Enterprise
1.  **SSH** into your Splunk VM (`mysoc@192.168.3.129`).
2.  Install the **Splunk Enterprise .deb file** (Version 10 was used) downloaded from splunk.com.
3.  Start Splunk and enable it to start on boot: `sudo /opt/splunk/bin/splunk enable boot-start -user splunk`

#### B. Configure Splunk GUI
1.  Access the GUI: `http://192.168.3.129:8000`
2.  **Receiving Port:** Add port **`9997`** (Settings $\rightarrow$ Forwarding and Receiving).
3.  **Index:** Create a new index named **`mysoc-project`**.
4.  **Add-on:** Install **"Splunk Add-on for Microsoft Windows"**.
5.  Take a **`Splunk-installed`** snapshot.

#### C. Windows Telemetry Setup (Universal Forwarder)
1.  On the Windows 10 VM, install the **Splunk Universal Forwarder (UF)**.
2.  Configure the UF to send data to the Indexer (`192.168.3.129`) on port **`9997`**.
3.  Place the following **`inputs.conf`** file in the UF local directory (`C:\Program Files\SplunkUniversalForwarder\etc\system\local\`):

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = mysoc-project
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
index = mysoc-project
disabled = false
source = Microsoft-Windows-Windows Defender/Operational
blacklist = 1151,1150,2000,1002,1001,1000

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = mysoc-project
disabled = false
source = Microsoft-Windows-PowerShell/Operational
blacklist = 4100,4105,4106,40961,40962,53504

[WinEventLog://Application]
index = mysoc-project
disabled = false

[WinEventLog://Security]
index = mysoc-project
disabled = false

[WinEventLog://System]
index = mysoc-project
disabled = false

[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
index = mysoc-project
disabled = false
```

### 3. N8N Installation and Setup

This section details setting up the N8N automation platform on your VM using Docker.

#### A. Install Docker and Run N8N

1.  **SSH** into your N8N VM (`mysoc@192.168.3.130`).
2.  Install Docker and Docker Compose:
    ```bash
    sudo apt install docker.io -y
    sudo apt install docker-compose -y
    ```
3.  Create a directory and run N8N using the `docker-compose.yaml` (available in this repository):
    ```bash
    mkdir n8n-compose && cd n8n-compose
    # Ensure docker-compose.yaml is in this directory
    sudo docker-compose pull && sudo docker-compose up -d
    ```
    > **Note:** The `docker-compose.yaml` ensures the N8N host is correctly set to `192.168.3.130`.
4.  Fix permissions and restart:
    ```bash
    sudo chown -R 1000 n8n_data
    sudo docker-compose down
    sudo docker-compose up -d
    ```

#### B. Access N8N

1.  Access the GUI: `http://192.168.3.130:5678`.
2.  Complete the initial setup.

## 💻 Building the SOAR Workflow

![n8n automation woorkflow](https://github.com/Gul31/Mysoc-automation/blob/main/screenshots/n8n%201.jpg?raw=true)

The core automation pipeline is: **Webhook $\rightarrow$ OpenAI $\rightarrow$ Slack**.

### 4. Splunk Alert and N8N Webhook Setup

This section establishes the trigger mechanism for the entire workflow.

* **Generate Test Data:** Manually generate failed RDP logins on the Windows 10 VM to ensure logs for **Event Code 4625** are present in Splunk.
* **Splunk Query:**
    ```spl
    event code=4625 | stats count by _time, host, user, src_ip
    ```
* **Save as Alert:** Set the alert to a **Cron Schedule** (`* * * * *`) for testing, and add a **Webhook** trigger action pointing to N8N.
* **N8N Webhook Node:** Create a **Webhook** node and set the Method to **`POST`**. Copy the generated URL and paste it into the Splunk alert.
* **Capture and Pin:** In N8N, click **Listen for test event**, capture the alert data, and **Pin** the result for static testing.
    > **CRITICAL:** **Disable the Splunk alert immediately** after capturing the output to prevent continuous alert spam.

![splunk alerting](https://github.com/Gul31/Mysoc-automation/blob/main/screenshots/splunk%20alert%204625.jpg?raw=true)

### 5. Configuring Threat Intelligence Tools

Configure two **HTTP Request** nodes to act as tools that the OpenAI model can call dynamically for enrichment.

| Tool Name | Purpose | API Key Source |
| :--- | :--- | :--- |
| `abuse-ipdb-enrichment` | IP reputation checking | AbuseIPDB |
| `virustotal-enrichment` | File hash reputation checking | VirusTotal |

* **Configuration:** For both tools, **Import cURL** commands from the respective API documentation.
* **Parameter Setup:** Replace the hard-coded IP/hash value with the **Tool Parameter** icon: `Let the model define this parameter`.
* **Credentials:** Insert the necessary API Keys in the payload or headers for authentication.

### 6. OpenAI Logic (Analysis & Triage)

The workflow uses the **System** and **User** roles to define the AI's behavior, SOC responsibilities, and inject the raw alert data.

1.  Add a node: **OpenAI $\rightarrow$ Message a Model**.
2.  **Model:** Select your desired model (e.g., `gpt-4o-mini`).
3.  **Role Configuration:**


### System (Behavioral Instructions for LLM)
```text
You are a SOC Level 1 (SOC1) analyst working in a Security Operations Center. Your role is to analyze incoming security alerts and provide concise, structured summaries for escalation.
Your key responsibilities:
1. Alert Triage: Evaluate incoming alerts from SIEM/log sources. Prioritize based on severity, confidence, and business impact.
2. Log Analysis: Extract and interpret relevant details such as IPs, usernames, timestamps, event types, and actions.
3. Event Correlation: Identify connections between alerts — such as repeated activity from the same host, IP, or user — to spot patterns suggesting lateral movement or persistence.
4. Threat Enrichment: Check whether any indicators (IP, domain, hash) appear in known threat intelligence feeds or have a known malicious reputation. For IP enrichment, use the tool named 'Abuse IPDB Enrichment'. For any File hash value, use the tool named 'VirusTotal-Hash' and use the URL: [https://www.virustotal.com/api/v3/files/](https://www.virustotal.com/api/v3/files/){id}, but replace '{id}' in the URL with the actual File hash value. Highlight if indicators are associated with any threat actors or known malware.
5. Assess the severity based on MITRE ATTACK mapping, identify tactics/techniques, and provide an initial rating (Low, Medium, High, Critical).
6. Reporting: Recommend next actions - Suggest investigation steps and potential containment actions. 
Formatting Requirements:
```

### Return the result in the given format:
#### - Summary: A short description of what the alert indicates.  
#### - IOC Enrichment: List extracted indicators (IPs, hashes, domains, users) with any enrichment context.  
#### - Severity Assessment: Classify the alert as Low / Medium / High and justify your reasoning.  
#### - Recommended Actions: Specific next steps a SOC1 or SOC2 analyst should take.
#### - Be analytical but concise. Use bullet points or markdown for readability. Avoid speculation unless it’s clearly stated as such.


### User Role (Alert Data Injection)

This prompt delivers the specific alert data from Splunk into the OpenAI model.

```text
Analyze the following Splunk alert and provide findings according to your SOC1 responsibilities.
Alert Name: {{$json.body.search_name}}
Alert Details: 
{{JSON.stringify($json.body.result,['_time','user','ComputerName'], 2)}}
```

### 7. Slack Reporting

1.  Add a node: **Slack $\rightarrow$ Send a Message**.
2.  Configure credentials and ensure the Slack App is added to your target channel (`#alerts`).
3.  **Message Text:** Use the output from the OpenAI node to send the structured report:
    ```
    {{ $node["Message a Model"].json.choices[0].message.content }}
    ```
    
4.  **Connect:** Link the entire workflow sequentially: **Webhook $\rightarrow$ OpenAI $\rightarrow$ Slack**.

![slack notification sample](https://github.com/Gul31/Mysoc-automation/blob/main/screenshots/slack%20alert%20.jpg?raw=true)

---
