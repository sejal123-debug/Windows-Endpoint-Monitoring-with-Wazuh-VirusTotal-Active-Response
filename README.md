# Windows-Endpoint-Monitoring-with-Wazuh-VirusTotal-Active-Response

````
# 🛡️ Windows Endpoint Monitoring with Wazuh, VirusTotal & Active Response


While working on some lab simulations, I unintentionally downloaded a malicious file. That incident made me realize how easy it is to get compromised — even when you're trying to be careful.

So I decided to build an automated setup where:

- **Suspicious files** in the `Downloads` folder are immediately **detected**.
- They are **scanned with VirusTotal** for reputation.
- If flagged as malicious, they’re **automatically deleted** — no manual action needed.

This project uses **Wazuh**, **VirusTotal integration**, and a **custom Python-based Active Response script** to secure the endpoint with minimal human intervention.

Keep reading for a step-by-step walkthrough of how I set this up and validated it using EICAR and ikarus test files.


## 🚀 Overview

- **File Monitoring**: Watches the `Downloads` folder using Wazuh's File Integrity Monitoring (FIM).
- **Threat Scanning**: Uses VirusTotal API to validate suspicious files.
- **Active Response**: Custom Python script deletes malicious files automatically.

---

## 📌 Tools Used

* 🧩 Wazuh - Kali Linux (Manager) + Windows (Agent)
* 🧪 VirusTotal API
* ⚙️ Python + PyInstaller
* 🖥️ Windows 10 + PowerShell


## 🖥️ Endpoint Configuration (Windows)

### 🔍 1. Enable FIM

In the Wazuh agent config (`ossec.conf`):
```xml
<syscheck>
  <disabled>no</disabled>
  <directories realtime="yes">C:\Users\<USER_NAME>\Downloads</directories>
</syscheck>
````

### 🐍 2. Python & Script Setup

* Installed Python and added it to PATH
* Installed PyInstaller:
  `pip install pyinstaller`

<img width="1920" height="1080" alt="Screenshot (56)" src="https://github.com/user-attachments/assets/e9ec6277-9cde-4191-88f6-da92db1354ec" />

<img width="1920" height="1080" alt="Screenshot (57)" src="https://github.com/user-attachments/assets/49bd3bb0-1aec-4bc1-86ff-5a0c693f6767" />


#### `remove-threat.py` Highlights:

* Accepts JSON input from Wazuh
* Prevents deletion of symlinks, streams, or unsafe files
* Deletes verified malicious files
* Logs actions to:
  `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

### ⚙️ 3. Convert to Executable

```bash
pyinstaller -F remove-threat.py
```

Move the generated `.exe` to:

```
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

<img width="1920" height="1080" alt="Screenshot (59)" src="https://github.com/user-attachments/assets/6f25e1fc-3213-4692-ac3e-f587a92bcd6d" />

<img width="1920" height="1080" alt="Screenshot (60)" src="https://github.com/user-attachments/assets/9256b741-4e97-43ad-b04b-2de2b84442c2" />


Restart Wazuh Agent:

```powershell
Restart-Service -Name wazuh
```

---

## 🧠 Wazuh Manager Configuration (Linux)

### 🔗 1. VirusTotal Integration (`ossec.conf`)

Enter the command sudo nano /var/ossec/etc/ossec.conf in your linux machine

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

### 🔄 2. Register Custom Command

```xml
<command>
  <name>remove-threat</name>
  <executable>remove-threat.exe</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

### ⚡ 3. Active Response Configuration

```xml
<active-response>
  <disabled>no</disabled>
  <command>remove-threat</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>
```

### 📜 4. Add Custom Rules (`local_rules.xml`)

Enter the command var/ossec/etc/rules/local_rules.xml
```xml
<group name="virustotal,">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>Threat removed at: $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat at: $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```

Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## 🧪 Simulated Attack Test

### ⚠️ Step 1: Disable Real-Time AV

Navigate to:
Windows Security → Virus & threat protection → Manage settings → Real-time protection → OFF

### 🐛 Step 2: Download Test Malware

```powershell
Invoke-WebRequest -Uri https://secure.eicar.org/eicar.com.txt -OutFile eicar.txt
cp .\eicar.txt C:\Users\<USER_NAME>\Downloads
```

---

## 📊 Logs & Validation

### Check Dashboard:

* Wazuh Web UI → **Threat Hunting**

### Monitor Logs:

* **Agent**:
  `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

* **Server**:
  `/var/ossec/logs/active-responses.log`
  `/var/ossec/logs/ossec.log`

---

##  Outcome

*  Real-time monitoring of endpoint Downloads folder
*  Automated VirusTotal threat checks
*  Active response deletes malicious files
*  Verified results using EICAR and ikarus test files

---

## 📬 Feel free to contribute or reach out!

If you’re setting up a similar environment or want to explore Wazuh + Active Response, feel free to fork this repo.
---
