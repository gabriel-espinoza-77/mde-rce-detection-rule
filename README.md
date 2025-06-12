A detection rule will be created for this Project. Once the rule has been triggered the VM associated with the rule will automatically be isolated.

This rule will be created for possible Remote Code Execution events speicfically, using PowerShell to automate the download and installation of the 7zip application.

The following command will be used to automate the downloading and installation of 7zip:

```bash
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command `
"Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' `
-OutFile 'C:\ProgramData\7z2408-x64.exe'; `
Start-Process 'C:\ProgramData\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

Using MDEs Advanced Hunting dashboard create a KQL query that detects for any PowerShell calling Invoke-WebRequest:

```kql
let target_machine = "io-test-vm";
DeviceProcessEvents
| where DeviceName == target_machine
| where InitiatingProcessCommandLine has ("Invoke-WebRequest")
| order by Timestamp desc 
```
<p align="center">
  <img src="https://github.com/user-attachments/assets/18a6272f-9c40-4e36-8b59-5b93478f8eda" width="450"/>
</p>

Once the KQL query has been typed, press the "Create detection rule" on the right side of the query page.

<p align="center">
  <img src="https://github.com/user-attachments/assets/de92a563-158b-457d-ba9a-85426ec89270" width="450"/>
</p>

It will bring you to the General page, once there fill out all the information requeried for the rule to be created.

<p align="center">
  <img src="https://github.com/user-attachments/assets/20f0f0ae-070f-4cb6-be7c-1f2390590022" width="450"/>
</p>

Press next and youll enter the Impact entities page, this will help MDE identify which assets are affected within the query results. 

<p align="center">
  <img src="https://github.com/user-attachments/assets/a368a4a3-9269-4163-b150-58e02d4391cf" width="450"/>
</p>

Press next, were on the automated actions page which defines what actions you want MDE to take on any endpoints that are affected.

<p align="center">
  <img src="https://github.com/user-attachments/assets/2bb45148-feb5-402b-a23e-728d35106224" width="450"/>
</p>

Note: we want the device fully isolated to prevent any further malicious activity

Next review all of the details that we went through and make sure they are all what we want. Once done, press submit

<p align="center">
  <img src="https://github.com/user-attachments/assets/9b780a4d-6d4f-43d2-a19d-1317fae314dd" width="450"/>
</p>



<p align="center">
  <img src="" width="450"/>
</p>




<p align="center">
  <img src="" width="450"/>
</p>















