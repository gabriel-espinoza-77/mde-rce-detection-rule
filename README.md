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

