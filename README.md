A detection rule will be created for this Project. Once the rule has been triggered the VM associated with the rule will automatically be isolated.

This rule will be created for possible Remote Code Execution events speicfically, using PowerShell to automate the download and installation of the 7zip application.

The following command will be used to automate the downloading and installation of 7zip:

```powershell
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command `
"Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' `
-OutFile 'C:\ProgramData\7z2408-x64.exe'; `
Start-Process 'C:\ProgramData\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

Using MDEs Advanced Hunting dashboard create a KQL query that detects for any PowerShell command calling Invoke-WebRequest or Start-Process:

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

Once the detection rule has been created, the rule will be visible on the "Detection rules" dashboard. If you enter the page of the rule you created, it will show the details of the rule and it's history of triggered alerts/actions.

<p align="center">
  <img src="https://github.com/user-attachments/assets/270233a8-f4e9-4ab4-9aaa-0bb6ef50bac5" width="450"/>
  <img src="https://github.com/user-attachments/assets/8fc98915-4082-45e0-8f3d-0bfebe949b3f" width="550"/>
</p>

To test the detection rule works, im going to go on the VM i created for this example, open powershell and execute the command for downloading 7zip mentioned earlier. 

<p align="center">
  <img src="https://github.com/user-attachments/assets/6ef9afc5-46f1-4532-bf6f-5b54d5296498" width="450"/>
</p>

Once the code has been run on the `io-test-vm` device, there will be an alert shwon on the Detection Rule page from the alert you created before on the MDE Detection rule dashbaord you created.

<p align="center">
  <img src="https://github.com/user-attachments/assets/9e7f0edf-a667-4fdf-97c6-92bbc763a871" width="1000"/>
</p>

If you press on the alert, it shows the desdcirptiobn of the alert, "Actions taken" on the impacted asset and as observed below and the isolation of the asset. It will also show the exact activity that was done before the code was executed in relation to what time the activity occured. 

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

Now try logging in to the device involved in the RCE. Youll observe that the device is inaccessible because of the detection rule isolating it. Now from the page of the device, you can manually release it from isolation if you know that is no more suspious activity occuring because of the RCE.

<p align="center">
  <img src="https://github.com/user-attachments/assets/4209f01d-8f68-4859-84b7-453c4a65e484" width="450"/>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/d10b98be-e412-4d1f-aa03-0188e15620fd" width="450"/>
</p>



<p align="center">
  <img src="" width="450"/>
</p>








