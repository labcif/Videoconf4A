# Videoconf4A

## Requirements

All the requirements are provided under a requirements file and can be installed with the following command:

```shell
pip3 install -r requirements.txt
```

## Usage for DPAPI decipher on Chrome

```powershell
py .\main.py "<Chrome Local State File>" "<User Masterkey SID>" "<User password>" "<User Masterkey file>" "<Chrome Cookie file to decipher>"
```

Example:

```powershell
py .\main.py "E:\MCIF\TESE\Zoom-Artifacts\extract\Local State" "S-1-5-21-1350253645-1860882672-2634105300-1001" "abc12345" "E:\MCIF\TESE\Zoom-Artifacts\extract\UserProtect\S-1-5-21-1350253645-1860882672-2634105300-1001\37fc173f-90a2-4bdf-8e09-a310714cfc33" "E:\MCIF\TESE\Zoom-Artifacts\extract\Cookies"
```

# TODO
* Find a way to use mimikatz without the terminal window
* Retrieve the masterkey file name using mimikatz
* Retrieve the NTLM hash from the correct user (mimikatz)
* Use mimikatz programmatically
* Make a GUI to input user's password. Show the NTLM hash on that GUI.
