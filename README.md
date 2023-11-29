# PrivEscWindows
Powershell Script For windows Vuln machine

# First, Before anything
We need to enable our machine to execute scripts.
To do that, we will follow this instructions:

1) Run Powershell as Administrator
2) Execute this as Administrator.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

# Disable Windows Defender

1) Copy minimal to desktop
2) Type msconfig in windows search bar and click on System Configuration
3) In Boot tab, set Safe boot and Minimal
4) Click Ok and Restart. This will restart the machine.
5) Open poweshell as administrator
6) Change directory to Desktop

```powershell
cd C:\Users\User\Desktop
```

7) Run the minimal.ps1

```powershell
.\minimal.ps1
```
8) Type msconfig in windows search bar and click on System Configuration
9) In Boot tab, unset Safe boot and Minimal
10) Click in Ok and Restart. This will restart the machine.

# Running setup.ps1
