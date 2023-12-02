# PrivEscWindows
Powershell Script For windows Vuln machine
Sorry guys, I don't know much from Powershell Scripting and because of that, my script is quite long ...

# Download windows 11 dev edition
Download from this link: https://developer.microsoft.com/pt-br/windows/downloads/virtual-machines/

# First, Before anything
We need to enable our machine to execute scripts.
To do that, we will follow this instructions:

1) Run Powershell as Administrator.
2) Execute this following command as Administrator.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

# Disable Windows Defender
Until now, I couldn't find anyway to automate this task. So, just follow this instructions to disable windows defender.

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
Now is the fun part, we run this script and we have a vulnerable windows 11 machine. We can now train the most common privilege escalation techniques.

1) Copy the script to Desktop
2) Run powershell as Administrator
3) Change directory

```powershell
cd C:\Users\User\Desktop
```

4) Save this script https://github.com/blakedrumm/SCOM-Scripts-and-SQL/blob/master/Powershell/General%20Functions/Set-UserRights.ps1#L437 as `Set-UserRights` in Desktop (if you have some question, you can try (this link)[https://blakedrumm.com/blog/set-and-check-user-rights-assignment/] and check some usage of this script)
5) Run the setup script:

```powershell
.\setup.ps1
```

5) Restart your windows VM