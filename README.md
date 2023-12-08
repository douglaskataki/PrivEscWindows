# Basic Privilege Escalation in Windows
Powershell Script For windows 11 Vuln machine
Sorry guys, I don't know much from Powershell Scripting (still learning) and because of that, my script is quite long ...
Very special thanks for [sagishahar](https://github.com/sagishahar/) and [blakedrumm](github.com/blakedrumm), they made scripts that I could use as bases for my own.
And last, but not least, [](https://github.com/Tib3rius/) and his setup.bat for Windows Privilege Escalation.

# Download windows 11 dev edition
Download from this link: https://developer.microsoft.com/pt-br/windows/downloads/virtual-machines/

# First, Before anything
We need to enable our machine to execute scripts.
To do that, we will follow this instructions (as user User, which is the default one):

1) Go to Windows Security > Virus & Threat Protection > Virus & Threat protection settings and click in Manage
2) *Turn off* the following settings: Real-time protection, Cloud-delivery protection, Automatic sample submission and tamper protection.
3) Now, run Powershell as *Administrator*.
4) Execute this following command as Administrator (in order to execute scripts in Powershell):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
```

5) Change in power setting the time to turn off the machine (by default is 5 min).

# Disable Windows Defender
Until now, I couldn't find anyway to automate this task. So, just follow this instructions to disable windows defender.

1) Copy the content from minimal.ps1 to a file named minimal and save it on Desktop.
2) Type msconfig in windows search bar and click on System Configuration.
3) In Boot tab, set Safe boot and Minimal.
4) Click Ok and restart your machine.
5) Open Powershell as *Administrator*.
6) Change directory to Desktop with the following command:

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

You can do it manually (I will put it here soon).

# Running setup.ps1
Now is the fun part, we run the setup script and we have a vulnerable windows 11 machine. We can now train the most common privilege escalation techniques.

1) Copy the setup content to a file called setup.ps1 and save it in Desktop.
2) Run powershell as *Administrator*
3) Change directory

```powershell
cd C:\Users\User\Desktop
```

4) Run the setup script:
```powershell
.\setup.ps1
```

5) Restart your windows VM, in order to 

# How to use it this script

# Services

## File Permission

## Insecure Service Permission

Need to use it after remote desktop login.

## Unquoted Path

# Registry

# Passwords

## Pass the Hash

### SeBackupPrivilege

# Scheduled Tasks

# God Potato

## SeImpersonatePrivilege

# 
