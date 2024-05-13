#Requires -RunAsAdministrator

# Thanks for blakedrumm for this script:

Function Set-UserRights(){
    param
    (
        [Parameter(Position = 0,
                   HelpMessage = 'You want to Add a user right.')]
        [Alias('add')]
        [switch]$AddRight,
        [Parameter(Position = 1)]
        [Alias('computer')]
        [array]$ComputerName,
        [Parameter(Position = 2,
                   HelpMessage = 'You want to Remove a user right.')]
        [switch]$RemoveRight,
        [Parameter(Position = 3)]
        [Alias('user')]
        [array]$Username,
        [Parameter(Mandatory = $false,
                   Position = 4)]
        [ValidateSet('SeNetworkLogonRight', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeSystemtimePrivilege', 'SeCreatePagefilePrivilege', 'SeDebugPrivilege', 'SeRemoteShutdownPrivilege', 'SeAuditPrivilege', 'SeIncreaseQuotaPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeLoadDriverPrivilege', 'SeBatchLogonRight', 'SeServiceLogonRight', 'SeInteractiveLogonRight', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeProfileSingleProcessPrivilege', 'SeSystemProfilePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege', 'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeUndockPrivilege', 'SeManageVolumePrivilege', 'SeRemoteInteractiveLogonRight', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeDelegateSessionUserImpersonatePrivilege', 'SeMachineAccountPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeCreatePermanentPrivilege', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeEnableDelegationPrivilege', 'SeLockMemoryPrivilege', 'SeRelabelPrivilege', 'SeSyncAgentPrivilege', IgnoreCase = $true)]
        [Alias('right')]
        [array]$UserRight
    )
    BEGIN
    {

        Write-Output '==================================================================='
        Write-Output '======================= Start of Script ==========================='
        Write-Output '==================================================================='

        $checkingpermission = "Checking for elevated permissions..."
        $scriptout += $checkingpermission
        Write-Output $checkingpermission
        if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        {
            $currentPath = $myinvocation.mycommand.definition
            $nopermission = "Insufficient permissions to run this script. Attempting to open the PowerShell script ($currentPath) as administrator."
            $scriptout += $nopermission
            Write-Warning $nopermission
            # We are not running "as Administrator" - so relaunch as administrator
            # ($MyInvocation.Line -split '\.ps1[\s\''\"]\s*', 2)[-1]
            Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
            break
        }
        else
        {
            $permissiongranted = " Currently running as administrator - proceeding with script execution..."
            Write-Output $permissiongranted
        }

        Function Time-Stamp
        {
            $TimeStamp = Get-Date -UFormat "%B %d, %Y @ %r"
            return "$TimeStamp - "
        }
    }
    PROCESS
    {
        function Inner-SetUserRights
        {
            param
            (
                [Parameter(Position = 0,
                           HelpMessage = 'You want to Add a user right.')]
                [Alias('add')]
                [switch]$AddRight,
                [Parameter(Position = 1)]
                [Alias('computer')]
                [array]$ComputerName,
                [Parameter(Position = 2,
                           HelpMessage = 'You want to Remove a user right.')]
                [switch]$RemoveRight,
                [Parameter(Position = 3)]
                [Alias('user')]
                [array]$Username,
                [Parameter(Mandatory = $false,
                           Position = 4)]
                [Alias('right')]
                [array]$UserRight
            )
            if (!$UserRight)
            {
                Write-Warning "Inner Function: Unable to continue because you did not supply the '-UserRight' parameter."
                break
            }
            if (!$AddRight -and !$RemoveRight)
            {
                Write-Warning "Inner Function: Unable to continue because you did not supply the '-AddRight' or '-RemoveRight' switches."
                break
            }
            elseif ($AddRight -and $RemoveRight)
            {
                Write-Warning "Inner Function: Unable to continue because you used both the '-AddRight' and '-RemoveRight' switches. Run again with just one of these present, either Add or Remove."
                break
            }
            elseif ($AddRight)
            {
                Write-Verbose "Inner Function: Detected -AddRight switch in execution."
                $ActionType = 'Adding'
            }
            elseif ($RemoveRight)
            {
                Write-Verbose "Inner Function: Detected -RemoveRight switch in execution."
                $ActionType = 'Removing'
            }
            else
            {
                Write-Warning "Something is wrong, detected logic is broken before executing main function. Exiting."
                break
            }
            Function Time-Stamp
            {
                $TimeStamp = Get-Date -UFormat "%B %d, %Y @ %r"
                return "$TimeStamp - "
            }
            $tempPath = [System.IO.Path]::GetTempPath()
            $import = Join-Path -Path $tempPath -ChildPath "import.inf"
            if (Test-Path $import) { Remove-Item -Path $import -Force }
            $export = Join-Path -Path $tempPath -ChildPath "export.inf"
            if (Test-Path $export) { Remove-Item -Path $export -Force }
            $secedt = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
            if (Test-Path $secedt) { Remove-Item -Path $secedt -Force }
            $Error.Clear()
            try
            {
                foreach ($right in $UserRight)
                {
                    $UserLogonRight = switch ($right)
                    {
                        "SeBatchLogonRight"                 { "Log on as a batch job (SeBatchLogonRight)" }
                        "SeDenyBatchLogonRight"             { "Deny log on as a batch job (SeDenyBatchLogonRight)" }
                        "SeDenyInteractiveLogonRight"       { "Deny log on locally (SeDenyInteractiveLogonRight)" }
                        "SeDenyNetworkLogonRight"           { "Deny access to this computer from the network (SeDenyNetworkLogonRight)" }
                        "SeDenyRemoteInteractiveLogonRight" { "Deny log on through Remote Desktop Services (SeDenyRemoteInteractiveLogonRight)" }
                        "SeDenyServiceLogonRight"           { "Deny log on as a service (SeDenyServiceLogonRight)" }
                        "SeInteractiveLogonRight"           { "Allow log on locally (SeInteractiveLogonRight)" }
                        "SeNetworkLogonRight"               { "Access this computer from the network (SeNetworkLogonRight)" }
                        "SeRemoteInteractiveLogonRight"     { "Allow log on through Remote Desktop Services (SeRemoteInteractiveLogonRight)" }
                        "SeServiceLogonRight"               { "Log on as a service (SeServiceLogonRight)" }
                        Default                             { "($right)" }
                    }
                    Write-Output ("$(Time-Stamp)$ActionType `"$UserLogonRight`" right for user account: '$Username' on host: '$env:COMPUTERNAME'")
                    if ($Username -match "^S-.*-.*-.*$|^S-.*-.*-.*-.*-.*-.*$|^S-.*-.*-.*-.*-.*$|^S-.*-.*-.*-.*$")
                    {
                        $sid = $Username
                    }
                    else
                    {
                        $sid = ((New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier])).Value
                    }
                    secedit /export /cfg $export | Out-Null
                    #Change the below to any right you would like
                    $sids = (Select-String $export -Pattern "$right").Line
                    if ($ActionType -eq 'Adding')
                    {
                        # If right has no value it needs to be added
                        if ($sids -eq $null)
                        {
                            $sids = "$right = *$sid"
                            $sidList = $sids
                        }
                        else
                        {
                            $sidList = "$sids,*$sid"
                        }
                    }
                    elseif ($ActionType -eq 'Removing')
                    {
                        $sidList = "$($sids.Replace("*$sid", '').Replace("$Username", '').Replace(",,", ',').Replace("= ,", '= '))"
                    }
                    Write-Verbose $sidlist
                    foreach ($line in @("[Unicode]", "Unicode=yes", "[System Access]", "[Event Audit]", "[Registry Values]", "[Version]", "signature=`"`$CHICAGO$`"", "Revision=1", "[Profile Description]", "Description=$ActionType `"$UserLogonRight`" right for user account: $Username", "[Privilege Rights]", "$sidList"))
                    {
                        Add-Content $import $line
                    }
                }

                secedit /import /db $secedt /cfg $import | Out-Null
                secedit /configure /db $secedt | Out-Null
                gpupdate /force | Out-Null
                Write-Verbose "The script will not delete the following paths due to running in verbose mode, please remove these files manually if needed:"
                Write-Verbose "`$import : $import"
                Write-Verbose "`$export : $export"
                Write-Verbose "`$secedt : $secedt"

                if ($VerbosePreference.value__ -eq 0)
                {
                    Remove-Item -Path $import -Force | Out-Null
                    Remove-Item -Path $export -Force | Out-Null
                    Remove-Item -Path $secedt -Force | Out-Null
                }
            }
            catch
            {
                Write-Output ("$(Time-Stamp)Failure occurred while granting `"$right`" to user account: '$Username' on host: '$env:COMPUTERNAME'")
                Write-Output "Error Details: $error"
            }
        }
        $InnerSetUserRightFunctionScript = "function Inner-SetUserRights { ${function:Inner-SetUserRights} }"
        function Set-UserRights
        {
            param
            (
                [Parameter(Position = 0,
                           HelpMessage = 'You want to Add a user right.')]
                [Alias('add')]
                [switch]$AddRight,
                [Parameter(Position = 1)]
                [Alias('computer')]
                [array]$ComputerName,
                [Parameter(Position = 2,
                           HelpMessage = 'You want to Remove a user right.')]
                [switch]$RemoveRight,
                [Parameter(Position = 3)]
                [Alias('user')]
                [array]$Username,
                [Parameter(Mandatory = $false,
                           Position = 4)]
                [ValidateSet('SeNetworkLogonRight', 'SeBackupPrivilege', 'SeChangeNotifyPrivilege', 'SeSystemtimePrivilege', 'SeCreatePagefilePrivilege', 'SeDebugPrivilege', 'SeRemoteShutdownPrivilege', 'SeAuditPrivilege', 'SeIncreaseQuotaPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeLoadDriverPrivilege', 'SeBatchLogonRight', 'SeServiceLogonRight', 'SeInteractiveLogonRight', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeProfileSingleProcessPrivilege', 'SeSystemProfilePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege', 'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeUndockPrivilege', 'SeManageVolumePrivilege', 'SeRemoteInteractiveLogonRight', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege', 'SeDelegateSessionUserImpersonatePrivilege', 'SeMachineAccountPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeCreatePermanentPrivilege', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeEnableDelegationPrivilege', 'SeLockMemoryPrivilege', 'SeRelabelPrivilege', 'SeSyncAgentPrivilege', IgnoreCase = $true)]
                [Alias('right')]
                [array]$UserRight
            )
            if (!$Username)
            {
                $Username = "$env:USERDOMAIN`\$env:USERNAME"
            }
            if (!$UserRight)
            {
                Write-Warning "Main Function: Unable to continue because you did not supply the '-UserRight' parameter."
                break
            }
            if (!$AddRight -and !$RemoveRight)
            {
                Write-Warning "Main Function: Unable to continue because you did not supply the '-AddRight' or '-RemoveRight' switches."
                break
            }
            elseif ($AddRight -and $RemoveRight)
            {
                Write-Warning "Main Function: Unable to continue because you used both the '-AddRight' and '-RemoveRight' switches. Run again with just one of these present, either Add or Remove."
                break
            }
            elseif ($AddRight)
            {
                Write-Verbose "Main Function: Detected -AddRight switch in execution."
                $ActionType = 'Adding'
            }
            elseif ($RemoveRight)
            {
                Write-Verbose "Main Function: Detected -RemoveRight switch in execution."
                $ActionType = 'Removing'
            }
            if (!$ComputerName)
            {
                $ComputerName = $env:ComputerName
            }
            foreach ($user in $Username)
            {
                foreach ($right in $UserRight)
                {
                    foreach ($computer in $ComputerName)
                    {
                        if ($computer -match $env:COMPUTERNAME)
                        {
                            Inner-SetUserRights -UserRight $right -Username $user -AddRight:$AddRight -RemoveRight:$RemoveRight
                        }
                        else
                        {
                            Invoke-Command -ComputerName $Computer -Script {
                                param ($script,
                                    [string]$Username,
                                    [Parameter(Mandatory = $true)]
                                    [array]$UserRight,
                                    $AddRight,
                                    $RemoveRight,
                                    $VerbosePreference)
                                . ([ScriptBlock]::Create($script))
                                $VerbosePreference = $VerbosePreference
                                $Error.Clear()
                                try
                                {
                                    if ($VerbosePreference -eq 0)
                                    {
                                        Inner-SetUserRights -Username $Username -UserRight $UserRight -AddRight:$AddRight -RemoveRight:$RemoveRight
                                    }
                                    else
                                    {
                                        Inner-SetUserRights -Username $Username -UserRight $UserRight -AddRight:$AddRight -RemoveRight:$RemoveRight -Verbose
                                    }
                                }
                                catch
                                {
                                    $info = [PSCustomObject]@{
                                        Exception = $Error.Exception.Message
                                        Reason    = $Error.CategoryInfo.Reason
                                        Target    = $Error.CategoryInfo.TargetName
                                        Script    = $Error.InvocationInfo.ScriptName
                                        Line      = $Error.InvocationInfo.ScriptLineNumber
                                        Column    = $Error.InvocationInfo.OffsetInLine
                                        Date      = Get-Date
                                        User      = $env:username
                                    }
                                    Write-Warning "$info"
                                }

                            } -ArgumentList $InnerSetUserRightFunctionScript, $user, $right, $AddRight, $RemoveRight, $VerbosePreference
                        }
                    }
                }
            }

        }
        if ($ComputerName -or $Username -or $UserRight -or $RemoveRight)
        {
            foreach ($user in $Username)
            {
                Set-UserRights -ComputerName $ComputerName -Username $user -UserRight $UserRight -AddRight:$AddRight -RemoveRight:$RemoveRight
            }
        }
        else
        {

         <# Edit line 437 to modify the default command run when this script is executed.
           Example:
                Set-UserRights -AddRight -UserRight SeServiceLogonRight, SeBatchLogonRight -ComputerName $env:COMPUTERNAME, SQL.contoso.com -UserName CONTOSO\User1, CONTOSO\User2
                or
                Set-UserRights -AddRight -UserRight SeBatchLogonRight -Username S-1-5-11
                or
                Set-UserRights -RemoveRight -UserRight SeBatchLogonRight -Username CONTOSO\User2
                or
                Set-UserRights -RemoveRight -UserRight SeServiceLogonRight, SeBatchLogonRight -Username CONTOSO\User1
           #>
            Set-UserRights
        }
    }
    END
    {
        Write-Output "$(Time-Stamp)Script Completed!"
    }
}

#---------------------------------------------------------------- My Functions Start Here!

Function Disable-Firewall(){
    Set-NetFirewallProfile -Enabled False

    Write-Host "Disable Windows Defender"
    $regpathWindowsDef = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableAntiVirus -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableSpecialRunningModes -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableRoutinelyTakingAction -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name ServiceKeepAlive -Value 0 -PropertyType DWORD -Force | Out-Null

    $regpathWindowsDef = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    New-Item -Path $regpathWindowsDef -Force
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableBehaviorMonitoring -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableOnAccessProtection -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableScanOnRealtimeEnable -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableRealtimeMonitoring -Value 1 -PropertyType DWORD -Force | Out-Null

    $regpathWindowsDef = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'
    New-Item -Path $regpathWindowsDef -Force
    New-ItemProperty -Path ($regpathWindowsDef) -Name ForceUpdateFromMU -Value 1 -PropertyType DWORD -Force | Out-Null

    $regpathWindowsDef = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
    New-Item -Path $regpathWindowsDef -Force
    New-ItemProperty -Path ($regpathWindowsDef) -Name DisableBlockAtFirstSeen -Value 1 -PropertyType DWORD -Force | Out-Null

    #!#!#!#! Attention
    # This needs to be executed before in minimal boot configuration (as Administrator!)
    # $regpathControl = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    # Set-ItemProperty -Path ($regpathControl+"\Sense") -Name Start -Value 4
    # Set-ItemProperty -Path ($regpathControl+"\WdFilter") -Name Start -Value 4
    # Set-ItemProperty -Path ($regpathControl+"\WdNisDrv") -Name Start -Value 4
    # Set-ItemProperty -Path ($regpathControl+"\WdNisSvc") -Name Start -Value 4
    # Set-ItemProperty -Path ($regpathControl+"\WdBoot") -Name Start -Value 4
    # Set-ItemProperty -Path ($regpathControl+"\WinDefend") -Name Start -Value 4

    Write-Host "Disable schedule tasks for Windows Defender"
    Get-ScheduledTask "Windows Defender Cache Maintenance" | Disable-ScheduledTask | Select-Object -Property Actions,State
    Get-ScheduledTask "Windows Defender Cleanup" | Disable-ScheduledTask | Select-Object -Property Actions,State
    Get-ScheduledTask "Windows Defender Scheduled Scan" | Disable-ScheduledTask | Select-Object -Property Actions,State
    Get-ScheduledTask "Windows Defender Verification" | Disable-ScheduledTask | Select-Object -Property Actions,State

}

Function Set-User(){
    Param(
        [string]$userName,
        $password
    )

    $checkForUser = (Get-LocalUser).Name -Contains $userName

    Write-Host "[*] Checking if $userName exists:"
    If ($checkForUser -eq $false) {
        Write-Host "$user doesn't exists!"
        Write-Host "[*] Creating $userName : $password"
        $Password = ConvertTo-SecureString $password -AsPlainText -Force
        New-LocalUser $userName -Password $Password | Out-Null


    }Else {
        Write-Host "$userName exists!"
    }

}

Function Set-Group(){
    Param(
        $userName,
        $groupName
    )

    Write-Host "[*] Checking if $user is in $groupName"
    $groupObj =[ADSI]"WinNT://./$groupName,group"
    $membersObj = @($groupObj.psbase.Invoke("Members"))

    $members = ($membersObj | foreach {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)})

    If ($members -contains $userName) {
       Write-Host "$user is in group $groupName"
     } Else {
       Write-Host "[*] Adding to group $groupName"
       Add-LocalGroupMember -Group $groupName -Member $userName | Out-Null
    }
}

Function Set-Folder(){
    Param(
        $folder
    )
    Write-Host "Checking if Directory $folder exists"
    if(Test-Path -Path $folder){
        Write-Host "Directory $folder already exists!"
    }
    else{
        Write-Host "[*] Creating $folder"
        New-Item -ItemType Directory -Path $folder | Out-Null
    }
}

function Move-File{
    Param(
        $file,
        $path
    )
    Write-Host "Checking if $file exists $path"

    $fullPath = $path+"\"+$file

    if(Test-Path -Path $fullPath){
        Write-Host "File $fullPath already exists!"
    }
    else{
        Write-Host "[*] Moving file $file to $path"
        Get-Item –Path $file | Move-Item -Destination $path | Out-Null
    }
}

function Check-Hash(){
    Param(
        $file,
        [string]$Hash
    )
    if((Get-FileHash $file -Algorithm MD5).Hash -eq $Hash){
        Write-Host "[+] Hash confirmed."
        return
    }else{
        Write-Host "[-] Hash mismatch. Exiting"
        exit 1
    }

}

# I changed some permissions to Full Access (/grant Everyone:F)

function Reset-File-Permission(){
    Param(
        $filePath
    )
    Write-Host "[*] Reseting File Permission $filePath"

    if($filePath -eq "C:\Program Files\File Permissions Service\filepermservice.exe"){
        icacls.exe $filePath /grant BUILTIN\Users:F | Out-Null
        return
    }
    if ($filePath -eq "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"){
        icacls.exe $filePath /grant "BUILTIN\Users:(OI)(CI)F" /T | Out-Null
        return
    }
    if ($filePath -eq "C:\Program Files\Unquoted Path Service") {
        icacls.exe $filePath /grant "BUILTIN\Users:(OI)(CI)F" /T | Out-Null
        return
    }
    if ($filePath -eq "C:\Program Files\Autorun Program\program.exe"){
        icacls.exe $filePath /grant BUILTIN\Users:F | Out-Null
        return
    }
    if ($filePath -eq "C:\Windows\Panther\Unattend.xml") {
        icacls.exe $filePath /grant BUILTIN\Users:R | Out-Null
        return
    }
    if ($filePath -eq "C:\PrivEsc\AdminPaint.lnk") {
        icacls.exe $filePath /grant BUILTIN\Users:R | Out-Null
        return
    }
    if ($filePath -eq "C:\DevTools\CleanUp.ps1") {
        icacls.exe $filePath /grant BUILTIN\Users:M | Out-Null
        return
    }
    else{
        icacls.exe $filePath /T /Q /C /RESET | Out-Null
        return
    }

}

function Write-File{
    param (
        $inputFile
    )

    if($inputFile -eq "dllhijackservice.exe"){
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists locally."
            Remove-Item $inputFile

        }else{
            Write-Host "[*] Creating file $inputFile"

            $hexFile ="4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000"
            $hexFile +="5045000064860300000000000000000000000000f0002f020b02021f002000000010000000b0000000dc000000c00000000040000000000000100000000200000400000000000000050002000000000000f000000010000000000000030060010000200000000000001000000000000000001000000000000010000000000000"
            $hexFile +="0000000010000000000000000000000000e000001401000000000000000000000060000088020000000000000000000014e100001400000000000000000000000000000000000000000000000000000050de00002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000555058300000000000b00000001000000000000000020000000000000000000000000000800000e055505831000000000020000000c000000020000000020000000000000000000000000000400000e055505832000000000010000000e000000002000000220000000000000000000000000000400000c0"
            $hexFile +="332e393500555058210d2402091e5dfa2cd7e65af70bb60000d91b00000048000049020056ffae6cffc30f1f440000662e0684004883ec28488b058599d9de771431d2c70001120e860c7b200732894cff424adfde75bf81384d5a74780d211a8915a36f058b0085c09dfb5bf77457b90225e8041e8448c7c1ff000b0d8774bb"
            $hexFile +="b7cc281558433d8902093e05ddf6769ba48b1008db425a48102d09fbed6fbabc104a833801746531c0acc428c3b901566eb7ff0feba766904863483c4801c8845045150f85f66db7ef72540fb7481895f90b32450602159bf9fb7b83b8f00e0f860c8b88f8f085ec8710fbc90f95c2e9340f8d0d990b5ffb600f760cac708378"
            $hexFile +="7436448b80e8372361591b45df384f63bfefba38b405ce4c8d059e6e51159f060de11ddb99a0d905780e0571065cf7db5c7724202f95e45d08d69c9075efff5f4338a7804f41554154555756534881ec987a72fb6eecc0b90da5543689d7f348ab3c3da8c2db9d3b0f45cdea048c6513042530a2feeeff3d1dbc4106700831ed"
            $hexFile +="4c8b25ff52eb114839c60f84eddf76ef272db9e80360ffd448e8f0480fb13348d562bfb9db75e22c3598332f8b0683f8012845f89fdb5b06ef099cc705bb6d00fe84ddd8971e5985ed077cc7dd40bdee1fdb5d49740c45acba0231c9ffd0d8eff76dc30fac02bd120fff156f802515109bc7d8ec0afd1b144c61fd221ecc71e1"
            $hexFile +="741f27ac4ca02eb176dcce828d6cb25a5d5e55eb1588b1f02f230084d2742c83e1ea27166fff7f5b39c093b61080fa207ee64189c84183f0010b22410f12be45f844c8ebe466a92f7511eb1aaf745db0dd2a7f0b361bf06f397de186cdf207e37419f69e5c01b80adc36b6cd283e450b605bc020b82cdfffbffd25d16c06458d"
            $hexFile +="6c24014d63ed49c1e5034c89e9be14c3eeb06d38e445c597200f8e19b7dd9371ba31db1f8b0cdf251dfcf07001bdeb886d26f13105dd1914df4989fdffefd680c18ec301170c4139dc7fce4983ed084ac7442d6c78729f3e892d52551b8c138e3fd28477234837128b0d416c203af6ecd885ea05240c15252c061f1e8db0dbdc"
            $hexFile +="0a0abb080585c9afc2b97d9bbb1ef26b0df50b6d6c34eb6bd7f1ffb181c4685b5e5f5d415c415dc30f886548ef5842bdf3630231b91f853dd65d36741450709c910d853f8d3d6e9c1d641bc70604205822c46e2aaf538703e90b8fd3aeddd8add10f077e081301e0cfa4e64e36427962063becc26ee33b64334552ed0703b223"
            $hexFile +="b00ed6bf1334906690bfa53f96e6e98fc31a4101ac90482840c6aeac40ef752f0015b6093b900055a0e504f725f7963f0f437c833d402b0f87fbb1637430b9a73ad5317d5e3441b66f532ff1a33adac114243dd635bb0926102bd0081788c4205d7b1be8dacc08bc0a961debdda96f17e816367f6f404245f8ed5a6c7b7f06f4"
            $hexFile +="c607b305cbb5b186d74c5a6abb7c5c89266473edb62e7d2a742e130a8948b1d821dd2199e81a13da136e915512f4b81cc4407cc7b619c372649c104145e005eb46760a2f00e87ef086d979768b951a45e050e47b4d1e76b75f20894d1009551844f9727b3023677fc73605ec0c4004020dde08c8c9919305d00c00c20c3232c8"
            $hexFile +="10b414a6f0049e8c181573c76939a0e9ce8e18427bf6c2276e489d9d75c75a05ac0e6f7c044451c70ee1f71c8b405772330d3ceb0e75db64ecb988134cbd2c34228bc0227ca33afa0474e390cbe9f76dd3c25f101474260405745c902ebf873c6cf5715bfb71b17a4b90eb397660bb751fe571ead70d04019149263bb93bbf75"
            $hexFile +="133261ddeb3a1eaa3a9c7e6c36c924843a76b35cd30df79053b1c289cb70812231d81a077a90b6ff98927483f47476b9087f5c2060073317db0b5c4f23108f7d975a83ef0e5b89d9162820f1c1f633a4274ca6c3f85d6cb0df4c1e051a45cc5b10113ceeb6271e4c0bd895305bc34774b28e6374d9ff34c3170f1f7ddbb48bbf"
            $hexFile +="2c080c540f9402b6c0f7d806076920b6df252787ed67334c1daf10148d50080aebe0dd1a5e4f15050eeee33be7b39734df5653410de3396f5f70ff1183faff89d0743947d7c283e801431cd148dbf6e98e294b74d1f8afff132feb5139059ea9e3f375f5727ec7513ddf6eb948d9afefeb0240448d4001bb416bf14a833cc113"
            $hexFile +="4463ebb16fba19b82d999a66835e06f376934bc4a960866641091c6ac96adfcfff25a9790c0f4fbc82c5c2a01d2170fabb4bec8f26b3b832a2df2d992b9cdeed1fc39e1639c3741748f7d3f71d7d21d0c0099897dec33f8d30df77cba2a68d78ed7c0a52ad81d9963bc40851c707e5b3ddbd791b263089c60c8c337ced5decd2"
            $hexFile +="4489f1baff001131f889ef04f4859b83c7be0948217039d87425c83e6cf872f7d2e0f825cb15017bdbf09f40ffbacc5d20d266d437b833b8a4030207ebcb6f565356f6c086ed7006ce619c656a16ae717361381d872a651655d81285d7e02b47164b4535c4fac1c1e00b8c960538d1a26ded4915248b2837b12946f79f301ae8"
            $hexFile +="a82548657323dd82cb41cd77e62e58285bdb05f735ad1a92036a050925c0c676136e09fd699cd5026a2a1b5d9a74c7dc45f00a203c158e2dbfcfed46acff34a17705f376bac019c7e044167d77f344dcd15ed78a184cbd82929a055265b0918c23fb0b1fcf8303c72c5ea2bfa67413b8e3b15cb61b42661f4418ac17908da7b6"
            $hexFile +="61bfb337360257dbda81026a5c430a13044221d95693402c87ffb4fdfb3d1d49847b35420639de74df3c0376470bf3370288dade75ed330846c70671ebb99fc147ddc88f7d58cf695edf429ff62cf20f562429890ab66dab3d6ce22b2816110530ac0557685c9c057b4092237ccaea589f890d4969101e68ed63a77c1fdf780f"
            $hexFile +="29743104ae6fa8dd86504405968339060f8753b99561d39c8ba015cc761704828ddab67bd0ffe0e098330ff2286e07dd6e53697108917918047106d3ed70ee1e94187e0f48603a65ceb1b1398f58282ef1310bb5e67eac74e31e2c900f2874ef067486ce8c7628b07811625408cff6daeb9b9f0b698f1fddd9992e0fc9bf0cf4"
            $hexFile +="0f912143322459cf8d42c2874fdbe35fd590b003e1c366901fc820c381ad8d1f38459d58d56b020bad63584cda60047a689977d7754c949cc2664cf541b81b47640b8750ba681c237424f8c8d1861389da94b1ec641512c6af909f9fdf054a87f7a137bf6794d7c78e1c6d6fc566fc0f640e0153a55cae1403667f064abd80d1"
            $hexFile +="39d672f0871770bbbb45034c01c20f0f822820c301919ed477221839cb75d9191aaccd2fd00a9fc40f9cd2417d5b48c14b34f7dbe30313dd4c032d5855096a41d1b61fd2c7450b1bfc418bf20cd3b91814625eff982354bac1db770529998418087e141acd68b59ebc104b74f50b9b50c083e2bf46e8cee07b37d3b7fbfc4803"
            $hexFile +="1dfeff4340003040b0abc56038c74561dd73b5039722ac9205d6a61386d4c37544faacba32986dd73eab0ced060ea33113ba0f9a366dcc3202c2f7dc8a9e5b305df75f5908197a0d4496d866b6591c104952f20e30e1f0c2905e5741566463074b45bac28dac4e9552376d7feef6f674111165e87a79415e4182c36e3f4c6ea5"
            $hexFile +="3366103c4898210440c00823ed03c51ec4e0cdacdb6f046e0e103345190629c436000107cc30b394b7d54403ae6599e62961f8565bdd2da396050b7e2ef91be1c876fbd4dbcf118c0b53040cd2d175a1704bd2f47523360c6226d8861f14032c203fd7c1de1f0485c90a53088c0b1295875bc37f2e4c39e30f83e4ce962da910"
            $hexFile +="68eec1fb8d75b049bf40603846b56da395ea332de802e939d66d1f5de100141242864ec9116d63dbd8200e4908405435d739c26dfbb2baf2c74901f808f70245b0d0f060078bcc0e4c7272a6909f7505b78b0ee5ada38e7f25017240171b22212dee9aebafabdfb136c697c3183b35e364c88d261aaed0179203a70fcf2318b7"
            $hexFile +="0699dd6e4808740f7424304152301277b681a33be7254d227cc8038bf476e14db011041821d5eba949f85becc303b0317b7db0ee4d04e676072684f40301c2bcc2db8e2fb8dc5d110ced08756717dbc337dc11e089d24981ca2d84080f86ad45894876a3f9d002b0bf2167f90137020fb7329003641733668502a929d7919868"
            $hexFile +="dff1b06bd8836d049d8b464d09fa41746921130457a663c61b3e8e0c872f7843c543088b50f81706c14ed02f574f28bcfbed02d43d9119c077633d8d06737b3d08753ff0c15e13d8f513ac3daa80acdff19e103d051b0213ba31d2b90bd44178161c0448ac142e99264483d8140e1c75e4d91ff630af3d945bdf77433d926862"
            $hexFile +="60bf3b3d930a757f31d2b908537684ade5e34452d26074b51cbddb263bffd253404f953774653d967d4d59f33e4004921889794d76c38b188e2b130f668f1d8125f1fd3fc73d8c061ee8af608758168b3276642304b0a3105033d9851d2c6ab80453041f0221390b150bffe0c41048fd2403375a507df8f0e061247de8e3ed75"
            $hexFile +="25d7ed7420372e44c661e8b0ef64941a1cf214cd20010e06c111ffb962c5884ba7eeb22fb9518b25f6a41bb1dd1a31f65cdff0b92017e837477cd74929ecfe08eb2ec60709a78d92db8e67eca84e0cdcb71b35f58953f403ec898c29e80fc7086cb504ed8943fc1219fed332617bea195b1b7cffc504f6841d88d41888b38fd1"
            $hexFile +="227101b7b13682baa86d8857b1f7db1bba72ebe49fea179b5eaa095c8bd8c181e17120811f318ef5f943434781163caa961527e3538cecaedd1607b2164638464bc6773fae0cae753f603c3cc0aa16dc2424a6612fcceab8ff5a2bc33d1d4b33d875c6631675646460d1185bc56e3489d92638e07f8c233f8ccf169077587446"
            $hexFile +="cb7f6323e3ca2725f544afb908810f616474eff64204b6648c811d155d91e4eea447c6581cd1e8744a77948dec161ab9045b88100b19cd851dad2f6f59c8d88d15b9a618ef48230b19ad35304288825b1882ef3fee6ac6cd160dd161042b6bb737371224a40cc2db74330b2dc8021bb863123d39063f0bca10a6e38572c6ffd7"
            $hexFile +="4c0eed0087abe8d462755b10c690fad53275da85613fe99b955b80d2363aff6f6fb8060de722e389cd48dfd2b0bf894b0b89f02f9718ba015e02c3203c4914743d891afb62094d784128a882fd6d8fb38ffb08131470891ded80996de30dfc101ec353db9ee0c3be18eb9aff2035cd273484bb86d1770f31c0f0c6c9f760bf0d"
            $hexFile +="c9605e239c674bb71b0c1af739d3a5eb4b0a398433e1e8da74298602ee8ccd48b7feee32965031c03fbe4bb02d2551d25010c924cdb619e9296c26ebd41b50c12469b7012a3615ebdc6ff0d53b5e2a3b194c7230c71b5de7b60b10751b8b18258a114b17cb8a10e11ceb0a4fd75816fc38b7c325f25f53197c576e6470b80d62"
            $hexFile +="94aad05f85601bfacbc9428b5990aebaf5ba4d3f75ef98d31cb5a85fdd826c131309a6ad10698e6d134eecbf51925f7416bbcbbec574267f5f00007e9049895fd811fb7c343bdb90ab7718fa0b5b7430df6341bfc12681e056efa239c1750966819d0b0242b553b1dae9175eb0e249f00931c02febcecf0d5d62b63fd14114b6"
            $hexFile +="01a00077b718084906d22983e90952ad2e50063b4cc8a9672ec037f10c493996c177080348d1ca72d8dea283f22848c875e359f32a08042cffcce8851864caa52b08776968b64317941429258d3a0b16e2408490b69bd15bb335ec28198c01e98b42d082500fd16d768b5c104006172a36047034a1b780037cc32884de0d03dd"
            $hexFile +="676761f420b0b1cbc58280fd39fb75e231db5a1f80a12e341b4caa9528760c9a22bc9cc866411061d0b39de1615bd4c97fec490be44c4c72b6d029c92fc885543385651b8211c228ef1bcdc29ba342093389c0721b42c158c3d6da72a4582113ca1bd266e04e1874663f15058f2171105a790f4489f0616f47c2000f447e4410"
            $hexFile +="06201b811cec6690cfc527c9409b842b244f44a7eeed6eb08f27d2094d16bd4917bacaa0656fc3c275e8baffa18b6d511e457f7c38cf05331c362a003f7f1c59b20bcf45d0fe3f052b1baceb86ca42083f1b2d187ebf403c0f8fc114c0d41cedba41c6060440142ab91236ecbe00743183eac7149291d0288f8c9be6e440c250"
            $hexFile +="d17210ab6c7b8b05662224f7d0661f73f8f0941d4400df1d65269fc9410dc2f646603ba051c860d99d7bc380a04b60d98b81903910dbc9213d6c9e516a1146ca86668b3d54ca28699f4ac8a66b67dc749f4ac8721c2fd29f71fc366c98668f5ed87513ebe61438c2643f41a4c0142c74e5e2020b7507ae3ec761eded02227fe5"
            $hexFile +="5a480c4d8d418f14ffac1f5150483d001080187219b1d876ec4881e90d8309032d091dc2a25fe177e74864145859bff90ab0c16b1ad5070ac8202707fa65eada20830c32cabaaa830c32c89a8a7a6a0c32c8205a4a3a36c820832a120277c820831c6464644106192c07a292685f0691823f05895a06b077c3324f2d87057612"
            $hexFile +="ef8b0c76766263375207422f830db60d0f225712070219e4e420f263e2d264904106c2b2a29041061992827206d916587f0732221d6490411202f26232c820837f626262c820830c626262c1a3063662df3ff96041d85f053cff00e02f400055d961031700008aaa645464c1211b0a0f10301752f2904dff2f0200000876f6c0"
            $hexFile +="0fc02e4fd007108705838c00cd8aa82c26ed395f0055b6006c6962fdffffff67636a2d31362e646c6c005f4a765f5265676973746572436c6173736573f6b1ff902f68696a61636b6d652e5065777002f66f633f00444c4c4819533876696365004d7909ecf30b1b0040854000608007fff609fbe01b401f417267755d6e7420"
            $hexFile +="646f6d615df6ffed696e2044726f722028444f4d41494e291e73ecb76fad1b09a1726974791d5349474e293f876dfff64f7631666c6f7720726120653e4fd67edbfe564552464c4f572450327469616c2022dc2e5b7bf7206f6647676e6966a72d6328504c618fdd23535349546f7425545a61eb9227681072258a85d6bed092"
            $hexFile +="3520746f6f2bb71ab79dfb7609206219701caf656436554e16acfdb04485556e6b6ea3dd475cfbee365f3574680e28293a202548f9766b6fdf052825672c066729203b4574765634dd6fdd3d0c0a2beccbffff3d03a0ac37344dd3bcccdc4d17772d77172e6cdb36347b7576692b2066466c75dfdc136e3f3a0a5f6464916025"
            $hexFile +="702068165a6b0bdf20856a79282db6707bdba4632d6f6e006b566921756b3574b1ed51758d793cbb664425b2d65abb066279c833a80245db261b42b73750d1744b6fbf70983977a06820636f6487307825286c87bd7827fb707275e4d75ea1602264577b113aed3514360b6f3cc3731072c72b2cd92e0a5f3762690fdb870dec"
            $hexFile +="7a652f002e7064246176610c187f406f500f91bc9043f02f30580dd90b79805000005f93900cc9850f7890f2420ec9a84086b88943322417b0a0a872612d24200f1043322443183040b02119b2801f86250f85ec85bcc01ce0857f900dd9903f505ff82ff4900cd9f40ff04743437fabb4b540280e5535d2322e312032307c80"
            $hexFile +="6d5bdb3100381f332e30ca0624ff37303332315f635404361f9f2c808d0a5f0046940aaa2d6edbb9ee011007700a07511103040bdbaeebba6007a9030c0bb007ce1403143540d7750bd007f20328f915d7755db7022203480b30073603680b5dd7755d40079c03700ba007a6037cb600b17b4707231673700759f76c77710390"
            $hexFile +="70075b17337007ae7b5bd40fdfa88f07bd03bbaeebbab40bc007d903bc0be0071519755dd76d03c40b20078603cc0b90afeb5ed707af03d86b07b703dc3b6dbbd77507c303e0bf07a61a03e475cfd5ee2307ab1b530b07df2d552ed803047193f71caeebbacefb0b50075303180b6007baaeebbaa1031c0bb007bc03240bc075"
            $hexFile +="dd33ec07ac1d131707b30340aeebbaee1707c403440bd007d403b710d0bd485f07417c4c5f10cf6ebb07b01f03587107a622ee1976af930b0748242b230767d875db3c25038c0b400712272b0b61d7755d20078a03a40b90070f282bbbd7759d0b1007ac03c447078a297b5df70c1f2307ae03d4170767d8bdaec203d89b0715"
            $hexFile +="2a2b5304ddebba07ab03e0230737ebbaee2dabec77077e03f40b8007ed0cbbaef203fc0b002cf7030472b1ebbace2307d1030c0be007aa2dd735dbce330bc02e03c81c0bd00768b37d5ddb0320232f03ea24726123a2ca5c006edf5541010304050442ffff9bc107620f08000f011300083007600670055004c0022d383bd8d0"
            $hexFile +="0923b02e33d40347f662c0ec148f071f04b737bb04eb1c151f075b020564c8deff040301500108030508320913720c2047160b32052f616f01cf520130b7070f0bb6fd0603000642021760d7030a06bf7dfbff000a72063005600470035002c00f05050ad22c03300260010ff605b2503f17a20b16090000b6fddb1688471078"
            $hexFile +="05000b680427e26740f8c1be3f62170c07000ca241fdffffdd13180a85180310c20c300b600a7009c007d005e003f001507c01f9927fa732e732d984ffd6087308420430036002700b0fc0860d0b27079352c2d8ed07ab0732e9702f139231ca071fa75b4555461d00958caa2aa84246554a5ed98b749813f897e4ec15f6f498"
            $hexFile +="432094073e608705195200700f830c32d88807a0aec20c32c820d8eefe64909383129524369041061950607c4106196494a4be9c1c6490d4e802961632c82083343c50c820830c5e7a8cc1063b2c009c0fb40706196490c2d2deec72729041fc0e9722c820830c2c3a4420830c324e5a62830c32c86c767e880c32c820909aa2"
            $hexFile +="32c82083acb6c0e120830ccad4de97e750d9822a00210bd8449003008f6c05d914900300289080b2456403007b80fc80601140001010170679813db0191fe01b1b5555b64000a72a2a19b040e0c9c19e006007fc8540a059a8aa92ef0062770154a503588225a87f01e344656c65746543500ca81b50e66c530e47e682fa0145"
            $hexFile +="6e0a15466b6fdbff7265654c6962726172790c4737437572112906d40254fb63167b6007b01249641454680513d40f766164134c6173744507b1eddbbf0d4d6f64758848616e640541118ecd807a41b50f53747df697a0c27570496e666f20537973b1d7debea36d54696d30734669360918cdb5db6f08636b436f756f00012d"
            $hexFile +="c1c000b65dd9697ae14c8a76158272c1da6fa0e165d4d6827a0c5059a56dbabb3117035565b152746c9b46db633fd60d365461626c6514436170a372da2db6732726787412516f6bb6ca1d0cc32a573b175b6b3f0937556e7769f4118174ee6d8f6d0a68ff6445786a702dd66d5b6b636e53141006540b6deb9e84b62c611270"
            $hexFile +="546c73f05646825a616e757f3f462c5942a30fde03443d1aa2d6380bed84a86002c243aa102cf6846c917241a017804570cd893d7c912bf3fd6edb443c701963682e00b254831aa25a7b5f5f435f1776475fad11f5cea0721548a0ddddbe0b2469740c675c6d61da7267731fdb68ed0e09162f760a6f625f662fb6fd0c3c0b6c"
            $hexFile +="6331761c0d0bf617b673335f6e705f747970650f955d842843215011616cb07fdb636d646e086d73675f6a630774dd7b1f666d6f64364df26d0a6cb396cc2d546b069575119cc3150addfe0f260fb7d078d6071d66703acb6608ac73742613057749076d248832bc118a6d6370e8c536b8e64112071f656e07101bd6b0cb6dcb"
            $hexFile +="7640004f483754f3648609a2f0002f9aa6ebfe020b02021f00220c44030a1510298037fb1d40240b8b9002186c0433059888783b76c0001478fc03030060fd812d5bcd202f08100000000060b18a940a2a8e81752362da88025e601b415c201c2817b01b400c3879e801374b4191ae2e3676204fb6ec60902200dc8a50602e1b"
            $hexFile +="c20951dd980a9bcf5e2eec262740c02e72283008a76c100e64432827402ed960639370e360733227c873b21c30782c7088f0003236627373866ddb027b4380eb16609f69b22f0883c809739f3a4f60dff796274352540b6804a0ef6cab1cd9442740577327da480699b046770040dbc51b008fb3030100000000000020ff0000"
            $hexFile +="53565755488d351ae4ffff488dbedb4fffff5731db31c94883cdffe85000000001db7402f3c38b1e4883eefc11db8a16f3c3488d042f83f9058a1076214883fdfc771b83e9048b104883c00483e9048917488d7f0473ef83c1048a10741048ffc0881783e9018a10488d7f0175f0f3c3fc415beb0848ffc6881748ffc78a1601"
            $hexFile +="db750a8b1e4883eefc11db8a1672e68d410141ffd311c001db750a8b1e4883eefc11db8a1673eb83e8037213c1e0080fb6d209d048ffc683f0ff743a4863e88d410141ffd311c941ffd311c9751889c183c00241ffd311c901db75088b1e4883eefc11db73ed4881fd00f3ffff11c1e83effffffeb875e4889f7564889f748c7"
            $hexFile +="c600220000b2025357488d4c37fd5e565beb2f4839ce7332565eac3c80720a3c8f7706807efe0f74062ce83c0177e44839ce731656ad28d075df5f0fc829f801d8ab4839ce7303acebdf5b5e4883ec28488dbe00b000008b0709c0744a8b5f04488d8c3000d000004801f34883c708ff15eb02000048958a0748ffc708c074d7"
            $hexFile +="4889f94889faffc8f2ae4889e9ff15dd0200004809c074094889034883c308ebd6ff25c10200004883c428488b2dc6020000488dbe00f0ffffbb00100000504989e141b8040000004889da4889f94883ec20ffd5488d87af01000080207f8060287f4c8d4c24204d8b014889da4889f9ffd54883c428c6052d000000fc488d8e"
            $hexFile +="00f0ffff6a015a4d31c050e81a000000585d5f5e5b488d4424806a004839c475f94883ec80e9d636ffffc356488d350dc2ffff48ad4885c07414515241504883ec28ffd04883c42841585a59ebe55ec378de400000000000d8de400000000000fc85400000000000d8de40000000000000000000000000000000000000000000"
            $hexFile +="00000000000000000000000000000000000000000000000000b040000000000060b0400000000000fc8540000000000040a040000000000000000000000000000000000000000000000000000000000000000000000000002ade4000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="00000000000000000000000098e0000050e00000000000000000000000000000a5e0000060e00000000000000000000000000000b2e0000088e000000000000000000000000000000000000000000000bee00000000000000000000000000000eee0000000000000d0e0000000000000dee0000000000000fce0000000000000"
            $hexFile +="00000000000000000ce1000000000000000000000000000041445641504933322e646c6c004b45524e454c33322e444c4c006d73766372742e646c6c000000005365745365727669636553746174757300004578697450726f6365737300000047657450726f634164647265737300004c6f61644c6962726172794100005669"
            $hexFile +="727475616c50726f74656374000065786974000000d000001400000050ae58ae60ae68aed8ae000000d000001400000050ae58ae60ae68aed8ae00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)

        }
            # Exiting
            return
    }

    if($inputFile -eq "Unattend.xml"){
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists."

        }else{
            Write-Host "[*] Writing $inputFile"

            $hexFile = "3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d227574662d38223f3e0d0a3c756e617474656e6420786d6c6e733d2275726e3a736368656d61732d6d6963726f736f66742d636f6d3a756e617474656e64223e0d0a202020203c73657474696e677320706173733d2277696e646f77735045223e0d0a"
            $hexFile +="20202020202020203c636f6d706f6e656e74206e616d653d224d6963726f736f66742d57696e646f77732d5365747570222070726f636573736f724172636869746563747572653d22616d64363422207075626c69634b6579546f6b656e3d223331626633383536616433363465333522206c616e67756167653d226e657574"
            $hexFile +="72616c222076657273696f6e53636f70653d226e6f6e5378532220786d6c6e733a77636d3d22687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f574d49436f6e6669672f323030322f53746174652220786d6c6e733a7873693d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c5363"
            $hexFile +="68656d612d696e7374616e6365223e0d0a2020202020202020202020203c55736572446174613e0d0a202020202020202020202020202020203c50726f647563744b65793e0d0a20202020202020202020202020202020202020203c57696c6c53686f7755493e416c776179733c2f57696c6c53686f7755493e0d0a20202020"
            $hexFile +="2020202020202020202020203c2f50726f647563744b65793e0d0a2020202020202020202020203c2f55736572446174613e0d0a2020202020202020202020203c55706772616465446174613e0d0a202020202020202020202020202020203c557067726164653e747275653c2f557067726164653e0d0a2020202020202020"
            $hexFile +="20202020202020203c57696c6c53686f7755493e416c776179733c2f57696c6c53686f7755493e0d0a2020202020202020202020203c2f55706772616465446174613e0d0a20202020202020203c2f636f6d706f6e656e743e0d0a20202020202020203c636f6d706f6e656e74206e616d653d224d6963726f736f66742d5769"
            $hexFile +="6e646f77732d506e70437573746f6d697a6174696f6e7357696e5045222070726f636573736f724172636869746563747572653d22616d64363422207075626c69634b6579546f6b656e3d223331626633383536616433363465333522206c616e67756167653d226e65757472616c222076657273696f6e53636f70653d226e"
            $hexFile +="6f6e5378532220786d6c6e733a77636d3d22687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f574d49436f6e6669672f323030322f53746174652220786d6c6e733a7873693d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c536368656d612d696e7374616e6365223e0d0a202020"
            $hexFile +="2020202020202020203c44726976657250617468733e0d0a202020202020202020202020202020203c50617468416e6443726564656e7469616c732077636d3a6b657956616c75653d2231222077636d3a616374696f6e3d22616464223e0d0a20202020202020202020202020202020202020203c506174683e2457696e5045"
            $hexFile +="447269766572243c2f506174683e0d0a202020202020202020202020202020203c2f50617468416e6443726564656e7469616c733e0d0a2020202020202020202020203c2f44726976657250617468733e0d0a20202020202020203c2f636f6d706f6e656e743e0d0a202020203c2f73657474696e67733e0d0a202020203c73"
            $hexFile +="657474696e677320706173733d227370656369616c697a65223e0d0a20202020202020203c636f6d706f6e656e74206e616d653d224d6963726f736f66742d57696e646f77732d4465706c6f796d656e74222070726f636573736f724172636869746563747572653d22616d64363422207075626c69634b6579546f6b656e3d"
            $hexFile +="223331626633383536616433363465333522206c616e67756167653d226e65757472616c222076657273696f6e53636f70653d226e6f6e5378532220786d6c6e733a77636d3d22687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f574d49436f6e6669672f323030322f53746174652220786d6c6e733a"
            $hexFile +="7873693d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c536368656d612d696e7374616e6365223e0d0a2020202020202020202020203c52756e53796e6368726f6e6f75733e0d0a202020202020202020202020202020203c52756e53796e6368726f6e6f7573436f6d6d616e642077636d3a616374696f"
            $hexFile +="6e3d22616464223e0d0a20202020202020202020202020202020202020203c4f726465723e313c2f4f726465723e0d0a20202020202020202020202020202020202020203c506174683e636d64202f632022464f5220256920494e20285820462045204420432920444f2028464f52202f462022746f6b656e733d3622202574"
            $hexFile +="20696e202827766f6c2025693a272920646f20284946202f49202574204e4551202222202849462045584953542025693a5c426f6f7443616d705c426f6f7443616d702e786d6c20526567204144442022484b4c4d5c53595354454d5c43757272656e74436f6e74726f6c5365745c436f6e74726f6c5c53657373696f6e204d"
            $hexFile +="616e616765725c456e7669726f6e6d656e7422202f762041707073526f6f74202f74205245475f535a202f64202569202f6620292929223c2f506174683e0d0a202020202020202020202020202020203c2f52756e53796e6368726f6e6f7573436f6d6d616e643e0d0a2020202020202020202020203c2f52756e53796e6368"
            $hexFile +="726f6e6f75733e0d0a20202020202020203c2f636f6d706f6e656e743e0d0a202020203c2f73657474696e67733e0d0a202020203c73657474696e677320706173733d226f6f626553797374656d223e0d0a20202020202020203c636f6d706f6e656e74206e616d653d224d6963726f736f66742d57696e646f77732d536865"
            $hexFile +="6c6c2d5365747570222070726f636573736f724172636869746563747572653d22616d64363422207075626c69634b6579546f6b656e3d223331626633383536616433363465333522206c616e67756167653d226e65757472616c222076657273696f6e53636f70653d226e6f6e5378532220786d6c6e733a77636d3d226874"
            $hexFile +="74703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f574d49436f6e6669672f323030322f53746174652220786d6c6e733a7873693d22687474703a2f2f7777772e77332e6f72672f323030312f584d4c536368656d612d696e7374616e6365223e0d0a2020202020202020202020203c46697273744c6f676f6e"
            $hexFile +="436f6d6d616e64733e0d0a20202020202020202020202020203c53796e6368726f6e6f7573436f6d6d616e642077636d3a616374696f6e3d22616464223e0d0a202020202020202020202020202020203c4465736372697074696f6e3e414d44204343432053657475703c2f4465736372697074696f6e3e0d0a202020202020"
            $hexFile +="202020202020202020203c436f6d6d616e644c696e653e2541707073526f6f74253a5c426f6f7443616d705c447269766572735c4154495c41544947726170686963735c42696e36345c41544953657475702e657865202d496e7374616c6c3c2f436f6d6d616e644c696e653e0d0a202020202020202020202020202020203c"
            $hexFile +="4f726465723e313c2f4f726465723e0d0a202020202020202020202020202020203c526571756972657355736572496e7075743e66616c73653c2f526571756972657355736572496e7075743e0d0a20202020202020202020202020203c2f53796e6368726f6e6f7573436f6d6d616e643e0d0a202020202020202020202020"
            $hexFile +="20203c53796e6368726f6e6f7573436f6d6d616e642077636d3a616374696f6e3d22616464223e0d0a2020202020202020202020202020202020203c4465736372697074696f6e3e426f6f7443616d702073657475703c2f4465736372697074696f6e3e0d0a2020202020202020202020202020202020203c436f6d6d616e64"
            $hexFile +="4c696e653e2541707073526f6f74253a5c426f6f7443616d705c73657475702e6578653c2f436f6d6d616e644c696e653e0d0a2020202020202020202020202020202020203c4f726465723e323c2f4f726465723e0d0a2020202020202020202020202020202020203c526571756972657355736572496e7075743e66616c73"
            $hexFile +="653c2f526571756972657355736572496e7075743e0d0a20202020202020202020202020203c2f53796e6368726f6e6f7573436f6d6d616e643e0d0a2020202020202020202020203c2f46697273744c6f676f6e436f6d6d616e64733e0d0a2020202020202020202020203c4175746f4c6f676f6e3e0d0a2020202020202020"
            $hexFile +="20202020202020203c50617373776f72643e0d0a20202020202020202020202020202020202020203c56616c75653e6347467a63336476636d51784d6a4d3d3c2f56616c75653e0d0a20202020202020202020202020202020202020203c506c61696e546578743e66616c73653c2f506c61696e546578743e0d0a2020202020"
            $hexFile +="20202020202020202020203c2f50617373776f72643e0d0a202020202020202020202020202020203c456e61626c65643e747275653c2f456e61626c65643e0d0a202020202020202020202020202020203c557365726e616d653e41646d696e3c2f557365726e616d653e0d0a2020202020202020202020203c2f4175746f4c"
            $hexFile +="6f676f6e3e0d0a20202020202020203c2f636f6d706f6e656e743e0d0a202020203c2f73657474696e67733e0d0a3c2f756e617474656e643e0d0a"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)

        }

            # Exiting
            return

    }

    if ($inputFile -eq "lpe.bat") {
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists."

        }else{
            Write-Host "[*] Writing $inputFile"
            $hexFile = "406563686F206F66660D0A7365746C6F63616C0D0A666F72202F4620227573656261636B712064656C696D733D222025256120696E202860776D696320757365726163636F756E7420776865726520276E616D655E3D227573657222272067657420736964205E7C2066696E642022532D22602920646F20280D0A2020202073"
            $hexFile +="6574207369643D2525610D0A290D0A63616C6C203A6164645F7265675F6B6579732025736964250D0A636F7079202F5920433A5C507269764573635C41646D696E5061696E742E6C6E6B20433A5C55736572735C757365725C4465736B746F70203E6E756C0D0A726567207361766520484B4C4D5C53595354454D20433A5C57"
            $hexFile +="696E646F77735C5265706169725C53595354454D202F79203E6E756C0D0A696361636C7320433A5C57696E646F77735C5265706169725C53595354454D202F6772616E7420757365723A52203E6E756C0D0A726567207361766520484B4C4D5C53414D20433A5C57696E646F77735C5265706169725C53414D202F79203E6E75"
            $hexFile +="6C0D0A696361636C7320433A5C57696E646F77735C5265706169725C53414D202F6772616E7420757365723A52203E6E756C0D0A65786974202F620D0A3A6164645F7265675F6B6579730D0A736574207061727365645F7369643D257E310D0A7265672061646420484B45595F55534552535C257061727365645F736964255C"
            $hexFile +="536F6674776172655C506F6C69636965735C4D6963726F736F66745C57696E646F77735C496E7374616C6C6572202F762022416C77617973496E7374616C6C456C65766174656422202F74205245475F44574F5244202F642031202F66203E6E756C0D0A7265672061646420484B4C4D5C534F4654574152455C506F6C696369"
            $hexFile +="65735C4D6963726F736F66745C57696E646F77735C496E7374616C6C6572202F762022416C77617973496E7374616C6C456C65766174656422202F74205245475F44574F5244202F642031202F66203E6E756C0D0A7265672061646420484B45595F55534552535C257061727365645F736964255C536F6674776172655C5369"
            $hexFile +="6D6F6E54617468616D5C50755454595C53657373696F6E735C425750313233463432202F76202250726F7879557365726E616D6522202F74205245475F535A202F642061646D696E202F66203E6E756C0D0A7265672061646420484B45595F55534552535C257061727365645F736964255C536F6674776172655C53696D6F6E"
            $hexFile +="54617468616D5C50755454595C53657373696F6E735C425750313233463432202F76202250726F787950617373776F726422202F74205245475F535A202F642070617373776F7264313233202F66203E6E756C0D0A65786974202F620D0A"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)
        }
    }
    if ($inputFile -eq "savecred.bat") {
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists."

        }else{
            Write-Host "[*] Writing $inputFile"
            $hexFile = "406966202840436F646553656374696F6E203D3D204042617463682920407468656E0A406563686F206F66660A73746172742022222072756E6173202F7361766563726564202F757365723A61646D696E2022636D642E657865202F432065786974220A43536372697074202F2F6E6F6C6F676F202F2F453A4A536372697074"
            $hexFile +="2022257E4630220A676F746F203A454F460A40656E640A575363726970742E4372656174654F626A6563742822575363726970742E5368656C6C22292E53656E644B657973282270617373776F72643132337B454E5445527D22293B0A"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)
        }
    }
    if ($inputFile -eq "AdminPaint.lnk") {
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists."

        }else{
            Write-Host "[*] Writing $inputFile"
            $hexFile = "4C0000000114020000000000C000000000000046ED01000020000000F94766D3C54CD401E070E4E455DCD501F94766D3C54CD401004E000000000000010000000000000000000000000000003B0114001F50E04FD020EA3A6910A2D808002B30309D19002F433A5C000000000000000000000000000000000000005600310000"
            $hexFile +="0000004550E32D100057696E646F777300400009000400EFBE2F4D2E31455017932E0000000B070000000001000000000000000000000000000000E8BA3A00570069006E0064006F0077007300000016005A0031000000000045508C86100053797374656D33320000420009000400EFBE2F4D2E3145502C902E000000C30D00"
            $hexFile +="000000010000000000000000000000000000009C614F00530079007300740065006D0033003200000018005C003200004E00002F4DAC3B200072756E61732E65786500440009000400EFBE2F4DAC3B45506A962E000000509D000000000100000000007400000000000000000007DA0600720075006E00610073002E00650078"
            $hexFile +="006500000018000000290040002500530079007300740065006D0052006F006F00740025005C00730079007300740065006D00330032005C007300680065006C006C00330032002E0064006C006C002C002D003200320035003600360023002E002E005C002E002E005C002E002E005C00570069006E0064006F00770073005C"
            $hexFile +="00530079007300740065006D00330032005C00720075006E00610073002E0065007800650033002F0075007300650072003A00610064006D0069006E0020002F007300610076006500630072006500640020002500770069006E0064006900720025005C00730079007300740065006D00330032005C006D0073007000610069"
            $hexFile +="006E0074002E006500780065001D002500770069006E0064006900720025005C00730079007300740065006D00330032005C006D0073007000610069006E0074002E0065007800650066000000090000A02D00000031535053E28A5846BC4C3843BBFC139326986DCE1100000000000000001300000000000000000000002D00"
            $hexFile +="00003153505355284C9F799F394BA8D0E1D42DE1D5F31100000012000000001300000001000000000000000000000010000000050000A025000000DD0000001C0000000B0000A0774EC11AE7025D4EB7442EB1AE5198B7DD00000060000000030000A058000000000000006D736564676577696E31300000000000905B82A7A9"
            $hexFile +="A4D84AB8763D8D45A508DE868F4BB6DC47EA11A75E000C2973FE5E905B82A7A9A4D84AB8763D8D45A508DE868F4BB6DC47EA11A75E000C2973FE5E00000000"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)
        }
    }
    if($inputFile -eq "CleanUp.ps1"){
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists."

        }else{
            Write-Host "[*] Writing $inputFile"
            $hexFile = "232054686973207363726970742077696C6C20636C65616E20757020616C6C20796F7572206F6C6420646576206C6F6773206576657279206D696E7574652E0A2320546F2061766F6964207065726D697373696F6E73206973737565732C2072756E2061732053595354454D202873686F756C642070726F6261626C79206669"
            $hexFile +="782074686973206C61746572290A0A52656D6F76652D4974656D20433A5C446576546F6F6C735C2A2E6C6F670A"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)
        }
    }

    else{
        if(Test-Path -Path $inputFile){
            Write-Host "$inputFile already exists."

        }else{
            Write-Host "[*] Writing $inputFile"
            $hexFile = "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000"
            $hexFile +="5045000064860300000000000000000000000000f0002f020b02021f002000000010000000a00000a0cb000000b00000000040000000000000100000000200000400000000000000050002000000000000e000000010000000000000030060010000200000000000001000000000000000001000000000000010000000000000"
            $hexFile +="0000000010000000000000000000000000d000001401000000000000000000000050000088020000000000000000000014d1000014000000000000000000000000000000000000000000000000000000f0cd00002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000555058300000000000a00000001000000000000000020000000000000000000000000000800000e055505831000000000020000000b000000020000000020000000000000000000000000000400000e055505832000000000010000000d000000002000000220000000000000000000000000000400000c0"
            $hexFile +="332e393500555058210d240209f7e40acf7f8da4c1f0a500007a1b00000046000049020044ffae6cffc30f1f440000662e0684004883ec28488b0565cc6cefb7340a31d2c70001120e660c3d900399692cdf326fefbadf4a81384d5a74780d011a8915a35f058b0085cefdadfbc07457b90225e8041e2448c7c1ff000b43badd"
            $hexFile +="db0d6c281538333d8902091e6e7bbbcd05848b1008bb325a48102dfdf637dd095c102a833801746531c0acc428c3b901b7dbff8756eba766904863483c4801c8845045150f85fbb6db7772540fb7481895f90b3245060215cdfcfd3d83b8f00e0f860c8b88f8f0f64388fd85c90f95c2e9340f8d0d390b5f7db0073b0c4c7083"
            $hexFile +="787436448b80e891b0ac8d3745df384fb1df37dd38b4e54c8d059e5e51159f06ff8eedcc0da0d905780e0571068944242074bfcd742f755d08d63c907538fefeff35a7804f41554154555756534881ec987ac0b90d23b7efc6a5543689d7f348ab3c3d880f23bcddb945cdea048c6513042530a21df76fffdf9c3106700831ed"
            $hexFile +="4c8b25df700ceb114839c60f84276effb67b2db9e80360ffd448e8f0480fb13348d575e216fbcddd2c3578332f8b0683f801285b112efcdc06ef099cc79f5d00fe6137f6651e5985ed077cc7bd30bdfbc7761749740c45acba0231c9ffd0d8fb7ddbb00f4c025d120fff154f702515f02c3136bbc2fd1b13ec61fd22c663ddc7"
            $hexFile +="1e6c274c4c801f05b1666c703b0b36925a5d5e55eb1521c6c2bf230084d2742c83e1ea271639bffdff6dc093b61080fa207ee64189c84183f0010b22410f44c84bf816e1ebe466a92f7511eb1aafd375c1762a7f0b361bf06f39f7851b36f207e37419f69e5c01b80a2873dbd8363e450b605bc020b81c76fffff625d15c0645"
            $hexFile +="8d6c24014d63ed49c1e5034c89e9b91db4c3ae61db38e445c597a8200f8e196edf9371ba31db1f8b0cdf259cf070017bd711db26f13105dd1914df498980fbffdfadc18ec30117ac4139dc7fce4983ed084ac7442d3ed8f0e43e892d52551b2c136e2fa509ef464837128b0d415c203aedd9b10bea05240c15252c05b71e1b61"
            $hexFile +="b7b90a0abb080585c9afc21edc1e3677f25b0df50b760c34eb5b1d6fffd881c4685b5e5f5d50415dc30f68f48e257465bdf3630231b91f63dd658385141450707c910dd8e3c6d9652f1d041bc706042042eca6d258af538703e90b8fedda8d2dadd10fef6d081301e06aee6433cf425942063bec36be43ec04334552ed0703b2"
            $hexFile +="3a587f28231fd4906690bf852fa73f0ec3961a4101ac904819bbb29a2840ef552f00d826ec00900055a0e597dc5b56043f0f437c833ddcc78edd401b0f7430b9a72ad519c5b27d9b3e9a2ff1a32adac1140cb1aed90d0926101bd008178806ba0aeec4205dcc900a961dde85cddeebdda96f7fb878db260cd6147a40fc346163"
            $hexFile +="1718d91d45e00a2f00e86845f0c3cdda62e507f8cd1e50ac8bbd9bf03c6c7b4979404d7bf86e9f20894d100955184f631330368e9cfd1d05540c4004020d4608052327474e380c002a1032c8c8201c140ed21378321815735fb529cff07647389a6b0d89c227d662bf679de93ef205ac0ed77c0444b9b12ff67d1c8b40bf26ce"
            $hexFile +="653c5d171bfbeb0eb988134c05de2c9c228bc21ede683a920474e3cf20e9ebbeed788b4510ac74260405745c902e5d5bee914926630990eb751f9d9d1dd84d62ea3f97010d216eec24933b27cd6a973a1ec80999b0123a04e66182450e79ec6192b3a61b6e12ff53b96289cb10b0350eb8e12a1a30beffd23de363387476b908"
            $hexFile +="c21dfc20c0cc5c6c4b0bbc572310dd680d1e2f8f0efb89d9f1c1f6f416285344274c46c36cb0df20984c1e057a456c5beeb6275d10711dec0bd89d305bc327ebf8edad242b1bd9ff3cc3170f1f1d14ba485f2c07c63294210da46f02b6c0f7d856afd90c93c117271db7107478b746fb8d50080a664f15650eec25cd3a8ee33b"
            $hexFile +="7f56534117dcfff90d232a1183faff89d0743947dfc2837dbae3dbe801431cd148295374d1f84fff1367eaf8b62feb5139f375f57a7e67516eb948addd79af8feb02412bf1df40448d40014a833cc1b34419b82dbb03ebb16f99fa5623934bc4ba5e06f34900e65692d0be7d41bccfff25e9690caf058985d54f40bde1779b30"
            $hexFile +="b68cef16b3b832a2df2d993e7b3b86e1c79e1e39c3fe48f7d3f77502a6771ddd219f7ec3df77cbd0df8da246d568ed7c0a9a81d93630dbc40899b3ddbdad6707c11b263089c60ccc5decd2e5337c4489f9baff001131859b83edf889ef04c75e09482170c26bf8f439d874257af7d2e0587473fe1308d9617b9fbacc5d20d266"
            $hexFile +="d440e0601b37b833b8ebcb0fd8b09d7456535e7006ce61fc552e0cc71e0a56ae1de72a0550783f6e1655d82b1547164b43ac1f6ce5c1800b2c9e0525dad65e384915248b28d79b62741f9f301ae8a82da855ccb12d18cb410d58058ed676c1fd28350d0892635a05092db16734dbc0095d01b6625a2acc458bc07b151af84f0a"
            $hexFile +="fd8ef5d23c15ce67893f25ace16771045ef3053bba44b6bd6770aebb9df3e43645184c1d679248c611ee9a05b255fb0abfcf162f51d88303bf467413b883db0da163b1661f44184c173efa302e90bf054327d6026b070a34577264430a85645b6d13049b402c87f6eff708ff1da9747b35a20639de74df3c1d2dccd303370228"
            $hexFile +="dade181d1bd875ed3371ebb93fd87423238f7d58f559ebdbe233962cf20ff62429890ab66db5c76ce22b28161105b5e00acd305c9c057b40844f599d9a583f890da95910ad7dec741e1c1fdf780f29743104f50db51b86504405368339060f87652861da533c8ba01376b6ed5e2eb70482d0ffe0e0d8230ff228a0db6dea1041"
            $hexFile +="0971089179180471bb1dcefd0e1e34187e0f48603aa5241c1b5b732a1058282ef1316beec7ea0b74e31dcc900f2874ef0667e8cc587628b0781162f80caf4d94eb9b9f4f0b8f3bc776411f0f0924bf0c940f362417b2d123990f2f28247c184fdbe35f093b10de75c366901fc8201cd8da081f38459d58d5b0d03a366b584cda"
            $hexFile +="60047a68765dc72499349c02664cf541b80b078b2f67badb1dbc2374cfd18664241389da34185621618c8caf909f3f5da07448f7a1371f58ecc8d1f694d76fc5069c0f0430d5c8750e0e14a30635f00b187fd139d672144c87457374dbdd034c01c20f0f82280eea96228cf48cbe1839cb75d9b91a4ccdc47e8156f80f3cd241"
            $hexFile +="7d5b48c1e3037a89d3df13dd4c032db857d57241c7452cdaf6430b1b9c418bf20cd3663b178342ff98237705898c4b3b702e8418087e5e649ea95fa0f0748b109b50c083e2bfe6e6be5da2e8d6e0fbfc48031d5e2a43b5186cef4000304038c745ba4bce75611d38379205362201460fd7d51344faacbad25d2b6518bb5aed06"
            $hexFile +="0e01c358b743315b630a0ce40f67faea41f7c6feeea8596b86dd0819ba228787961cc2d866b6108952f20e905eba30e1f05741566463c28dacf6074b454e35b237f67411116e6d7fee65e87a79415e4182c3a59356ed6e3f4c42dc489821044003c51e2dc00823c4e0cd4cae50ccf66bc09345590629c4366067c00133b334b7"
            $hexFile +="0f7b134b05c7412961f8077e9605a9adb6ba0b7e2e991b81db6fe190edf6112c0b53040cd24bd20da3eb42f47523360c1fbdc51cb01403cc201f0485c9ff7eae830a53088c0b12352e4c39e30ff70fb78683e46e962de9108d75b049bf402bd1dc83603846ea33ba6adb462de802e93981006cdb043f1411a138116911200eb2"
            $hexFile +="6d635d1a4060d5d739baf28bc26dfbc74901f808f70245b0d0cc74f560070dec7272a690e3551bf9ac7b9ba38e7f254162ac8abe6381ae2e0aeb36c697c3183b3543e1fee2ed2a0f8d26920305370f82716ba0cf99dd6e480874c70007340ff2d012173670740dec11254d227cc891de2edc034db011041821d5eba9498b7d78"
            $hexFile +="60f8f0217b7db0ee4ddceec0640484f40301c278dbf1c5bcb8dc5d10aced0875677bf8865b1711e089d24981ca2d8408b0b528710f4876a3f9d0f637e4cc02f90137a20fb7327280ec023366850234523b1298a820f9b0ecc136826b9d8b464d09fa41bab4900904570654e30d1f470cc71f7843c543088b50f80b8360271020"
            $hexFile +="574fdefd768128d43d9119c077633d8d06737b3d08ba1ff8605e1378f5134c3daa80d6ef78cf103d051b02135a31d2b90bd4203c0b0ea4484c13ce9913a241ec13ae1c7584ec0f7b18af3d945b7f77433d926831b0df9d3d930a757f31d2b908533bc2d672e34452d26074b51cde6d931dffd253404f953774653d96bea6acf9"
            $hexFile +="3e400492b8897926bbe1c5188e2b12af668f1dc092f8fe3fc73d8c061ee8b0172c8baf8bd276b2910258a368f033ecc20e166ab80453041f81909c85150bff70620824fd24811b2d287d98f040522496ebf1f67525d7ed742037785d877d27eb26529419bcf214cd207030084611ff19535c3a750fcd122fb9518b25f6dd88ed"
            $hexFile +="42ba31f65cdf90b920bf39e22317d74929ec9e08eb2ec60709364aed468e67044aa84e0c6ed4d49fdc8953f403ec898c29e8b6bab5df0fc7088943fc120c83fed332b03df50c5b1b1cffc504f61d88d4f8841428b38fd1227101b7b1967bbae85d8857b1f7db1bba72ebe49fea179b5eaa095c8bd8c181e17120811f318ef5f9"
            $hexFile +="4343478115dcaa961527e3538c8caedd15a7b215e638464bc6773fae0cae753f603c3cc0aa167c2424a6602fcceab8ff5a2bc33d1d4b19ec3ae31603167564c450d1b1d533c0dc802638e038f2c3887fcf163077587446373632cecbca27259544f81046f6afb90874eff64204c618d811b614fd91e4eef4c8f8451c1571e874"
            $hexFile +="4ab291dd82771ab9045b88c442c69742bdad2f5b1632368d1559a618efd2c842c6ad35302c84f81618e68f38c6ae66cd160d31047b5bbdbdb99124040cc2db74330b2d085c28b081fb123d81193f0bca0a613a5e72c6ffd74c0e88dd0e70b8d462755b103275d01852bbdc4be5513fe961b3720bd27e3aff6fbf6fb885c1aa22"
            $hexFile +="e389cd48894b0b8920dfd2b0f02f9718ba018297a0b54e1e14743d89597dbf584d78418851a8d28f10f9dbde5b69137406891d4d30606e2b691e0b7253bee1b627f818eb9aff20352d27180de1aed1770f31c0f0bfc138193b0d295e73fc677de976831af739d3a5eb4b0a39da74299670261c8602eefeee0b63f3ec32f65098"
            $hexFile +="31c03fbaef126c2551d25010c9c429cc40b36d466eebd41b50c11749da6d2a9615ebdc6f2a027cf58e3b18ec7230c71b1078d7b9ed751b8b78258a114b16bceb0aedb222444fd758c32561b61f915253191c0d4434b691c16294aa30cbc99b0ac136428b5990ae3f75ef2674eb7598331cb50850139cba05d90906ad6059ec8b"
            $hexFile +="8ddd26bf51f24f85167426f976977ddf4f00007e9049e94f348360b023f6db90ab77189adf4517b6e863415fc126813962c1adde61750966819d0b02dae02d6aa7e917fe0931c06c61c5932febce6f3f6e1bbac4d14114b60118084906a04001eed22983e90906e2a55a5d3b4cc8a9670c4939075d806f96c177080348d1ca72"
            $hexFile +="9258b0bd452848c875e359f3ffc8541008ccca2ed00b31452b08776934541908d16c87258d3a0b900f2cc481b69bd1d02cddd66c0d01e98b42d082508b5ced43749b104006172a36048003191c4de87cc32884de677fc340f7619420b0b1cb39fb75e231db4db120605a1f1b4c0bb44c0baad502269cc8c5a029c266411061d0"
            $hexFile +="b3dd191eb6d4c97fec490be44c29c9c824670b2fc88554335a58b62111c228ef1b42da2cbc39093389c0721b42c172c31ab6e6832113ca1bd266027742a066df15458f0e8983d0790f4489f0000f7b3b120f447e441006206690b214c860cf05c90bb449b8244f44a78f27e6deee06d2094d16bd4917bac3a60c5af6c275e8ba"
            $hexFile +="9f4c13ba16291f227c38cf5030c3612a003f7fce9125bbcf45d0fe3f45b7b2c1ba86ca42083fbfbbd182e1403c0f8fc114c041c64bcdd1ae060440142ab900742e61c3ee3183eac7149291d0288f40c0b8694ec250d17210abc1b6b758662224f7d0661f73840f4fd94400df1da5169fc94160d8206c6f3ba051c860d9a0d6b9"
            $hexFile +="370c4b60d98b81903910db9e931cd2c3516a1146ca546768b6d8ca28699f4ac8a69fb976c64d4ac8721c2fd29f71c66fc386668f5ed87513ebe63f4081234c41a4c0142c40572e2e0b7507ae3ec71ad6de2e227fe55a480c4d8d4191a2d4cf1f5150483d3b8016db8efd1872194881e90d8309032d091d58f42b3c77e7486414"
            $hexFile +="58595f5f0136586b5ac5074a0c32c8203a2a1ae4e420830afa55ea90410619dacaba41061964aa9a8a061964907a6a5242196490412a1a0ac8202707fa54e2d2edcb2032c23f05e94a06f66e58064f2d8705d612ef91c1ce0eb25337a20792b0c1b6612f0f6257520741061964423222061b64901202f24fe2166490c107d2c2"
            $hexFile +="779041b6050782724106196462524206196490322212020636d841f2527f52cf41d8c1a1cf4f053cef6103f96000702f400017433654d800000a0fa0ec230b6587900200002fecec81a50f602e4f70073a2c1814ec00cdaaaaec0c4d00000f5151326c6962fdffffff67636a2d31362e646c6c005f4a765f5265676973746572"
            $hexFile +="436c6173736573d8bffd902f4441434c531c76696365004d79093b12bc6c004075e7607007ff7fc23e801b403f417267756d656e7420646f6d6169bbecffdb6e2040726f722028444f4d41494e291e731bd96fdf5a0981726974791d5349474e293f0fdbfeed4f7631666c6f7720726120653e4f56adfdb6fd4552464c4f5724"
            $hexFile +="50327469616c2022bc5db6f6ee206f6647676e6966a32d63285099c21ebb23535349546f742554b5c2d62527681072058a0aad7da1921520746f6f2bb7296f3bf7ed09206219701caf656436554e442c58fb6185556e6b6ea3dd47b9f6dd6d5f3574680e28293a202548f9edd6debe052825672c066729203b4574765675dbdf"
            $hexFile +="ba3d0c0a2bacdbfffffdda0360076c37344dd3037c8c9c4d17772d77172e6cdb36347b7576692b2066466c75dfdc136e3f3a0a5f6464916025702068165a6b0bbf20856a79282db6707bdba4632d6f6e006b566921756b3574b1ed51758d793cbb664425b2d65abb066279c833a80245db261b42b73750d1744b6fbf70983977"
            $hexFile +="a06820636f6487307825286c87bd7827fb707275e4d75ea1602264577b113aed3514360b6f3cc3731072c72b2cd92e0a5f3762690fdb870dec7a652f002e7064246176610c187f306f500f91bc9043802f10485ec80b796040000030834886e442587079218764884076b8792119920bb0a0b2901d92a80090cf0f1d92211918"
            $hexFile +="304070241cb2901f9fe0241f2c6443361c1f757f3f866cc886505ff82ff4a58764c80ff047434340fa5ba5ad280e5535b2322e31203230e7036cdbbb3100381f332e30513620f937303332315f18a322b01f9f65016c545f00378254548d011075dbce7507600a07511103040b60db765dd707a9030c0bb007ce1403140bb5ed"
            $hexFile +="baaed007f203280b00150222aeeb3a03430b30073603680bbaaeebba40079c03700ba007a6037cdbb35df74707bb038460070916038cb667bbb36007f303986007a71703a4ae7b66f72f075d188f0779033bb3ebbab80b8007b503c060072619ebbaee6d03c883074f03d40b50075dd7bdae5703d83b076303dc0b70a87bae76"
            $hexFile +="07461aa723074b80dbbda54cf00b077f1bd3755dd76d4b8007e903080bf007f316001cd0031463e741ebbaaeeb03180b50075c03200b6007afebdeb64c1d0324170753033c17755dd775076403400b700774034450f7baee5f07e103485f07503dc3b34b5e5461074622430b29ea9edb07e8232b2307dcfdeb0cbb6e880be007"
            $hexFile +="b2262b0bc007ecbaceb02a27630b3007af03b06161f7dcce074c281f47072a291f75afeb9e23074e03d0170762ddebbad703d49b07b503d853074bf7baeeb92a6f2307d703e877075dd7756e1e2b8b0b20079203f80ba061e71a7607d62b1b622307712c37db39769d0b80074a2d530b602ed35fd7759d03180b70077b031c0b"
            $hexFile +="2faa32da6c037a20627c5545d8880066b0db7701030405044207620ef6ffff0f08000f011300083007600670055004c002d00923502e36db6ccf33d41403ece024071f37bb044704df1c151f07c0deffb75b0205040301500108030508320913c0821c581b7227bd101dd80b053b520130d8f6bf84b3070603000642021760d3"
            $hexFile +="edff3f2c030a06000a72063005600470035002c00f17c8fef605050ad22c0330026001503f17f66f3fd8a20b160900168847107805000b68042707fb02d8e2673f62170c07ff7703e1000ca23d13180a85180310c20c300b60e44bf6ff0a7009c007d005e003f001507fa732fe5bf305e73208730842043003600270362c6413"
            $hexFile +="0b0f270763b7031b9307ab0732e970c6284b092f071b55194d489b19aaaa6c15001955553265afa20a2c881303d92b79b887ac8844842cc86067061e07320090c1063b500f6807804106196494aac007196490d0e4f6088532c8202722324ec820830c66809620830c32aac4d84e0e32c8f6fe128620166490413c4e00c86083"
            $hexFile +="1d5e0f76078420830c3294a0ae830c32c8bed0e4ee3939c820fc068710649041061c242e9041061938404a41061964525c64061964906e78828c9570904196a087d720a22c0400ec9005ec800300148003b247b62a002880035044d922009e3d407e6011400010101750192083bcc01f801b1b8caa2a5b00cf531595a0400060"
            $hexFile +="49f0e46007fc754090efaa2c54550003aabb00a50348a2a812d47f0144656c65746543707d06d425066c532e01456eb72373410a15472a4375501b50ed7272651c0e63811dc01a2912496414503fd8ed5468056164134c61737445b66fff4e1a0d4d6f64757b48616e6405413603eac51141c80fd95f823a5374d57570496e66"
            $hexFile +="6f205e7bfbf6537973966d54696d307346693609d76ebfc51808636b436f756f00012db4d9766537b3697ad44c8a7615827a825a11503117d4d65e976d08473fd6babb65a352746c8d460d285461626c65b673db6314436170957227267874126618d63e4c6f6f6ba82a3c51fb4950b1173c556e7769e67b6cdb5a1173740a68"
            $hexFile +="f16445786a5a1b736f702dc86e53141024b46ddb06540b6d2c6112620a735bf7546c73e25646757f3fc91212d4a80f34b48062de38f028440521eae7b1276c27c343aa6c837241a0826b8660177b3d7c8377db062c2b443c701963682e6aedcdee00b25418735f5f435f1776d43b6b884c5fa07215fb2eb4465ca02469740c67"
            $hexFile +="5ca3b577776d61da7267730e091621f6337c6c760a6f625f663c0b6c63315fd8bed8761c0d73335f6e705f7479a20c2dd870650f9521fe6d7711551161636d646e086d73675fef7db0c16a6307666d6f64364d32b7d075f26d0a6c546b06955728cc5a7511ddfe0fe359730e180f071d66702cd815dc42cb6608ee4766777823"
            $hexFile +="58e73b076d247c6d637070cd1165e8461207ac618b6d1f656e07cb6dcb7640ee2820360038648609d7fd9f9087f0002f020b02021f00200c42036ff6354d0a15101d40240b30d852007004330576ec20057db000148eed033fb065ff030060010000202f0810000000ec5791b2000a4fb8080fb02e4404ed8802430730c72b20"
            $hexFile +="a05217288274852d448701372e07db828a36c31f902000d46db065dc00608c602e9ef06342e2ba0030030024f0ece5c22740c02e7228100879ca1e8232432627402e70910d3636e350733027833c27cb30782860343d7c0f206273730bc0d270b36d6181eb62609f694f5236d8086b809f384f1becfbde274352540b680490ef"
            $hexFile +="4227936d952340577327a0581bc92044771b000068bb0074a30324000000ff0053565755488d357ae4ffff488dbedb5fffff5731db31c94883cdffe85000000001db7402f3c38b1e4883eefc11db8a16f3c3488d042f83f9058a1076214883fdfc771b83e9048b104883c00483e9048917488d7f0473ef83c1048a10741048ff"
            $hexFile +="c0881783e9018a10488d7f0175f0f3c3fc415beb0848ffc6881748ffc78a1601db750a8b1e4883eefc11db8a1672e68d410141ffd311c001db750a8b1e4883eefc11db8a1673eb83e8037213c1e0080fb6d209d048ffc683f0ff743a4863e88d410141ffd311c941ffd311c9751889c183c00241ffd311c901db75088b1e4883"
            $hexFile +="eefc11db73ed4881fd00f3ffff11c1e83effffffeb875e4889f7564889f748c7c600200000b2025357488d4c37fd5e565beb2f4839ce7332565eac3c80720a3c8f7706807efe0f74062ce83c0177e44839ce731656ad28d075df5f0fc829f801d8ab4839ce7303acebdf5b5e4883ec28488dbe00a000008b0709c0744a8b5f04"
            $hexFile +="488d8c3000c000004801f34883c708ff154b03000048958a0748ffc708c074d74889f94889faffc8f2ae4889e9ff153d0300004809c074094889034883c308ebd6ff25210300004883c428488b2d26030000488dbe00f0ffffbb00100000504989e141b8040000004889da4889f94883ec20ffd5488d87af01000080207f8060"
            $hexFile +="287f4c8d4c24204d8b014889da4889f9ffd54883c428c6052d000000fc488d8e00f0ffff6a015a4d31c050e81a000000585d5f5e5b488d4424806a004839c475f94883ec80e93647ffffc356488d356dc2ffff48ad4885c07414515241504883ec28ffd04883c42841585a59ebe55ec318ce40000000000078ce400000000000"
            $hexFile +="fc7540000000000078ce4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a040000000000060a0400000000000fc7540000000000040904000000000000000000000000000000000000000000000000000000000000000000000000000cacd400000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="00000000000000000000000098d0000050d00000000000000000000000000000a5d0000060d00000000000000000000000000000b2d0000088d000000000000000000000000000000000000000000000bed00000000000000000000000000000eed0000000000000d0d0000000000000ded0000000000000fcd0000000000000"
            $hexFile +="00000000000000000cd1000000000000000000000000000041445641504933322e646c6c004b45524e454c33322e444c4c006d73766372742e646c6c000000005365745365727669636553746174757300004578697450726f6365737300000047657450726f634164647265737300004c6f61644c6962726172794100005669"
            $hexFile +="727475616c50726f74656374000065786974000000c0000014000000f0adf8ad00ae08ae78ae000000c0000014000000f0adf8ad00ae08ae78ae00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            $hexFile +="0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

            # Decode and write it locally
            [byte[]]$bytes = ($hexFile -split '(.{2})' -ne '' -replace '^', '0X')
            $localPath = (pwd).Path
            $fullPath = $localPath+"\"+$inputFile
            [System.IO.File]::WriteAllBytes($fullPath, $bytes)
        }

            # Exiting
            return

    }
}

Function Create-Service{
    Param(
        $serviceName,
        $servicePath,
        $serviceDisplayName
    )
    # Check if the service exists

    if ((get-service).name | select-string $serviceName){
         Write-Host "[*] $serviceName is already running"
    }
    else{
        #If not, create the service
        Write-Host "[*] Creating $serviceName service"
        # No quotes service
        if($serviceName -eq "unquotedsvc"){
            New-Service -Name $serviceName -BinaryPathName $servicePath -StartupType Manual -DisplayName $serviceDisplayName
        }
        # These services needed to be in quotes
        else{
            if($serviceName -eq "svcdll"){
                $servicePath = '"C:\Program Files\DLL Hijack Service\dllhijackservice.exe", "DLL Hijack Service"'
            }
            if($serviceName -eq "daclsvc"){
                $servicePath = '"C:\Program Files\DACL Service\daclservice.exe"'
            }
            if($serviceName -eq "regsvc"){
                $servicePath = '"C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"'
            }
            if($serviceName -eq "filepermsvc"){
                $servicePath = '"C:\Program Files\File Permissions Service\filepermservice.exe"'
            }
            New-Service -Name $serviceName -BinaryPathName $servicePath -StartupType Manual -DisplayName $serviceDisplayName
        }
    }
    return
}

Function Set-ServicePermission(){
    Param(
        $serviceName,
        $serviceSddl
    )

    Write-Host "[*] Setting service permissions"
    sc.exe sdset $serviceName $serviceSddl
    return
}

Function Start-LocalService(){
    Param(
        $serviceName
    )

    # Check if the service is running
    if((Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status -eq "Running"){
        Write-Host "[-] Service $serviceName is already running"
        return
    }
    else{
        Write-Host "[*] Starting Service $serviceName"
        Start-Service -Name $serviceName
    }
}

Function CleanUp-Local(){
    Param(
        $inputFile
    )

    $localPath = (pwd).Path
    $fullPath = $localPath+"\"+$inputFile

    if($inputFile -eq "AdminPaint.lnk" ){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "CleanUp.ps1"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "daclservice.exe"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "dllhijackservice.exe"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "filepermservice.exe"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "insecureregistryservice.exe"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "lpe.bat"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "program.exe"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "savecred.bat"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "Unattend.xml"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $fullPath
    }

    if($inputFile -eq "unquotedpathservice.exe"){
        Write-Host "[-] Removing $fullPath"
        Remove-Item $inputFile
    }
}

# Functions End Here! ----------------------------------------------------------------

# Use this in order to script to work (As Administrator!)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# In order to set up OpenSSH, your machine must be online:
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the sshd service
Start-Service sshd

# OPTIONAL but recommended:
Set-Service -Name sshd -StartupType 'Automatic'

# Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
    Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
} else {
    Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
}

# Script is starting
Write-Host "[*] Initial Setup"
Write-Host "----------------------------------------"

Write-Host "[*] Disabling All Firewall Profiles"
Disable-Firewall

# Create system environment variable
Write-Host "[*] Create system environment variable for password"
[Environment]::SetEnvironmentVariable("AdminP@ssword", "password123", [EnvironmentVariableTarget]::Machine)

# Create users

## Enable Administrator Account
Get-LocalUser -Name "Administrator" | Enable-LocalUser

## 
$user = ''
$password = "password321"

Set-User -user $user -password $password

$groupName = "Users"
Add-LocalGroupMember -Group $groupName -Member $user

$groupName = "Remote Management Users"
Add-LocalGroupMember -Group $groupName -Member $user

$groupName = "Remote Desktop Users"
Add-LocalGroupMember -Group $groupName -Member $user

Get-LocalUser -Name $user | Enable-LocalUser

## admin
$user = 'admin'
$password = "password123"

Set-User -user $user -password $password

$groupName = "Administrators"
Add-LocalGroupMember -Group $groupName -Member $user

Get-LocalUser -Name $user | Enable-LocalUser

## backupuser - secretdumps
$user = 'backupuser'
$password = "backup1"

Set-User -user $user -password $password

$groupName = "Backup Operators"
Add-LocalGroupMember -Group $groupName -Member $user

$groupName = "Remote Management Users"
Add-LocalGroupMember -Group $groupName -Member $user

## fakeadmin - seimpersonateprivilege
$user = 'fakeadmin'
$password = "fakeadmin"

Set-User -user $user -password $password

$groupName = "Remote Management Users"
Add-LocalGroupMember -Group $groupName -Member $user

Set-UserRights -AddRight -Username fakeadmin -UserRight SeImpersonatePrivilege

# Enable Remote Desktop Services
Write-Host "[*] Enable Remote Desktop"
#Restart-Service -Force -DisplayName "Remote Desktop Services"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

# Enable Remote Management Services
if ((Get-Service -Name WinRM -ErrorAction SilentlyContinue).Status -eq "Running"){
         Write-Host "[*] WinRM is already running"
}else{
    Write-Host "[*] Enable WinRM"
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
    winrm quickconfig -quiet
}


# Create some directories
Write-Host "[*] Creating Directories"

$folder = "C:\PrivEsc"
Set-Folder -folder $folder
$folder = "C:\DevTools"
Set-Folder -folder $folder
$folder = "C:\Temp"
Set-Folder -folder $folder
$folder = "C:\Program Files\Unquoted Path Service"
Set-Folder -folder $folder
$folder = "C:\Program Files\Autorun Program"
Set-Folder -folder $folder
$folder = "C:\Windows\Repair"
Set-Folder -folder $folder

# This is for PS History
$folder = "$env:APPDATA\Microsoft\Windows\PowerShell\"
Set-Folder -folder $folder
$folder = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\"
Set-Folder -folder $folder

# Add C:\Temp in $PATH for dll hijacking
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Temp", "Machine")

# Set PS History and grant Read for everybody
# check this file: cat "C:\Users\User\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

Set-PSReadlineOption -HistorySavePath "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# added fakeadmin credentials to this
$password = 'fakeadmin'
echo "$password = ConvertTo-SecureString 'fakeadmin' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('fakeadmin', $password)
Enter-PSSession -ComputerName ComputerName -Credential $cred" > "C:\Users\User\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

# added backupuser credentials to this
$password = 'backup1'
New-Item -ItemType File -Path "C:\DevTools\ConsoleHost_history.txt"
echo "$password = ConvertTo-SecureString 'backup1' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('backupuser', $password)
Enter-PSSession -ComputerName ComputerName -Credential $cred" > "C:\DevTools\ConsoleHost_history.txt"

# Try to find this file with winPEAS! And yes, it will find it.
icacls.exe "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" /grant Users:R

Write-Host "[+] Initial setup complete."

Write-Host "`n###########################################################################################"
Write-Host "#### DLL Hijacking ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Services (DLL Hijacking)"

$inputFile = "dllhijackservice.exe"
$path = "C:\Program Files\DLL Hijack Service\"

Write-File -InputFile $inputFile

#checking hash
$Hash = "fa6e050321f433af0e486acf88eefe32"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath

# Create and Start Service
$service = "svcdll"
Create-Service -serviceName $service -servicePath $fullPath -serviceDisplayName "DLL Hijack Service"
Set-ServicePermission -serviceName $service -serviceSddl "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPLCRCCCLOSW;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
Start-LocalService -serviceName $service

Write-Host "[+] Services (DLL Hijacking) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Services (binPath) ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Services (binPath)"

$inputFile = "daclservice.exe"
$path = "C:\Program Files\DACL Service\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "d62cfe23ad44ae27954d9b054296f2c3"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory for Password Mining
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath

# Create and Start Service
$service = "daclsvc"
Create-Service -serviceName $service -servicePath $fullPath -serviceDisplayName "DACL Service"
Set-ServicePermission -serviceName $service -serviceSddl "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPLCRCCCLOSWDC;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
Start-LocalService -serviceName $service

Write-Host "[+] Services (binPath) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Services (Unquoted Path) ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Services (Unquoted Path)"

$inputFile = "unquotedpathservice.exe"
$path = "C:\Program Files\Unquoted Path Service\Common Files\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "d62cfe23ad44ae27954d9b054296f2c3"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$newfullPath = "C:\Program Files\Unquoted Path Service"
Reset-File-Permission -filePath $newfullPath


# Create and Start Service
$service = "unquotedsvc"
$fullPath = $path+$inputFile
Create-Service -serviceName $service -servicePath $fullPath -serviceDisplayName "Unquoted Path Service"
Set-ServicePermission -serviceName $service -serviceSddl "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPLCRCCCLOSW;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
Start-LocalService -serviceName $service
Write-Host "[+] Services (Unquoted Path) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Services (Registry) ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Services (Registry)"

$inputFile = "insecureregistryservice.exe"
$path = "C:\Program Files\Insecure Registry Service\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "d62cfe23ad44ae27954d9b054296f2c3"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath

# Change registry permission
Write-Host "[*] Changing registry permissions for regsvc.."

# Registry path
$registryPath = "HKLM:\SYSTEM\ControlSet001\services\regsvc"

# Registry value data
$valueData = [byte[]]@(17, 1, 21, 8)

# Create registry key
New-Item -Path $registryPath -Force | Out-Null

# Set registry value
Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $valueData

# Specify the registry key path
$registryKeyPath = "HKLM:\SYSTEM\ControlSet001\services\regsvc"

# Get the current ACL (Access Control List) for the registry key
$acl = Get-Acl -Path $registryKeyPath

# Define the rule for the NT Authority\Interactive group
$rule = New-Object System.Security.AccessControl.RegistryAccessRule(
    "NT AUTHORITY\INTERACTIVE", # Identity
    "FullControl",              # Permissions
    "Allow"                     # Access Control Type
)

# Add the rule to the ACL
$acl.AddAccessRule($rule)

# Set the modified ACL back to the registry key
Set-Acl -Path $registryKeyPath -AclObject $acl

# Create and Start Service
$service = "regsvc"
Create-Service -serviceName $service -servicePath $fullPath -serviceDisplayName "Insecure Registry Service"
Set-ServicePermission -serviceName $service -serviceSddl "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPLCRCCCLOSW;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

# Start Service
Start-LocalService -serviceName $service

Write-Host "[+] Services (Registry) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Services (Executable File) ####"

Write-Host "----------------------------------------"
Write-Host "[*] Configuring Services (Executable File)"

$inputFile = "filepermservice.exe"
$path = "C:\Program Files\File Permissions Service\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "d62cfe23ad44ae27954d9b054296f2c3"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath

# Create and Start Service
$service = "filepermsvc"
Create-Service -serviceName $service -servicePath $fullPath -serviceDisplayName "File Permissions Service"
Set-ServicePermission -serviceName $service -serviceSddl "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPLCRCCCLOSW;;;WD)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
Start-LocalService -serviceName $service
Write-Host "[+] Services (Executable File) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Registry (Autorun) ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Registry (Autorun)"

$inputFile = "program.exe"
$path = "C:\Program Files\Autorun Program\"

# Copy Item
Write-Host "[+] Copying dummy program"
Copy-Item  -Path "C:\Windows\System32\locator.exe" -Destination $inputFile

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath

Write-Host "[*] Adding program to run at startup via registry"
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $registryPath -Name $inputFile -Value $fullPath -PropertyType String -Force

Write-Host "[+] Registry (Autorun) configuration complete."
Write-Host "----------------------------------------"

###########################################################################################
# I couldn't find a way until now to use this vulnerability #
#### Registry (AlwaysInstallElevated) ####
# Write-Host "----------------------------------------"
# Write-Host "[*] Configuring Registry (AlwaysInstallElevated)"
# Write-Host "[*] Enabling AlwaysInstallElevated via registry.."

# # Registry path
# $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"

# # Registry value name
# $valueName = "AlwaysInstallElevated"

# # Registry value data
# $valueData = 1

# # Create or update the registry value
# New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

# Write-Host "[*] Final configuration will run upon restart..."
# Write-Host "[+] Registry (AlwaysInstallElevated) configuration complete."
# Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Password Mining (Registry) ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Password Mining (Registry)"
Write-Host "[*] Adding autologon user to registry.."


$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$valueName = "DefaultUsername"
$valueData = "admin"
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null

$valueName = "DefaultPassword"
$valueData = "password123"
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null

$valueName = "AutoAdminLogon"
$valueData = 0
New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null
Write-Host "[+] Password Mining (Registry) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Password Mining (Configuration Files) ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Password Mining (Configuration Files)"

$inputFile = "Unattend.xml"
$path = "C:\Windows\Panther\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "63f7269bbc53e36d2a8c323721313f9c"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath
Write-Host "[+] Password Mining (Configuration Files) configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Scheduled Tasks ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Scheduled Tasks"

$inputFile = "CleanUp.ps1"
$path = "C:\DevTools\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "9b8377237f5dea36d6af73e3f8f932a2"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path

# Reset Permission to file
$fullPath = $path+$inputFile
Reset-File-Permission -filePath $fullPath

schtasks.exe /Create /F /RU SYSTEM /SC Minute /TN "CleanUp" /TR "powershell.exe -exec bypass -nop C:\DevTools\CleanUp.ps1"  | Out-Null

Write-Host "[+] Scheduled Task configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Startup Applications ####"
Write-Host "----------------------------------------"
Write-Host "[*] Configuring Startup Applications"

$fullPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
Reset-File-Permission -filePath $fullPath

Write-Host "[+] Startup Applications configuration complete."
Write-Host "----------------------------------------"

Write-Host "`n###########################################################################################"
Write-Host "#### Creating final configuration task to complete upon restart ####"
Write-Host "----------------------------------------"
Write-Host "[*] Creating final configuration task to run upon restart..."

###########################################################################################
# # Creating lpe.bat
# Write-Host "`n[*] Creating lpe.bat"
# $inputFile = "lpe.bat"
# $path = "C:\PrivEsc\"

# Write-File -InputFile $inputFile -path $path

# # Checking hash
# $Hash = "a61df3883f400102e17894d7e6177c92"
# Check-Hash -file $inputFile -Hash $Hash

# # Creating Directory
# Set-Folder -folder $path

# # Moving it to $path
# Move-File -file $inputFile -path $path

# #schtasks.exe /Create /RU "SYSTEM" /SC ONLOGON /TN "LPE" /TR "\"C:\PrivEsc\lpe.bat\""

# # Task action script path
# $scriptPath = $path+$inputFile

# # Task action
# $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $scriptPath"

# # Task trigger (ONLOGON)
# $trigger = New-ScheduledTaskTrigger -AtLogon

# # Task principal (Run as SYSTEM)
# $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

# # Register the scheduled task
# Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "LPE" -Force

###########################################################################################
# Creating AdminPaint.lnk
# Write-Host "`n[*] Creating AdminPaint.lnk"
# $inputFile = "AdminPaint.lnk"

# Write-File -InputFile $inputFile -path $path

# # Checking hash
# $Hash = "30b7a4303bcf16936432f30ce13edbb9"
# Check-Hash -file $inputFile -Hash $Hash

# # Creating Directory
# Set-Folder -folder $path

# # Moving it to $path
# Move-File -file $inputFile -path $path

# # Reset Permission to file
# $fullPath = $path+$inputFile
# Reset-File-Permission -filePath $fullPath

###########################################################################################
# Creating savecred.bat #

Write-Host "`n[*] Creating savecred.bat"
$inputFile = "savecred.bat"
$path = "C:\PrivEsc\"

Write-File -InputFile $inputFile -path $path

# Checking hash
$Hash = "5d8190e96d1b2e3230e1fd2409db81db"
Check-Hash -file $inputFile -Hash $Hash

# Creating Directory
Set-Folder -folder $path

# Moving it to $path
Move-File -file $inputFile -path $path


#!#!#!#!#!#!#!#! Remember to change this douglas user #!#!#!#!#!#!#!#!#!#!
icacls.exe C:\PrivEsc\savecred.bat /grant douglas:RX | Out-Null

# schtasks /Create /F /RU "user" /SC ONLOGON /TN "SaveCred" /TR "\"C:\PrivEsc\savecred.bat\""
# Task action script path
$scriptPath = $path+$inputFile

# Task action
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $scriptPath"

# Task trigger (ONLOGON)
$trigger = New-ScheduledTaskTrigger -AtLogon

# Task principal (Run as the specified user)
$user = "douglas"
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive

# Register the scheduled task
Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "SaveCred" -Force

Write-Host "`n###########################################################################################"
Write-Host "#### [-] Cleaning up Locally ####"

# CleanUp-Local -inputFile "AdminPaint.lnk"
# CleanUp-Local -inputFile "CleanUp.ps1"
# CleanUp-Local -inputFile "daclservice.exe"
# CleanUp-Local -inputFile "dllhijackservice.exe"
# CleanUp-Local -inputFile "filepermservice.exe"
# CleanUp-Local -inputFile "insecureregistryservice.exe"
# CleanUp-Local -inputFile "lpe.bat"
# CleanUp-Local -inputFile "program.exe"
# CleanUp-Local -inputFile "savecred.bat"
# CleanUp-Local -inputFile "Unattend.xml"
Move-File -file "Unattend.xml" -path "C:\Temp"
icacls.exe "C:\Temp\Unattend.xml" /grant BUILTIN\Users:R
# CleanUp-Local -inputFile "unquotedpathservice.exe"


# Enable SMB transfer
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name AllowInsecureGuestAuth -Value 1 -PropertyType DWORD -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" SMB1 -Type DWORD -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" SMB2 -Type DWORD -Value 1 -Force

Write-Host "`n###########################################################################################"
Write-Host "[+] Configuration completed successfully."
Write-Host "[+] Please restart Windows to begin."

#Write-Host -NoNewLine '[+] Press any key to continue...';
#Read-Host -Prompt "[!] Please, restart your computer now.[!]`nPress any key to continue..."
