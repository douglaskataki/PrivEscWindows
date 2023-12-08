$regpathControl = 'HKLM:\SYSTEM\CurrentControlSet\Services'
Set-ItemProperty -Path ($regpathControl+"\Sense") -Name Start -Value 4
Set-ItemProperty -Path ($regpathControl+"\WdFilter") -Name Start -Value 4
Set-ItemProperty -Path ($regpathControl+"\WdNisDrv") -Name Start -Value 4
Set-ItemProperty -Path ($regpathControl+"\WdNisSvc") -Name Start -Value 4
Set-ItemProperty -Path ($regpathControl+"\WdBoot") -Name Start -Value 4
Set-ItemProperty -Path ($regpathControl+"\WinDefend") -Name Start -Value 4