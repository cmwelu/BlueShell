<#
.SYNOPSIS
A Powershell script to acquire various information from a system.

.DESCRIPTION
The script will collect data on a number of different user-definable items from a system.  Data can be collected remotely via PS Remoting (Requires WinRM), or Remote WMI Queries.

.PARAMETER ComputerName
An array of fully qualified computer names to collect data from. If none is specified, the local machine will be collected from.

.PARAMETER PSRemoting
A switch to use PSRemoting as the remote data collection method. This will require WinRM to be enabled on the remote system.

.PARAMETER RemoteReg
A switch to use Remote Registry as the remote data collection method.

.PARAMETER Wmi
A switch to use Remote WMI Queries as the remote data collection method.

.PARAMETER WmiSoft
A switch to query the Win32_Product class. Please see the notes for further information.

.PARAMETER Credential
Alternate credentials to authenticate to the remote systems

.PARAMETER Software
A switch to collect Software information

.PARAMETER Netstat
A switch to collect netstat information

.PARAMETER ComputerInfo
A switch to collect Computer Information

.PARAMETER RunningProcesses
A switch to collect running processes

.PARAMETER Services
A switch to collect services

.PARAMETER Updates
A switch to collect a list of updates

.PARAMETER Features
A switch to collect a list of features

.PARAMETER LocalUsers
A switch to collect a list of Local Users

.PARAMETER DomainUsers
A switch to collect a list of Domain Users - This may take a long time on large domains

.PARAMETER GridView
A switch to output to GridView

.PARAMETER CSV
A switch to output to CSV in the Output\ directory

.EXAMPLE
./BlueShell.ps1 -ComputerInfo -GridView
Gets ComputerInfo from the Local Machine, outputting to Grid View

.EXAMPLE
./BlueShell.ps1 -Software -Features -Updates -PSRemoting -CSV -ComputerName Win7vm
Gets Software, Features and Updates using PS Remoting from Win7vm, outputting to CSV

.EXAMPLE
Get-Content computerList.txt | ./BlueShell.ps1 -RunningProcesses -Netstat -GridView -Wmi
Gets Running Processes and Netstat from computers in computerList.txt using Remote WMI Queries, output to Grid View

.NOTES
The Win32_Product class is not query optimized. Whenever it is queried, a consistency check of all installed packages happens. This essentially runs the installation repair process on every piece of software. 
This is not ideal, and this check will not happen by default in this script. To enable this data source, use the -WmiSoft switch.

.LINK
https://github.com/cmwelu/BlueShell

#>
[CmdletBinding()]
Param(
    [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $ComputerName,
    [switch]$PSRemoting = $false,
    [switch]$RemoteReg = $false,
    [switch]$Wmi = $false,
    [switch]$WmiSoft = $false,
    [switch]$Software = $false,
    [switch]$Netstat = $false,
    [switch]$ComputerInfo = $false,
    [switch]$RunningProcesses = $false,
    [switch]$Services = $false,
    [switch]$Updates = $false,
    [switch]$Features = $false,
    [switch]$LocalUsers = $false,
    [switch]$DomainUsers = $false,
    [switch]$GridView = $false,
    [switch]$CSV = $false,
    [System.Management.Automation.PSCredential]$Credential = (Get-Credential)
)
process
{
    function Get-Software-Wmi($ComputerName, $Credential)
    {
        $software = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_Product | Select-Object Name, Version, @{Name='Publisher'; Expression={$_.Vendor}}, InstallDate, InstallSource, InstallLocation, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $software
    }

    function Get-Feature-Wmi($ComputerName, $Credential)
    {
        $feature = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_OptionalFeature | Select-Object Name, Caption, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $feature
    }
    
    function Get-Feature
    {
        $feature = Get-WmiObject -Class Win32_OptionalFeature | Select-Object Name, Caption
        return $feature
    }

    function Get-Updates-Wmi($ComputerName, $Credential)
    {
        $update = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_QuickFixEngineering | Select-Object Description, HotFixID, InstalledBy, InstalledOn, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $update
    }

    function Get-Updates
    {
        $update = Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object Description, HotFixID, InstalledBy, InstalledOn
        return $update
    }

    function Get-Services-Wmi($ComputerName, $Credential)
    {
        $services = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_Service | Select-Object Name, StartMode, State, Status, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $services
    }

    function Get-Services
    {
        $services = Get-WmiObject -Class Win32_Service | Select-Object Name, StartMode, State, Status
        return $services
    }

    function Get-RunningProcesses-Wmi($ComputerName, $Credential)
    {
        $processes = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_Process | Select-Object Name, CommandLine, ExecutablePath, ProcessId, ParentProcessId, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $processes
    }

    function Get-RunningProcesses($ComputerName, $Credential)
    {
        $processes = Get-WmiObject -Class Win32_Process | Select-Object Name, CommandLine, ExecutablePath, ProcessId, ParentProcessId
        return $processes
    }

    function Get-ComputerInfo-Wmi($ComputerName, $Credential)
    {
       $system = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_ComputerSystem | Select-Object Domain, Manufacturer, Model, Name, TotalPhysicalMemory
       $os = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_OperatingSystem | Select-Object Version
       $proc = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_Processor | Select-Object MaxClockSpeed, @{Name='CPU'; Expression={$_.Name}}, @{Name='PSComputerName'; Expression={$ComputerName}}, @{Name='CPUManufacturer'; Expression={$_.Manufacturer}}
        foreach($property in $system.psobject.Properties)
        { 
            $arguments += @{$Property.Name = $Property.value}
        }
        foreach($property in $os.psobject.Properties)
        { 
            $arguments += @{$Property.Name = $Property.value}
        }
        foreach($property in $proc.psobject.Properties)
        { 
            $arguments += @{$Property.Name = $Property.value}
        }
        $computer = [Pscustomobject]$arguments
       
        return $computer
    }

    function Get-ComputerInfo
    {
       $system = Get-WmiObject -Class Win32_ComputerSystem | Select-Object Domain, Manufacturer, Model, Name, TotalPhysicalMemory
       $os = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Version
       $proc = Get-WmiObject -Class Win32_Processor | Select-Object MaxClockSpeed, @{Name='CPU'; Expression={$_.Name}}, @{Name='CPUManufacturer'; Expression={$_.Manufacturer}}
        foreach($property in $system.psobject.Properties)
        { 
            $arguments += @{$Property.Name = $Property.value}
        }
        foreach($property in $os.psobject.Properties)
        { 
            $arguments += @{$Property.Name = $Property.value}
        }
        foreach($property in $proc.psobject.Properties)
        { 
            $arguments += @{$Property.Name = $Property.value}
        }
        $computer = [Pscustomobject]$arguments
       
        return $computer
    }

    function Get-LocalUsers-Wmi($ComputerName, $Credential)
    {
        $users = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_UserAccount -Filter LocalAccount=true | Select-Object Domain, SID, FullName, Name, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $users
    }

    function Get-LocalUsers
    {
        $users = Get-WmiObject -Class Win32_UserAccount -Filter LocalAccount=true | Select-Object Domain, SID, FullName, Name
        return $users
    }

    function Get-DomainUsers-Wmi($ComputerName, $Credential)
    {
        #This will take a long time to run on large networks!
        $users = Get-WmiObject -Credential $Credential -ComputerName $ComputerName -Class Win32_UserAccount -Filter LocalAccount=false | Select-Object Domain, SID, FullName, Name, @{Name='PSComputerName'; Expression={$ComputerName}}
        return $users
    }

    function Get-DomainUsers
    {
        #This will take a long time to run on large networks!
        $users = Get-WmiObject -Class Win32_UserAccount -Filter LocalAccount=false | Select-Object Domain, SID, FullName, Name
        return $users
    }

    function Get-NetStat
    { 
        #http://blogs.microsoft.co.il/scriptfanatic/2011/02/10/how-to-find-running-processes-and-their-port-number/
        $properties = ‘Protocol’,’LocalAddress’,’LocalPort’ 
        $properties += ‘RemoteAddress’,’RemotePort’,’State’,’ProcessName’,’PID’

        netstat -ano | Select-String -Pattern ‘\s+(TCP|UDP)’ | ForEach-Object {

            $item = $_.line.split(” “,[System.StringSplitOptions]::RemoveEmptyEntries)

            if($item[1] -notmatch ‘^\[::’) 
            {            
                if (($la = $item[1] -as [ipaddress]).AddressFamily -eq ‘InterNetworkV6’) 
                { 
                   $localAddress = $la.IPAddressToString 
                   $localPort = $item[1].split(‘\]:’)[-1] 
                } 
                else 
                { 
                    $localAddress = $item[1].split(‘:’)[0] 
                    $localPort = $item[1].split(‘:’)[-1] 
                } 

                if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq ‘InterNetworkV6’) 
                { 
                   $remoteAddress = $ra.IPAddressToString 
                   $remotePort = $item[2].split(‘\]:’)[-1] 
                } 
                else 
                { 
                   $remoteAddress = $item[2].split(‘:’)[0] 
                   $remotePort = $item[2].split(‘:’)[-1] 
                } 

                New-Object PSObject -Property @{ 
                    PID = $item[-1] 
                    ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                    Protocol = $item[0] 
                    LocalAddress = $localAddress 
                    LocalPort = $localPort 
                    RemoteAddress =$remoteAddress 
                    RemotePort = $remotePort 
                    State = if($item[0] -eq ‘tcp’) {$item[3]} else {$null} 
                } | Select-Object -Property $properties 
            } 
        } 
    }

    function Get-Software-Reg($ComputerName)
    {
        #Does not currently support alternate creds!!!

        Write-Verbose "Opening Registry on: $ComputerName"
        # Credit: https://blogs.technet.microsoft.com/heyscriptingguy/2011/11/13/use-powershell-to-quickly-find-installed-software/
        $Reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey(‘LocalMachine’,$ComputerName) 
        $Regkey=$Reg.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall") 
        $Subkeys=$Regkey.GetSubKeyNames() 
        $Software = @()
        foreach($Key in $Subkeys){
        Write-Verbose "Opening Subkey: $Key"
            $ThisKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\”+$Key 
            $ThisSubKey=$Reg.OpenSubKey($ThisKey) 

            #Only add entries that have a name
            if($ThisSubKey.GetValue("DisplayName") -ne $null)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name “Name” -Value $($ThisSubKey.GetValue(“DisplayName”))
                $Obj | Add-Member -MemberType NoteProperty -Name “Version” -Value $($ThisSubKey.GetValue(“DisplayVersion”))
                $Obj | Add-Member -MemberType NoteProperty -Name “InstallLocation” -Value $($ThisSubKey.GetValue(“InstallLocation”))
                $Obj | Add-Member -MemberType NoteProperty -Name “InstallSource” -Value $($ThisSubKey.GetValue("InstallSource"))
                $Obj | Add-Member -MemberType NoteProperty -Name “Publisher” -Value $($ThisSubKey.GetValue(“Publisher”))
                $Obj | Add-Member -MemberType NoteProperty -Name “PSComputerName” -Value $ComputerName
                $Software += $Obj
            }
        }
        return $software
    }

    function Get-Software($WmiSoft)
    {


        #Get the data from Registry, select and rename fields
        $Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object @{Name='Name'; Expression={$_.DisplayName}}, @{Name='Version'; Expression={$_.DisplayVersion}}, Publisher, InstallDate, InstallSource, InstallLocation, @{Name='PSComputerName'; Expression={$env:computername}}

        #Only get from WMI if the user would like. This can be quite slow, and actually initiates the install/repair operation on ALL software.
        if($WmiSoft)
        {
            #Get the data from WMI, select and rename fields
            $Software +=   Get-WmiObject -Class Win32_Product | Select-Object Name, Version, @{Name='Publisher'; Expression={$_.Vendor}}, InstallDate, InstallSource, InstallLocation, @{Name='PSComputerName'; Expression={$env:computername}}
        }
        $Software = $Software | Select-Object Name, Version, Publisher, InstallDate, InstallSource
        #Select unique entries based on Name
        $Software = $Software | Sort-Object Name -Unique
        return $Software
    }


    #---------------------MAIN--------------------------

    #If no remote computers specified, run on the local computer. Use Get-Software function locally.
    $ComputerInfoOut = @()

    if(!$ComputerName)
    {
        $ComputerName = "localhost"
        if($Software)
        {
            $SoftwareOut = Get-Software($WmiSoft)
        }
        if($Netstat)
        {
            $NetstatOut = Get-NetStat
        }
        if($ComputerInfo)
        {
            $ComputerInfoOut = Get-ComputerInfo
        }
        if($RunningProcesses)
        {
            $RunningProcessesOut = Get-RunningProcesses
        }
        if($Services)
        {
            $ServicesOut = Get-Services
        }
        if($Updates)
        {
            $UpdatesOut = Get-Updates
        }
        if($Features)
        {
            $FeaturesOut = Get-Features
        }
        if($LocalUsers)
        {
            $LocalUsersOut = Get-LocalUsers
        }
        if($DomainUsers)
        {
            $DomainUsersOut = Get-DomainUsers
        }
    }
    elseif($PSRemoting -OR $Wmi -OR $RemoteReg)
    {
        ForEach ($Computer in $ComputerName)
        {
            Write-Verbose "Getting info from $Computer"
            if($PSRemoting)
            {
                    Write-Verbose "Using PSRemoting"
                    if($Software)
                    {
                        $SoftwareOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-Software} -Credential $Credential -ArgumentList $WmiSoft
                    }
                    if($Netstat)
                    {
                        $NetstatOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-Netstat} -Credential $Credential
                    }
                    if($ComputerInfo)
                    {
                        $ComputerInfoOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-ComputerInfo} -Credential $Credential
                    }
                    if($RunningProcesses)
                    {
                        $RunningProcessesOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-RunningProcesses} -Credential $Credential
                    }
                    if($Services)
                    {
                        $ServicesOUt += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-Services} -Credential $Credential
                    }
                    if($Updates)
                    {
                        $UpdatesOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-Updates} -Credential $Credential
                    }
                    if($Features)
                    {
                        $FeaturesOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-Feature} -Credential $Credential
                    }
                    if($LocalUsers)
                    {
                        $LocalUsersOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-LocalUsers} -Credential $Credential
                    }
                    if($DomainUsers)
                    {
                        $DomainUsersOut += Invoke-Command -ComputerName $Computer -ScriptBlock ${function:Get-DomainUsers} -Credential $Credential
                    }
            }
            if($RemoteReg)
            {
                Write-Verbose "Using Remote Reg"
                $Software += Get-Software-Reg $Computer
            }
            if($Wmi)
            {
                Write-Verbose "Using WMI"
                if($Software)
                {
                    if($WmiSoft)
                    {
                        
                        $SoftwareOut += Get-Software-Wmi $Computer $Credential
                    } 
                }
                if($ComputerInfo)
                {
                    $ComputerInfoOut += Get-ComputerInfo-Wmi $Computer $Credential
                }
                if($RunningProcesses)
                {
                    $RunningProcessesOut += Get-RunningProcesses-Wmi $Computer $Credential
                }
                if($Services)
                {
                    $ServicesOut += Get-Services-Wmi $Computer $Credential
                }
                if($Updates)
                {
                    $UpdatesOut += Get-Updates-Wmi $Computer $Credential
                }
                if($Features)
                { 
                    $FeaturesOut += Get-Feature-Wmi $Computer $Credential
                }
                if($LocalUsers)
                {
                    $LocalUsersOut += Get-LocalUsers-Wmi $Computer $Credential
                }
                if($DomainUsers)
                {
                    $DomainUsersOut += Get-DomainUsers-Wmi $Computer $Credential
                }
            }
        }  
    }
    else
    {
        Write-Error "ERROR: You must specify either -PSRemoting, -RemoteReg, or -Wmi when collecting from remote computers."
    }   
}
end
{
    if($GridView)
    {
        if($Software)
        {
            $SoftwareOut | Out-GridView
        }
        if($Netstat)
        {
            $NetstatOut | Out-GridView
        }
        if($ComputerInfo)
        {
            $ComputerInfoOut | Out-GridView
        }
        if($RunningProcesses)
        {
            $RunningProcessesOut | Out-GridView
        }
        if($Services)
        {
            $ServicesOut | Out-GridView
        }
        if($Updates)
        {
            $UpdatesOut | Out-GridView
        }
        if($Features)
        {
            $FeaturesOut | Out-GridView
        }
        if($LocalUsers)
        {
            $LocalUsersOut | Out-GridView
        }
        if($DomainUsers)
        {
            $DomainUsersOut | Out-GridView
        }
    }
    if($CSV)
    {
        if(!(Test-Path Output))
        {
            New-Item -ItemType Directory -Force -Path Output | Out-Null
        }
        if($SoftwareOut)
        {
            $SoftwareOut | Export-Csv -Path Output/Software.csv
        }
        if($NetstatOut)
        {
            $NetstatOut | Export-Csv -Path Output/Netstat.csv
        }
        if($ComputerInfoOut)
        {
            $ComputerInfoOut | Export-Csv -Path Output/ComputerInfo.csv
        }
        if($RunningProcessesOut)
        {
            $RunningProcessesOut | Export-Csv -Path Output/RunningProcesses.csv
        }
        if($ServicesOut)
        {
            $ServicesOut | Export-Csv -Path Output/Services.csv
        }
        if($UpdatesOut)
        {
            $UpdatesOut | Export-Csv -Path Output/Updates.csv
        }
        if($FeaturesOut)
        {
            $FeaturesOut | Export-Csv -Path Output/Features.csv
        }
        if($LocalUsersOut)
        {
            $LocalUsersOut | Export-Csv -Path Output/LocalUsers.csv
        }
        if($DomainUsersOut)
        {
            $DomainUsersOut | Export-Csv -Path Output/DomainUsers.csv
        }
    }
}