#BlueShell

##Overview
This PowerShell script will utilize a few different methods to acquire various information on a system. 

This script can utilize a number of methods to acquire the data from remote systems. PSRemoting can be utilized, and requires WinRM to be running on the remote system. Additionally, Remote Registry or Remote WMI Queries can be used. The user can select which method(s) are appropriate for the network to be scanned.

This PowerShell script has been tested on Windows 10 with PowerShell 5, collecting from various PowerShell versions and operating systems to include:
* Windows 7
* Windows 8
* Windows 10
* Windows Server 2008R2
* Windows Server 2012
* Windows Server 2012R2

Note: This script was created during Dakota State University's CSC-842 Rapid Tool Development course.

##Usage
```PowerShell
 .\BlueShell.ps1 [[-ComputerName] <String[]>] [-PSRemoting] [-RemoteReg] [-Wmi] [-WmiSoft] [-Software] [-Netstat] [-ComputerInfo] [-RunningProcesses] [-Services] [-Updates] [-Features] [-LocalUsers] [-DomainUsers] [-GridView] [-CSV] [[-Credential] <PSCredential>] [<CommonParameters>]
```
For detailed help and examples, run 
````PowerShell
Get-Help .\BlueShell.ps1
````
##Known Issues
The Win32_Product class is not query optimized. Whenever it is queried, a consistency check of all installed packages happens. This essentially runs the installation repair process on every piece of software. 
This is not ideal, and this check will not happen by default in this script. To enable this data source, use the -WmiSoft switch.

##Future Work
* Utilize threading to collect from multiple computers concurrently

##Resources
* [Video Demo](https://www.youtube.com/watch?v=LtG1F85BdyM&feature=youtu.be)
