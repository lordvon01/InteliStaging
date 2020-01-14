#####################################################################################

#Script Name: InteliStaging

#Last Modified: 24 October 2019

#Original Creation: 16 October 2019

#Author: Daniel Stuetz & Michael Tiebout

#

#Purpose: To stage the Symantec DLP software

#

#Usage: To stage the Symantec DLP software

#

#Revision History: <date> - <person> - <change>

#16-Oct-2019 - Michael Tiebout - Initial creation
#19-Oct-2019 - Michael Tiebout - Added array, fixed syntax
#21-Oct-2019 - Michael Tiebout - fixed syntax
#24-Oct-2019 - Michael/Daniel - fixed syntax and added features (log write, timestamp)
#25-Oct-2019 - Michael Tiebout - changed DoForReal to Proceed and checking if InteliStaging.log exists or not
#25-Oct-2019 - Michael Tiebout - added additional logging, check for folder on remote machines, loop, and formatting

#

#Version: v1.6

#Requirements:
#UNC path
#PowerShell 5.0 and above
#PowerShell as Administrator

#Useage: To run the script use the following commands.
   #To test if it will reach each server and UNC run .\intelistaging.ps1
   #To run live then run .\intelistaging.ps1 -Proceed 

######################################################################################

param (
    [string]$Logfile  = "C:\InteliStaging.log",
    [switch]$Proceed
)

### Begin Functions ###
Function LogWrite
{
   Param ([string]$logstring)
   $stamp = Get-TimeStamp
   Write-Host "$stamp $logstring"
   Add-content $Logfile -value "$stamp $logstring"
}

## Pulls formatted date for logging
Function Get-TimeStamp {
    
    Return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)   
}


## Used to find the config directory of Symantec DLP
## Returns string with config path of Symantec DLP
Function getInstallPath {

    # Get all drives found in OS. Contains a lot of entries that are not conventional disks
    $Drives = Get-PSDrive
    Foreach ($DriveLetter in $Drives) {

        # Only check for config directory for single drive letters (ex. C, A, D)
        If ($DriveLetter -match "^[A-Z]$") {

            $Drive = "$($DriveLetter):\"    
            # Only check drives that actually have contents. This will exclude drives that are mounted but nothing is there like DVD drives with no disk
            If (Test-Path $Drive) {

                # Look for normal default install path of recent versions
                If (Test-Path "$Drive\Program Files\Symantec\DataLossPrevention\EnforceServer\15.5\Protect\config") {

                    $ConfigPath = "$($Drive)Program Files\Symantec\DataLossPrevention\EnforceServer\15.5\Protect\config"
                    If (Test-Path $ConfigPath) {
                        Write-Host "Config directory for Symantec DLP found under $ConfigPath"
                        Return $ConfigPath
                    }
                    Else { Write-Host "Install directory not found on $Drive" }
                }
                # Look for normal default install path of older versions
                Elseif (Test-Path "$Drive\SymantecDLP") {

                    $ConfigPath = "$($Drive)SymantecDLP\Protect\config"
                    If (Test-Path $ConfigPath) {
                        Write-Host "Config directory for Symantec DLP found under $ConfigPath"
                        Return $ConfigPath
                    }
                    Else { Write-Host "Install directory not found on $Drive" }
                }
                Else { Write-Host "Install directory not found on $Drive" }            
            }

        }
    }
    # Catch all statement and return value of null
    Write-Host "Install directory was not found in the default install directories. Please rerun the script with the -DLPConfig parameter specified."
    Return $null
}

Function getOracleConnectionString ([String]$ConfigDir) {

	$PropertiesFile = "$($ConfigDir)\jdbc.properties"
	$jdbcline = Get-Content $PropertiesFile | Where-Object {$_ -Like "jdbc.dbalias.oracle-thin*" }
	$linearray = $jdbcline.split('@')
	return $linearray[1]
}

### End Functions ###

### Start Main Script ###

#Checking for InteliStaging.log
Test-Path -path $Logfile
if ($Logfile){
Remove-Item $Logfile -erroraction SilentlyContinue
}

$InstallDir = getInstallPath
$tnsalias = getOracleConnectionString $InstallDir

$OraclePassword = Read-Host 'Input protect user password' -AsSecureString

$PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($OraclePassword)
$PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)

$sqlQuery = @'
    spool "c:\DetectionServerList.csv"
	select host from informationmonitor where isdeleted='0';
	spool off;
'@

$sqlQuery | sqlplus -silent protect/$PlainTextPassword@$tnsalias
### End Main Script ###

### Entering Editing File Stage###
""
Write-host "Please review DetectionServerList.csv is present and formatted correctly before moving on."
""
#Pausing script and awaiting "Enter" key
Read-Host -Prompt "Press Enter to continue"

#Loading data from CSV file
#formatting csv file
$computers = New-Object System.Collections.ArrayList
ForEach($line in (Get-Content "C:\DetectionServerList.csv")){
    if($line -match "^(?!HOST)[A-Za-z\d]+") {
        $trimmed = $line.trim()
        $computers.Add($trimmed) > $null
    }

}

#Using existing array that is loaded into PowerShell
foreach ($computer in $computers) {
#Report if UNC is enabled
    If (Test-Path "\\$computer\c$") { LogWrite "UNC is enabled on $computer" }
#Reporting if UNC is disbled
    Else { LogWrite "UNC is disabled on $computer" }
}

#Using existing array that is loaded into PowerShell
foreach ($computer in $computers) {
#Checking for staging folder on the detection servers
    If (Test-Path "\\$computer\c$\DLPStaging") { LogWrite "The directory exists on $computer" }
    Else { LogWrite "The directory does not exist $computer" }
}
""
#Pausing script and awaiting "Enter" key
LogWrite "Review the InteliStaging.log for more details."
""
Read-Host -Prompt "Press Enter to continue - Proceed is $Proceed"

### Copying files to the detection servers###
#LogWrite "Copying the DLP installation files to the detection servers.`n"
foreach ($computer in $computers) {
    if($Proceed){
        LogWrite "Copying files to \\$computer\c$\"
        Copy-Item C:\DLPStaging -Destination \\$computer\c$\  -Recurse
        LogWrite "Copying DLP installation files to $computer is now complete." `n
    }
    else{
        #Test-Path -path C:\DLPStaging
        #LogWrite "The DLPStaging folder does not exist on $computer"
        Copy-Item C:\DLPStaging -Destination \\$computer\c$\  -Recurse -WhatIf -ErrorAction SilentlyContinue
        LogWrite "No installation files were copied to detection servers."
    }
}