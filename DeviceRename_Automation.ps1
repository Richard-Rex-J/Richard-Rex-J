<#PSScriptInfo

.AUTHOR - Richard Rex
.COMPANYNAME - Kyndryl India
.COPYRIGHT

.RELEASENOTES
Version 1.0 - 23 April 2024 -  Original version.
Version 2.0 - 13 March 2024 - Added Check logics to determine if this script needs to proceed or not


.SYNOPSIS

The Requirement is to have a Device Naming Standards when deployed as part of Windows Autopilot (Hybrid Joined). 
This script will allow to rename the hostname of the device according to the convention name CCCYYXXXX with
 - CCC = Country Code with City (based on a value of one registry key)
 - YY = DT (Desktop) or NB (Notebook)
 - XXXX = Last 4 Digits of Serial Number

# Convert this Script as a EXE (Refer https://github.com/MScholtes/PS2EXE)

#>

Write-Host "DeviceRename_Automation"
Write-Host

# --------------------------------------------------------------------
# Variable Section
# --------------------------------------------------------------------
$LogName="DeviceRename.log"
$Log= "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\$LogName"
$CCregistryPath = "HKLM:\SOFTWARE\(Name of your Choice)\CountryWithCityCode\"
$Dest = "$($env:ProgramData)\Microsoft\IntuneManagementExtension"
$CCKeyName = "CountryWithCityCode"
$CountryCode = ""
$ScriptName = "DeviceRename_Automation"
$ScriptDetection ="HKLM:\SOFTWARE\(Name of your Choice)\$ScriptName" #This will act as the detection when deployed From Intune

# --------------------------------------------------------------------
# Check Section
# --------------------------------------------------------------------
# 1: If no value for Country Code then EXIT

If ((Get-ItemProperty -Path $CCregistryPath -Name $CCKeyName) -eq $null) {
    "- $(date) - Country Code not present yet in registry" | out-file $Log1 -append
    "- $(date) - Exit with Warning... check the Citycode Script if implemented from Intune" | out-file $Log1 -append
    Exit 1
}

# 2: Check the Computer name with the Country code

$CountryCode = $((Get-ItemProperty -Path $CCregistryPath -Name $CCKeyName).$CCKeyName)


if($Env:ComputerName -match '...NB]'){ 
 
    # 2.1 If CountryCode isn't ZZZ, that means the hostname has already been renamed

    if($CountryCode -ne "ZZZZZZ"){  
        "- $(date) - Already renamed...Exit" | out-file $Log1 -append
    
        Exit 0
    
    } Else {
    
    # 2.2 If CountryCode isn't ZZZ and current hostname begin by ZZZ, that means the hostname must be updated
    
      if(($Env:ComputerName -match 'ZZZZZZNB') -AND ($CountryCode -ne "ZZZZZZ")){
    
            "- $(date) - Hostname will be update" | out-file $Log -append   
    
     } Else {
    
            "- $(date) - Already renamed ...Exit" | out-file $Log -append
    
            Exit 0
        }
    }
}

if($Env:ComputerName -match '...DT]'){  

    # 2.3 If CountryCode isn't ZZZ, that means the hostname has already been renamed

    if($CountryCode -ne "ZZZZZZ"){  
        "- $(date) - Already renamed...Exit" | out-file $Log -append
        Exit 0
    } Else {
       
    # 2.4 If CountryCode isn't ZZZ and current hostname begin by ZZZ, that means the hostname must be updated
       
        if(($Env:ComputerName -match 'ZZZZZZDT') -AND ($CountryCode -ne "ZZZZZZ")){
       
            "- $(date) - Hostname will be update" | out-file $Log -append   
       
        } Else {
       
            "- $(date) - Already renamed ...Exit" | out-file $Log -append
       
            Exit 0
        }
    }
}


# 3 Checking if this script already executed successfully, if Yes, proceed no further. If no, continue.

$registryPath = "$ScriptDetection"
$registryKey = "Datetime"

# 3.1  Check if the registry key exists

if (Test-Path -Path "$registryPath\$registryKey") {

 Write-Host "The registry key '$registryKey' is present. Exiting script."

  "- $(date) - The registry key is existing. The script should be already executed. Exiting" | out-file $Log -append
    exit 0

} else {
    
    Write-Host "The registry key '$registryKey' is not present. Proceeding with the rest of the script."

  "- $(date) - The registry key doesn't exist. Proceeding with the Script" | out-file $Log -append

}

# 4: Checking the Device Join if it's AD or Entra ID Joined

$ComputerDetails = Get-ComputerInfo
$isAD = $false
$isAAD = $false
if ($ComputerDetails.CsPartOfDomain) {
    $isAD = $true
    $GoodToGo = $false
        "- $(date) - Device is joined to AD domain: $($ComputerDetails.CsDomain)" | out-file $Log -append
} else {
    $GoodToGo = $true
    $subKey = Get-Item "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"
    $guids = $subKey.GetSubKeyNames()
    foreach($guid in $guids) {
        $guidSubKey = $subKey.OpenSubKey($guid);
        $tenantId = $guidSubKey.GetValue("TenantId");
    }
    
if ($null -ne $tenantID) {
$isAAD = $true
         "- $(date) - Device is joined to Entra ID tenant: $tenantID"| out-file $Log -append

    } else {
        "- $(date) - Not part of a Entra ID or AD, Device is in workgroup"| out-file $Log -append
    }
  
  }


"- $(date) ------------------------------------------------------------------------------------------" | out-file $Log -append


# --------------------------------------------------------------------
# Main Section
# --------------------------------------------------------------------

"- $(date) - Current hostname $Env:ComputerName" | out-file $Log -append


# 1 : Getting the Serial Number

$SN = (Get-WmiObject Win32_bios).SerialNumber

"- $(date) - Serial Number is $SN" | out-file $Log -append

"- $(date) - Building the new hostname" | out-file $Log -append

# 2 : Retrieve the Country Code

$NewName = $CountryCode

"- $(date) - Step 1...Country Code set is $CountryCode => $NewName........" | out-file $Log -append
  
# 3 : Preparing the Admin Credentials (Global Admin or Device Admin Credentials which have necessary permissions to Join the device)

$password = "" | ConvertTo-SecureString -asPlainText -Force #Enter the Password
$username = "" #Enter the User ID
[PSCredential] $credential = New-Object System.Management.Automation.PSCredential($username, $password)

# 3.1 : Checking if the credentials are valid

try{

$testConnection = Test-ComputerSecureChannel -Credential $credential -ErrorAction Stop

} Catch{
  	
  "- $(date) - Invalid credentials or unable to connect to the domain. Please check and try again." | out-file $Log -append
exit
}

# 4 : Creating Function to determine the type between Notebook (NB) or Desktop (DT)

Function Get-DeviceDetails
{
Param(
[string]$computer = "localhost"
)

$isLaptop = $false
$type = ""
 
<#  Get the ChassisType of a client computer using Win32_SystemClosure Operating system class

The Following Values are considerd as Laptops (NB)  (8, 9, 10, 11, 12, 14, 18, 21, 31, 32) Rest are considered as Desktop.

Reference: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure

#>

 
if(Get-WmiObject -Class win32_systemenclosure -ComputerName $computer | 
Where-Object { $_.chassistypes -eq 8 -or $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 11 -or $_.chassistypes -eq 12 -or $_.chassistypes -eq 14 -or $_.chassistypes -eq 18 -or $_.chassistypes -eq 21 -or $_.chassistypes -eq 21 -or $_.chassistypes -eq 31 -or $_.chassistypes -eq 32})

{$isLaptop = $true}

# Check if a battery exists 

if(Get-WmiObject -Class win32_battery -ComputerName $computer) 
  {$isLaptop = $true}

$isLaptop

} # end function Get-DeviceDetails

If(get-DeviceDetails) { 
$type = "NB"
$typelog = "NoteBook"}
else {
$type = "DT"
$typelog = "Desktop"
}


$NewName = $NewName + $type

"- $(date) - $Env:ComputerName is a $typelog - $type => $NewName...... " | out-file $Log -append

#Fetch Last 4 Serial number details
# Get the serial number of the device
$serialNumber = (Get-WmiObject Win32_BIOS).SerialNumber

# Extract the last four digits of the serial number
$L4S = $serialNumber.Substring($serialNumber.Length - 4)

"- $(date) - Add last 4 digits => $NewName" | out-file $Log -append

$NewName = $NewName + "$L4S"

"- $(date) - Final name of the device will be $NewName" | out-file $Log -append


# Renaming the Device according to Requirements 


"- $(date) - Starting the Rename-Computer Process" | out-file $Log -append

Try{
 Rename-Computer -NewName $NewName -DomainCredential $credential 

"- $(date) - Execute Rename-Computer Successful" | out-file $Log -append

}
Catch {

"- $(date) - Execute Rename-Computer Failed - $_" | out-file $Log -append

}


#Determining the runtime and detection

 New-Item -Path "$ScriptDetection"
 New-Itemproperty -Path "$ScriptDetection" -Name "Datetime" -value (Get-date) -PropertyType String

"- $(date) - Detection Registry Key Set" | out-file $Log -append
"- $(date) ------------------------------------------------------------------------------------------" | out-file $Log -append

# Prompt the end user to sign out and sign in back to the device


"- $(date) " | out-file $Log -append
"- $(date) - End of script execution..." | out-file $Log -append
"- $(date) ------------------------------------------------------------------------------------------" | out-file $Log -append
Write-Host
Write-Host "End of script execution"

# End Script