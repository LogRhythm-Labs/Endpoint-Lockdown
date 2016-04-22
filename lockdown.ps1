  #========================================#
  # LogRhythm Labs                         #
  # Workstation Lockdown and Quarantine    #
  # greg . foss [at] logrhythm . com       #
  # v0.1  --  June 2015                    #
  #========================================#

# Copyright 2015 LogRhythm Inc.   
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at;
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.


[CmdLetBinding()]
Param(
    [Parameter(Mandatory=$false,Position=0)]
    [string]$target = '127.0.0.1',
    
    [Parameter(Mandatory=$false,Position=1)]
    [switch]$remote = $false,
    
    [Parameter(Mandatory=$false,Position=2)]
    [string]$username,
    
    [Parameter(Mandatory=$false,Position=3)]
    [string]$password
)

foreach($c in $target){
    # Log the user off
    Function Invoke-Lockdown{

        # Disable Network Interfaces
        $wirelessNic = Get-WmiObject -Class Win32_NetworkAdapter -filter "Name LIKE '%Wireless%'"
        $wirelessNic.disable()
        $localNic = Get-WmiObject -Class Win32_NetworkAdapter -filter "Name LIKE '%Intel%'"
        $localNic.disable()

        $WmiHash = @{}
        if($Private:Credential){
            $WmiHash.Add('Credential',$credential)
        }
        Try{
            $Validate = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $C -ErrorAction Stop @WmiHash).Win32Shutdown('0x0')
        } Catch [System.Management.Automation.MethodInvocationException] {
            Write-Error 'No user session found to log off.'
            Exit 1
        } Catch {
            Throw
        }
        if($Validate.ReturnValue -ne 0){
            Write-Error "User could not be logged off, return value: $($Validate.ReturnValue)"
            Exit 1
        }
    # Lock Workstation
    rundll32.exe user32.dll,LockWorkStation > $null 2>&1
    }
}
if (-Not ($remote)) {
Invoke-Lockdown
} Else {
    if ($remote -eq $true) {
        $scriptName = $MyInvocation.MyCommand.Name
        $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
        Invoke-Command -FilePath "$scriptName" -ComputerName $target -Credential $cred
    }
}
Exit 0