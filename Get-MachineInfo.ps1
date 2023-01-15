function Get-MachineInfo {
    <#
.SYNOPSIS
Retrieves specific information about one or more computers, using WMI or CIM.
.DESCRIPTION
This command uses either WMI or CIM to retrieve specific information about
one or more computers. You must run this command as a user who has
permission to remotely query CIM or WMI on the machines involved. You can
specify a starting protocol (CIM by default), and specify that, in the
event of a failure, the other protocol be used on a per-machine basis.
.PARAMETER ComputerName
One or more computer names. When using WMI, this can also be IP addresses.
IP addresses may not work for CIM.
.PARAMETER LogFailuresToPath
A path and filename to write failed computer names to. If omitted, no log
will be written.
.PARAMETER Protocol
Valid values: Wsman (uses CIM) or Dcom (uses WMI). Will be used for all
machines. "Wsman" is the default.
.PARAMETER ProtocolFallback
Specify this to automatically try the other protocol if a machine fails.
.EXAMPLE
Get-MachineInfo -ComputerName ONE,TWO,THREE
This example will query three machines.
.EXAMPLE
Get-ADUser -filter * | Select -Expand Name | Get-MachineInfo
This example will attempt to query all machines in AD.
.LINK
https://powershell.org/forums/
.LINK
Get-CimInstance
.LINK
Get-WmiObject

#>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $true)] 
        [Alias('CN', 'MachineName', 'Name')]
        [string[]] $ComputerName = 'localhost',
        [string]$LogFailuresToPath,
        [ValidateSet('Wsman', 'Dcom')]
        [string]$Protocol = "Wsman",
        [switch]$ProtocolFallback
    )
    
    BEGIN {}

    PROCESS {
        foreach ($computer in $computername) {
            if ($protocol -eq 'Dcom') {
                $option = New-CimSessionOption -Protocol Dcom
            }
            else {
                $option = New-CimSessionOption -Protocol Wsman
            }

            try {  
            
                #Establish session
                $session = New-CimSession -ComputerName $computer -SessionOption $option -ErrorAction Stop

                #Query OS
                $os_params = @{'ClassName' = 'Win32_OperatingSystem'; 'CimSession' = $session }
                $os = Get-CimInstance @os_params

                #Query ComputerSystem
                $cs_params = @{'ClassName' = 'Win32_ComputerSystem'; 'CimSession' = $session }
                $cs = Get-CimInstance @cs_params

                #Query LogicalDisk
                $sysdrive = $os.SystemDrive
                $drive_params = @{'ClassName' = 'Win32_LogicalDisk'; 'Filter' = "DeviceID='$sysdrive'"; 'CimSession' = $session }
                $drive = Get-CimInstance @drive_params

                $proc_params = @{'ClassName' = 'Win32_Processor'; 'CimSession' = $session }
                $proc = Get-CimInstance @proc_params | Select-Object -First 1
            
           
                #Close session
                $session | Remove-CimSession
                $props = @{
                    'ComputerName'      = $computer
                    'Operating System'  = $os.Version
                    'SPVersion'         = $os.ServicePackMajorVersion
                    'OSBuild'           = $os.BuildNumber
                    'Manufacturer'      = $cs.Manufacturer
                    'Model'             = $cs.Model
                    'Processors'        = $cs.NumberOfProcessors
                    'Cores'             = $proc.NumberOfLogicalProcessors
                    'RAM'               = ($cs.TotalPhysicalMemory / 1GB)
                    'Architecture'      = $proc.AddressWidth
                    'SysDriveFreeSpace' = $drive.FreeSpace
                }#props
            
                $obj = New-Object -TypeName psobject -Property $props
                Write-Output $obj
            }
            catch {
                Write-Warning -Message "FAILED $Computer on $protocol"
                # Did we specify protocol fallback? If so, try again. If we specified logging, we won't log a problem here - we'll let
                # the logging occur if this fallback also
                # fails
                if($ProtocolFallback){
                    If($Protocol -eq 'Dcom'){
                        $NewProtocol='WsMan'
                    }
                    else{
                        $NewProtocol='Dcom'
                    }#if protocol
                    Write-Verbose "Trying again with new protocol $NewProtocol"
                    $Params=@{ComputerName=$ComputerName; $Protocol=$NewProtocol; $ProtocolFallback=$false}

                    If($PSBoundParameters.ContainsKey('LogFailurestoPath')){
                        $Params+=@{LogFailuresToPath=$LogFailuresToPath}                         
                    }#if logging
                    Get-MachineInfo @Params
                   
                }#if protocolfallback

                 # if we didn't specify fallback, but we did specify logging, then log the error,
                    # because we won't be trying again
                If(!$ProtocolFallback -and  $PSBoundParameters.ContainsKey('LogFailurestoPath')){
                    Write-Verbose "Logging failures to $LogFailurestoPath"
                    $computer | Out-File $LogFailuresToPath -Append
                 }
            } #TryCatch           

        }#foreach
    }#Process

    END {}
}#function
    

