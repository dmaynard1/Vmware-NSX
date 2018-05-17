# Author: Askar Kopbayev
#
# Description:  Powershell script to automate validation of NSX-v VTEP connectivity and MTU size along the path.
# Blog post: https://vmnomad.blogspot.com/2017/11/validating-nsx-vtep-connectivity.html
# 
# The script requires vCenter an NSX names and credentials and produces two reports: Detailed and Summary.
# 

# clean up all variables
foreach ($i in (ls variable:/*)) {rv -ea 0 $i.Name}

# Environment variables
$vcName = 'updateMe'
$nsxServerIP = 'updateMe'
$vcUsername = 'updateMe'
$vcPassword =  'updateMe'

# Connect to NSX server
Connect-NsxServer -vCenterServer $vcName -Username $vcUsername -password $vcPassword -ErrorAction SilentlyContinue | Out-Null
 
# validate connection
if(($DefaultNSXConnection.VIConnection.name -eq $vcName) -and ($DefaultNSXConnection.Server -eq $nsxServerIP)){
    Write-host -Fore:green "Connection to NSX server $($DefaultNSXConnection.Server) was established successfully"
}
else{
    Write-host -Fore:red "Connection to NSX server failed. Exiting..."
    Exit
}

sleep 3

# Getting current path
$path = Split-Path -parent $PSCommandPath

# timestamp for report filename
$startTime = (get-date).ToString("yyyy-MM-dd_HH-mm")

#error message definitions
$Fail1 = "The number of receieved packets is less than number of transmitted packets."
$Fail2 = "Zero packets received. This could be wrong MTU size or network misconfiguration"
$Fail3 = "The source VMK MTU is too small to fit largest VXLAN packet"

#ping function
function vtep_ping{
    param(
        [string]$hostname,
        [string]$destIP,
        [string]$source_VMK,
        [string]$size
    )

    $result = ""
    $arguments = @{}
    $esxcli = Get-ESXCLI -vmhost $hostname -V2

    $arguments = $esxcli.network.diag.ping.CreateArgs()
    $arguments.host = $destIP
    $arguments.count = 3
    $arguments.netstack = "vxlan"
    $arguments.df = $true
    $arguments.interface = $source_VMK
    $arguments.size = $size

    try{
        Write-Host -Fore:white "`nPacket size $size"
        $result = $esxcli.network.diag.ping.Invoke($arguments)
        if($result.summary.Transmitted -eq $result.summary.Recieved){
            Write-Host -Fore:green "Ping was successful"
            Return "Pass"
        }
        elseif(($result.summary.Transmitted -$result.summary.Recieved) -gt 0){
            Write-Host -Fore:yellow "Packets transmitted $($result.summary.Transmitted) - Packets received $($result.summary.Recieved)"
            return "Fail1"
        }
        else{
            Write-host -Fore:red "Zero packets received`n"
            Write-Host -fore:yellow "This could be due MTU size or network misoncfiguration`n"
            return "Fail2"
        }
    }
    catch{
        if($_.Exception.Message -match "Message too long"){
            write-host -Fore:red "Ping failed because the source VMK MTU is too small to fit largest VXLAN packet`n"
            return "Fail3"
        }              
    }
}


function host_to_host_ping{
    param(
        [int]$source
    )

    for($i = 0; $i -lt $Hosts_vteps.Count; $i++){
        if($Hosts_vteps[$source].hostName -ne $Hosts_vteps[$i].hostName){
            Write-host "`nsource host: "$Hosts_vteps[$source].hostName "- destination host: "$Hosts_vteps[$i].hostName
            foreach($s_vtep in $Hosts_vteps[$source].vteps){    
                foreach($d_vtep in $Hosts_vteps[$i].vteps){
                    Write-host "Source VMK       $($s_vtep.Name), IP $($s_vtep.IPv4)"
                    Write-host "Destination VMK  $($d_vtep.Name), IP $($d_vtep.IPv4)"
                    $ping64 = vtep_ping -hostname $($Hosts_vteps[$source].hostName) -destIP $d_vtep.IPv4 -source_VMK $s_vtep.name -size 64
                    $ping1572 = vtep_ping -hostname $($Hosts_vteps[$source].hostName) -destIP $d_vtep.IPv4 -source_VMK $s_vtep.name -size 1572
                    
                    #building detailed report
                    $b = New-Object -TypeName psobject
                    $b | Add-Member -MemberType NoteProperty -Name source_host -value $Hosts_vteps[$source].hostName
                    $b | Add-Member -MemberType NoteProperty -Name destination_host -value $Hosts_vteps[$i].hostName
                    $b | Add-Member -MemberType NoteProperty -Name source_VMK -value $s_vtep.Name
                    $b | Add-Member -MemberType NoteProperty -Name source_IP -value $s_vtep.IPv4
                    $b | Add-Member -MemberType NoteProperty -Name destination_vmk -value $d_vtep.Name
                    $b | Add-Member -MemberType NoteProperty -Name destination_IP -value $d_vtep.IPv4

                    switch($ping64){

                        "Fail1" { 
                            $b | Add-Member -MemberType NoteProperty -Name Ping_64 -value "Fail"
                            $b | Add-Member -MemberType NoteProperty -Name Error_Message_64 -value $Fail1
                        }

                        "Fail2" {
                            $b | Add-Member -MemberType NoteProperty -Name Ping_64 -value "Fail"
                            $b | Add-Member -MemberType NoteProperty -Name Error_Message_64 -value $Fail2
                        }
                        "Fail3" {
                            $b | Add-Member -MemberType NoteProperty -Name Ping_64 -value "Fail"
                            $b | Add-Member -MemberType NoteProperty -Name Error_Message_64 -value $Fail3
                        }
                        default {
                            $b | Add-Member -MemberType NoteProperty -Name Ping_64 -value "Pass"
                        }

                    }

                    switch($ping1572){

                        "Fail1" { 
                            $b | Add-Member -MemberType NoteProperty -Name Ping_1572 -value "Fail"
                            $b | Add-Member -MemberType NoteProperty -Name Error_Message_1572 -value $Fail1
                        }

                        "Fail2" {
                            $b | Add-Member -MemberType NoteProperty -Name Ping_1572 -value "Fail"
                            $b | Add-Member -MemberType NoteProperty -Name Error_Message_1572 -value $Fail2
                        }

                        "Fail3" {
                            $b | Add-Member -MemberType NoteProperty -Name Ping_1572 -value "Fail"
                            $b | Add-Member -MemberType NoteProperty -Name Error_Message_1572 -value $Fail3
                        }
                        default {
                            $b | Add-Member -MemberType NoteProperty -Name Ping_1572 -value "Pass"
                        }

                    }

                    $script:detailed_report += $b
                }
            }

            #bulding summary report
            $c = New-Object -TypeName Psobject
            $c | Add-Member -MemberType NoteProperty -Name source_host -value $Hosts_vteps[$source].hostName
            $c | Add-Member -MemberType NoteProperty -Name destination_host -value $Hosts_vteps[$i].hostName

            if(($detailed_report | ?{($_.source_host -eq $Hosts_vteps[$source].hostName) -and ($_.destination_host -eq $Hosts_vteps[$i].hostName)}) -match "Fail"){
                $c | Add-Member -MemberType NoteProperty -Name Result -Value "Fail"
            }
            else{
                $c |  Add-Member -MemberType NoteProperty -Name Result -Value "Pass"
            }
            $script:summary_report += $C
        }
    }
}


# get transportZone-host array
$tz_hosts = @()
Get-NsxTransportZone | %{
    $Props = @{
        tzName = $_.Name
        clusterNames = $_.clusters.cluster.cluster.name
        hostNames = ($_.clusters.cluster.cluster.name | %{get-cluster -name $_ | get-vmhost}).name
    }
    $tz_hosts += New-Object PSObject -Property $Props
}

# iterate through zones/host/vteps
foreach($tz in $tz_hosts){
    Write-host -Fore:magenta "Testing ESXi hosts in Transport Zone $($tz.tzname)"
    
    # reset reporting arrays for each transport zone
    $detailed_report = @()
    $summary_report = @()

    # Collecting host-vteps array
    $Hosts_vteps = @()
    foreach($vmhost in $tz.hostNames){
        #create esxcli object for a host
        $esxcli = Get-ESXCLI -VMHost $vmhost -V2
        $esxVersion = ($esxcli.system.version.get.Invoke()).version

        #collecting VTEP VMK names and IP Addresses
        $vteps = $esxcli.network.ip.interface.list.Invoke() | ?{$_.netstackinstance -eq "vxlan"} | select Name, Enabled, MTU

        #collect IP addresses for each VTEP
        foreach($vmk in $vteps){
            if($esxVersion -eq "6.0.0"){
                $ipv4 = ($esxcli.network.ip.interface.ipv4.get.Invoke() | ?{$_.name -eq $vmk.name}).IPv4Address
            }
            else{
                $ipv4 = ($esxcli.network.ip.interface.ipv4.address.list.Invoke() | ?{$_.name -eq $vmk.name}).IPv4Address
            }
            $vmk | Add-Member -MemberType NoteProperty -Name IPv4 -Value $ipv4 -force
        }

        # update Host-VTEP array with host name and VTEP info
        $a = New-Object -TypeName psobject
        $a | Add-Member -MemberType NoteProperty -Name hostName -Value $vmhost
        $a | Add-Member -MemberType NoteProperty -Name vteps -Value $vteps
        $hosts_vteps += $a
    }


    for($i = 0; $i -lt $Hosts_vteps.Count; $i++){
        host_to_host_ping -source $i
        Write-host
    }

    # Exporing reports
    $detailedFileName = $startTime + "_" + $($tz.tzName) + "_detailed_report.csv"
    $detailedFilePath = Join-Path -Path $path -ChildPath $detailedFileName

    $summaryFileName = $startTime + "_" + $($tz.tzName) + "_summary_report.csv"
    $summaryFilePath = Join-Path -Path $path -ChildPath $summaryFileName

    Write-host "Detailed report for transport zone $($tz.tzName) is exported to $detailedFilePath file"
    write-host "Summary report for transport zone $($tz.tzName) is exported to $summaryFilePath file"
    $detailed_report | Export-Csv -Path $detailedFilePath -NoTypeInformation
    $summary_report | Export-Csv -Path $summaryFilePath -NoTypeInformation

    if($summary_report -match "Fail"){
        write-host -fore:red "There were issues detected in transport zone $($tz.tzName) during VTEP validation test, please check reports for details"
    }
    else{
        write-host -fore:green "No issues were detected in transport zone $($tz.tzName) during VTEP validation test"
    }
}