<#==============================
Fail2Ban4W / Fail To Ban For Windows

06.12.2024 murats => sakarmurat@hotmail.com / You can contact me from this e-mail address
V:1.0.0


This script was developed to detect and block IP addresses of those who tried wrong passwords xx2 times in xx1 time period.
The values ​​in question are variable. You can change these values.
Blocked IP addresses (default values) If there are less than 50 password attempts in 24 hours, temporary blocking is applied, if there are more than 50 wrong password attempts, permanent blocking is applied.
Temporarily blocked IP addresses are removed after 6 hours.
This script is set to run every 10 minutes. You can review the codes below to change the values
By default, it is set to run under the "C:\script\" folder. It has not been tested to work in any other folder.
This script has been tested on Windows2012Server_x64, Windows2019Server_x64 and Windows11EnterpriseLTSC_x64 systems.
All these movements are recorded.
You can send an e-mail to ask your questions about the subject.

+++++++++++++++++++++++++++++
+++   A T T E N T I O N   +++
+++++++++++++++++++++++++++++
#>
#If you set this parameter to "$false" and then run this script, all database and firewall settings will return to default
#Blocked IP addresses will be unban and all records will be deleted. If the parameter is $false this script will not work
#=============
$status=$true
#=============
<#
+++++++++++++++++++++++++++++
+++   A T T E N T I O N   +++
+++++++++++++++++++++++++++++
#>


#==============================
#----------
$RunPath = "c:\script\" #Should be the path where the script runs
$Last_Hours=24 #How long ago was the last attack check? Min value = 1
$WhiteList="10.10.10.10,10.10.10.11","95.130.171.243" # IP addresses that will not be blocked. You should only enter the IPv4 ip address. Please make sure that the IP addresses you enter here are in the correct format
$NOA=10 #Number of Attempts / How many times has the above been tried over time. Max value = 49. A real user cannot make more than 50 wrong IP attempts in 24 hours.
$Database = $Runpath+"IP_BAN_DB" # Default > c:\script\IB_BAN_DB
$DeleteLog=365 #Delete logs from xx days ago
$DeleteRawData=365 #Delete Raw data (all IP addresses trying) from xx days ago
$TemporaryBlockHours=12 # Hour(s) to be temporarily blocked
$PermanentlyDays=90 #Day(s) to be permanently blocked
$TaskName = "F2B4W"
#----------
#==============================
cls
cd $RunPath

function WriteLog {
    param(
        [string]$LogMessage
    )
    $Query = "insert into Log (LogDate, LogMessage) values ( datetime(CURRENT_TIMESTAMP, 'localtime'), '"+$LogMessage+"')"
    Invoke-SqliteQuery -DataSource $Database -Query $Query

}

$SQLite_Install=(Get-InstalledModule -name SQLite | select -ExpandProperty Name )
$SQLite_Version=(Get-InstalledModule -name SQLite | select -ExpandProperty Version )


If  ( ($SQLite_Install -eq "SQLite") )  {
$Update_Check = Get-Date -Format HH
   if ($Update_Check -eq "20") {
        WriteLog "The latest version will be checked and updated"
        Update-Module -name SQLite
        Update-Module -name PSSQLite
   }
} else {
WriteLog "SQLite is not installed. It will now try to auto-install" 
 
Install-Module PSSQLite -Confirm:$false -Force 
Install-Module SQLite -Confirm:$false -Force 

}

#Clearing the log table
$Query = "select count(*) as count from Log where LogDate < datetime('now', '-"+ $DeleteLog +" day')"
$Count = (Invoke-SqliteQuery -DataSource $Database -Query $Query).Count
    if ( $Count -gt 0 ) {
        $Query = "Delete from Log where LogDate < datetime('now', '-"+ $DeleteLog +" day')"
        Invoke-SqliteQuery -DataSource $Database -Query $Query 
        $a = $Count.ToString() + " record(s) deleted from log table"
        WriteLog $a
     }
#Clearing the RawData table
$Query = "select count(*) as count from RawData where ActionTimeStamps < datetime('now', '-"+ $DeleteLog +" day')"
$Count = (Invoke-SqliteQuery -DataSource $Database -Query $Query).Count
    if ( $Count -gt 0 ) {
        $Query = "Delete from RawData where ActionTimeStamps < datetime('now', '-"+ $DeleteLog +" day')"
        Invoke-SqliteQuery -DataSource $Database -Query $Query 
        $a = $Count.ToString() + " record(s) deleted from RawData table"
        WriteLog $a
     }


if ($status -eq $true) 
{
    #Check Event Log
    $badRDPlogons = Get-EventLog -LogName ‘Security’ -after ([DateTime]::Now.AddHours(-$Last_Hours)) -InstanceId 4625 |  Select-Object @{n = ‘IpAddress’; e = { $_.ReplacementStrings[-2] } }
    $getip = $badRDPlogons | group-object -property IpAddress | Where-Object { $_.Count -gt $NOA } | Select-Object -property Name
    #$getip
    $Query = 'delete from TempData'
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    WriteLog "TempData table cleared"

    
    #import TempData
    foreach ($ip in $getip) {
             $Query = "insert into TempData (ActionTimeStamps, IPAddress, AttemptCount ) values ( datetime(CURRENT_TIMESTAMP, 'localtime'), '" + $ip.name + "', "+ ($badRDPlogons | Where-Object { $_.IpAddress -eq $ip.name }).count +"  )"
             Invoke-SqliteQuery -DataSource $Database -Query $Query
             
    }
    $a=$getip.Count.ToString()+" IP addresses added to TempData table"
    WriteLog -LogMessage $a
    sleep 2
    $Query = "Insert Into  RawData (ActionTimeStamps, IPAddress, AttemptCount) select ActionTimeStamps, IPAddress, AttemptCount from TempData"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    WriteLog "TempData table imported into RawData table"

    #except WhiteList
    $regex = [regex] "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    $ValidIP = $regex.Matches($WhiteList) | %{ $_.value }

    $Query = "Delete from WhiteList"
    Invoke-SqliteQuery -DataSource $Database -Query $Query

    
    Foreach ($i in $ValidIP) {
            $Query = "insert into WhiteList (IPAddress) values ('"+$i.ToString() +"')"
            Invoke-SqliteQuery -DataSource $Database -Query $Query
        }
    WriteLog "WhiteList table updated"
    sleep 1
    
    # TempFWBlockList  
          

    $Query = -join @("
          
        insert into TempFWBlockList (IPAddress,BlockType) 
        --Continually
          Select IPAddress, 'Continually' as BlockType from
          (Select IPAddress from(--WhiteList Control - Continually IP Block
                                      SELECT * FROM TempData
                                      where IPAddress in (SELECT IPAddress FROM TempData  except  Select IPAddress from WhiteList)
                                      and AttemptCount > 50 
                                  
                                  ) as WhiteListCheck
           except 
           Select TempFWBlockList.IPAddress from TempFWBlockList where BlockType = 'Continually'  ) 
           
       union 
       -- Temp
          Select IPAddress, 'Temp' as BlockType from
          (Select IPAddress from(--WhiteList Control - Temp IP Block
                                      SELECT * FROM TempData
                                      where IPAddress in (SELECT IPAddress FROM TempData  except  Select IPAddress from WhiteList)
                                      and AttemptCount < 50 
                                  ) as WhiteListCheck
           except 
           Select TempFWBlockList.IPAddress from TempFWBlockList ) 

        ")
    Invoke-SqliteQuery -DataSource $Database -Query $Query


    $QueryCount = -join @("select count(*) as count from (
                    select IPAddress, BlockType from TempFWBlockList
                    except
                    select IPAddress, BlockType from FWBlockList
                    )")
    $Count1 = Invoke-SqliteQuery -DataSource $Database -Query $QueryCount
    
    $a = "Checked FWBlockList table and recorded necessary updates. " + $Count1.'count'  + " added record(s)" 
    if ($Count1.'count' -gt 0 ) { 
        WriteLog $a 
     

    $Query = -join @("insert into FWBlockList (IPAddress,BlockType)
                     select IPAddress, BlockType from TempFWBlockList
                     except
                     select IPAddress, BlockType from FWBlockList
                     ")
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    
    }
 
     $Query = -join @(" select count(*) as count  from FWBlockList where Blocktype = 'Temp' and DateAdded < datetime('now', '-"+$TemporaryBlockHours+" hour') ")
     $QueryCount = Invoke-SqliteQuery -DataSource $Database -Query $Query
     

     if ($QueryCount.count -gt 0) {
        $Query = -join @("delete from FWBlockList where Blocktype = 'Temp' and DateAdded < datetime('now', '-"+$TemporaryBlockHours+" hour')")
        Invoke-SqliteQuery -DataSource $Database -Query $Query
        $a = "Temporarily blocked IP addresses have been checked."+$QueryCount.'count'+" IP addresses from "+$TemporaryBlockHours+" hour(s) ago have been removed"
        WriteLog $a
    }




     $Query = -join @(" select count(*) as count  from FWBlockList where Blocktype = 'Continually' and DateAdded < datetime('now', '-"+$PermanentlyDays+" day') ")
     $QueryCount = Invoke-SqliteQuery -DataSource $Database -Query $Query
     

     if ($QueryCount.count -gt 0) {
        $Query = -join @("delete from FWBlockList where Blocktype = 'Continually' and DateAdded < datetime('now', '-"+$PermanentlyDays+" day')")
        Invoke-SqliteQuery -DataSource $Database -Query $Query
        $a = "Continually blocked IP addresses have been checked. "+$QueryCount.'count' +"IP addresses from "+$PermanentlyDays+" day(s) ago have been removed"
        WriteLog $a
    }
    sleep 1

    #Duplicate
     $Query = -join @("delete from FWBlockList where RefID in 
                        (
                            select RefID from FWBlockList 
                            where FWBlockList.IPAddress  in 
                            (select aaa.IPAddress from 
                                (
                                    (
                                    select IPAddress, count(IPAddress) as 'RepeatIP', BlockType from FWBlockList 
                                    group by IPAddress
                                    HAVING  (RepeatIP >1) 
                                    )
                                ) as aaa
                            ) and BlockType = 'Temp'
                        )
                                  
                     ")
     Invoke-SqliteQuery -DataSource $Database -Query $Query

    
    if ( -Not $(Get-NetFirewallRule -DisplayName "_F2B4W" )) 
    {
         New-NetFirewallRule -DisplayName "_F2B4W" –RemoteAddress "127.127.127.127" -Direction Inbound -Protocol TCP -Action Block
    } 

 
     $Query = -join @(" select IPAddress  from FWBlockList")
     $BlockIPs = Invoke-SqliteQuery -DataSource $Database -Query $Query

     
     Set-NetFirewallRule -DisplayName “_F2B4W” -RemoteAddress $BlockIPs.'IPAddress'
     WriteLog "Firewall rule updated"


$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $RunPath"f2b4w.ps1"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) 
$principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description "Fail To Ban For Window ==> m_2024"
$task.Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries 
$Description = "Fail To Ban For Window"

if ( $(Get-ScheduledTask -TaskName $TaskName ))  {
UnRegister-ScheduledTask -TaskName $TaskName -Confirm:$false
} 
 
Register-ScheduledTask  $TaskName  -InputObject $task 

} else {
    #Default Settings
    Remove-NetFirewallRule -DisplayName "_BlockRDPBruteForce"
    $Query = "Delete from FWBlockList"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "UPDATE sqlite_sequence SET seq = 0 where name = 'FWBlockList'"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "Delete from Log"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "UPDATE sqlite_sequence SET seq = 0 where name = 'Log'"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "Delete from RawData"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "UPDATE sqlite_sequence SET seq = 0 where name = 'RawData'"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "Delete from TempData"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "UPDATE sqlite_sequence SET seq = 0 where name = 'TempData'"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
  
    $Query = "Delete from TempFWBlockList"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    $Query = "Delete from WhiteList"
    Invoke-SqliteQuery -DataSource $Database -Query $Query
    WriteLog "All data has been deleted. Database returned to default values"

}
