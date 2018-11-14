##############################
# POWERSHELL SCRIPT
# 
# Authors: Alexandra Ioannidis
#	   Jathan Anandham
#
##############################

# include error and status messages 
# put in current user Desktop folder

#PROCESSES

# Get hash for all current processes
#$nullCount = 0
#[System.Collections.ArrayList]$processhash=@()
#foreach($proc in $processArray){
#	try{
#		$hash = Get-FileHash $proc.path -Algorithm MD5 -ErrorAction continue
#		$processhash.Add($hash)
#	}
#	catch{
#		$processhash.Add("NULL")
#		$nullCount = $nullCount + 1
#	}
#}

#$table=@(@{Process=$processArray; Path=$processPath; Hash=$processhash})
#$table.ForEach({[PSCustomObject]$_}) | Format-Table


# ACTUAL sCIRPT

Get-ChildItem -Recurse -filter *.exe C:\ 2> $null |
ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; ./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName 2> $null }

Write-Output "Beginning reporting process..."

# GENERAL INFORMATION

# Get current date (ISO Compliant) for report title 
$titleDate=Get-Date -format yyyy_MM_dd
$text = $titleDate + '_Report.txt'

# Create a reports directory for report files if non existent
$path = "C:\Windows Artifact Reports"
if(!(test-path $path)){ New-Item -ItemType Directory -Force -Path $path}
New-Item -Path "C:\" -Name $text -ItemType "file" 

$title="WINDOWS ARTIFACTS REPORT"
$title | Out-File "C:\Windows Artifact Reports\$text" -Append

# Get current date/time for report
$time=Get-Date
$time.ToUniversalTime()
$time | Out-File "C:\Windows Artifact Reports\$text" -Append

# Get name of machine
$compName=$env:computername
$compName | Out-File "C:\Windows Artifact Reports\$text" -Append

Write-Output "Beginning Processes Section..."

# PROCESSES
$processArray=Get-Process | Select-Object -Property ProcessName
$processPath=Get-Process | Select-Object -Property Path
$procCount= "Number of current processes: " + $processArray.Count
$procCount | Out-File "C:\Windows Artifact Reports\$text" -Append

$startup=Get-CimInstance win32_service -Filter "startmode = 'auto'" | Select-Object ProcessId, Name
$autoCount = "Number of Start-Up Processes: " + $startup.Count
$startup | Out-File "C:\Windows Artifact Reports\$text" -Append
$autoCount | Out-File "C:\Windows Artifact Reports\$text" -Append

# SERVICES
$running = Get-Service | where {$_.status -eq 'running'}
$runCount = "Number of Running Services: " + $running.Count
$running | Out-File "C:\Windows Artifact Reports\$text" -Append
$runCount | Out-File "C:\Windows Artifact Reports\$text" -Append
$stopped = Get-Service | where {$_.status -eq 'stopped'}
$stopCount = "Number of Stopped Services: " + $stopped.Count
$stopCount | Out-File "C:\Windows Artifact Reports\$text" -Append

Write-Output "Reporting Process Finished..."

