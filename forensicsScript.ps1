##############################
# POWERSHELL SCRIPT
# 
# Authors: Alexandra Ioannidis
#	   Jathan Anandham
#
##############################

# make sure to create section titles in report (ex. YARA, General Process Information)

Write-Output "Beginning reporting process..."

# GENERAL INFORMATION

# Get current date (ISO Compliant) for report title 
$titleDate=Get-Date -format yyyy_MM_dd
$text = $titleDate + '_Report.txt'

# Get current user's Desktop path
$desktopPath=[Environment]::GetFolderPath("Desktop")

# Create a reports directory for report files if non existent
$path = $desktopPath + '\Windows Artifact Reports'
if(!(test-path $path)){ New-Item -ItemType Directory -Force -Path $path}
New-Item -Path $path -Name $text -ItemType "file" 

$title="WINDOWS ARTIFACTS REPORT"
$title | Out-File "$path\$text" -Append

# Get current date/time for report
$time=Get-Date
$time.ToUniversalTime()
$time | Out-File "$path\$text" -Append

# Get name of machine
$compName=$env:computername
$compName | Out-File "$path\$text" -Append

Write-Output "Beginning YARA analysis..."
$yarasection="YARA"
$yarasection | Out-File "$path\$text" -Append

# Display the count of anomalies that YARA found in Report and the number of files it scanned?
$childCount=0
Get-ChildItem -Recurse -filter *.exe C:\ 2> $null |
ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; $childCount+=1; ./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName 2> $path\$text }

$yarafileCount="Number of files scanned: " + $childCount.Count
$yarafileCount | Out-File "$path\$text" -Append


Write-Output "Beginning Processes Section..."

# PROCESSES
$processArray=Get-Process | Select-Object -Property ProcessName
$processPath=Get-Process | Select-Object -Property Path
$procCount= "Number of current processes: " + $processArray.Count
$processArray=Get-Process | Select-Object -Property Id, ProcessName, Path
$procCount | Out-File "$path\$text" -Append

$startup=Get-CimInstance win32_service -Filter "startmode = 'auto'" | Select-Object ProcessId, Name
$autoCount = "Number of Start-Up Processes: " + $startup.Count
$startup | Out-File "$path\$text" -Append
$autoCount | Out-File "$path\$text" -Append

# SERVICES
$running = Get-Service | where {$_.status -eq 'running'}
$runCount = "Number of Running Services: " + $running.Count
$running | Out-File "$path\$text" -Append
$runCount | Out-File "$path\$text" -Append
$stopped = Get-Service | where {$_.status -eq 'stopped'}
$stopCount = "Number of Stopped Services: " + $stopped.Count
$stopCount | Out-File "$path\$text" -Append

Write-Output "Reporting Process Finished..."

