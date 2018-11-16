##############################
# POWERSHELL SCRIPT - VERITAS
#
# CSEC-464
# Computer Forensics Project
#
# Authors: Alexandra Ioannidis
#	   Jathan Anandham
#
##############################

Write-Output "Beginning reporting process..."
$separator="`n`n================================================================================="

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
$compName="Computer Name: " + $env:computername
$compName | Out-File "$path\$text" -Append

Write-Output "Beginning YARA analysis..."
$separator | Out-File "$path\$text" -Append
$yarasection="`n`nYARA: "
$yarasection | Out-File "$path\$text" -Append
$yaraanom="`nAnomalies Found: "
$yaraanom | Out-File "$path\$text" -Append

# User specifies the directory they want
$yarachoice=Read-Host -Prompt "Do you want to specify a specific directory for Yara to search through? (Y for Yes, N for No) "
$pathchildCount=0
if($yarachoice -eq 'y' -OR $yarachoice -eq 'Y'){
   $yarapath=Read-Host -Prompt "Enter the Full Path of the directory you want to search "
   Get-ChildItem -Recurse -filter *.exe $yarapath 2> $null |
   ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; $pathchildCount+=1; ./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName 2> $path\$text }
   $yarapathCount="Number of files scanned for " + $yarapath + " directory: " + $pathchildCount
   $yarapathCount | Out-File "$path\$text" -Append
}

$childCount=0
$dllCount=0
$jpgCount=0

Get-ChildItem -Recurse -filter *.exe C:\ 2> $null |
ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; $childCount+=1; $exe=./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName }
$exe | Out-File "$path\$text" -Append

Get-ChildItem -Recurse -filter *.dll C:\ 2> $null |
ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; $dllCount+=1; $dll=./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName }
$dll | Out-File "$path\$text" -Append

Get-ChildItem -Recurse -filter *.jpg C:\ 2> $null |
ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; $jpgCount+=1; $jpg=./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName }
$jpg | Out-File "$path\$text" -Append

$yarafileCount="`n`nNumber of files scanned for C:\ directory for .exe files: " + $childCount
$yarafileCount | Out-File "$path\$text" -Append

$yaradllCount="Number of files scanned for C:\ directory for .dll files: " + $dllCount
$yaradllCount | Out-File "$path\$text" -Append

$yarajpgCount="Number of files scanned for C:\ directory for .jpg files: " + $jpgCount
$yarajpgCount | Out-File "$path\$text" -Append

# run YARA on current processes
$processPath=Get-Process | Select-Object -Property Path
Get-ChildItem -Recurse -filter *.exe $processPath 2> $null |
ForEach-Object { Write-Host -foregroundcolor "green" "Scanning"$_.FullName $_.Name; $childCount+=1; ./yara64.exe -d filename=$_.Name TOOLKIT.yar $_.FullName 2> $path\$text }

Write-Output "Beginning Processes Section..."

# PROCESSES
$processArray=Get-Process | Select-Object -Property Id, ProcessName, Path
$procCount= "Number of current processes: " + $processArray.Count
$separator | Out-File "$path\$text" -Append
$current="`nCURRENT PROCESSES:"
$current | Out-File "$path\$text" -Append

$processArray | Out-File "$path\$text" -Append
$procCount | Out-File "$path\$text" -Append

$separator | Out-File "$path\$text" -Append

$boot= "`nPROCESSES ON BOOT"
$boot | Out-File "$path\$text" -Append
$startup=Get-CimInstance win32_service -Filter "startmode = 'auto'" | Select-Object ProcessId, Name
$autoCount = "Number of Start-Up Processes: " + $startup.Count
$startup | Out-File "$path\$text" -Append
$autoCount | Out-File "$path\$text" -Append

# SERVICES
$separator | Out-File "$path\$text" -Append
$servicestitle="`nSERVICES:"
$servicestitle | Out-File "$path\$text" -Append
$running = Get-Service | where {$_.status -eq 'running'}
$runCount = "Number of Running Services: " + $running.Count
$running | Out-File "$path\$text" -Append
$runCount | Out-File "$path\$text" -Append
$stopped = Get-Service | where {$_.status -eq 'stopped'}
$stopCount = "Number of Stopped Services: " + $stopped.Count
$stopCount | Out-File "$path\$text" -Append
$end="`nEND OF REPORT"
$end | Out-File "$path\$text" -Append

Write-Output "Reporting Process Finished..."


