##############################
# Windows Analyzer Script
# 
# Authors: Alexandra Ioannidis
#	         Jathan Anandham
#
##############################

import os

os.system("Write-Output "Beginning reporting process..."")

# GENERAL INFORMATION

# Get current date (ISO Compliant) for report title 
os.system("$titleDate=Get-Date -format yyyy_MM_dd")
os.system("$text = $titleDate + '_Report.txt'")

# Create a reports directory for report files if non existent
os.system("$path = "C:\Windows Artifact Reports"")
os.system("if(!(test-path $path)){ New-Item -ItemType Directory -Force -Path $path}")
os.system("New-Item -Path "C:\" -Name $text -ItemType "file" ")

os.system("$title="WINDOWS ARTIFACTS REPORT"")
os.system("$title | Out-File "C:\Windows Artifact Reports\$text" -Append")

# Get current date/time for report
os.system("$time=Get-Date")
os.system("$time.ToUniversalTime()")
os.system("$time | Out-File "C:\Windows Artifact Reports\$text" -Append")

# Get name of machine
os.system("$compName=$env:computername")
os.system("$compName | Out-File "C:\Windows Artifact Reports\$text" -Append")

os.system("Write-Output "Beginning Processes Section..."")

# PROCESSES
os.system("$processArray=Get-Process | Select-Object -Property ProcessName")
os.system("$processPath=Get-Process | Select-Object -Property Path")
os.system("$procCount= "Number of current processes: " + $processArray.Count")
os.system("$procCount | Out-File "C:\Windows Artifact Reports\$text" -Append")

os.system("$startup=Get-CimInstance win32_service -Filter "startmode = 'auto'" | Select-Object ProcessId, Name")
os.system("$autoCount = "Number of Start-Up Processes: " + $startup.Count")
os.system("$autoCount | Out-File "C:\Windows Artifact Reports\$text" -Append")

# SERVICES
os.system("$running = Get-Service | where {$_.status -eq 'running'}")
os.system("$runCount = "Number of Running Services: " + $running.Count")
os.system("$runCount | Out-File "C:\Windows Artifact Reports\$text" -Append")
os.system("$stopped = Get-Service | where {$_.status -eq 'stopped'}")
os.system("$stopCount = "Number of Stopped Services: " + $stopped.Count")
os.system("$stopCount | Out-File "C:\Windows Artifact Reports\$text" -Append")

os.system("Write-Output "Reporting Process Finished..."")
