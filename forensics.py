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

# Get name of machine
os.system("$compName=$env:computername")
os.system("$compName | Out-File "C:\Windows Artifact Reports\$text" -Append")

# Get current date/time for report
os.system("$time=Get-Date")
os.system("$time.ToUniversalTime()")
os.system("$time | Out-File "C:\Windows Artifact Reports\$text" -Append")

os.system("Write-Output "Beginning Current Processes Section..."")

# PROCESSES
os.system()
