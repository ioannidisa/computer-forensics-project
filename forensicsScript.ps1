##############################
# POWERSHELL SCRIPT
# 
# Authors: Alexandra Ioannidis
#	   Jathan Anandham
#
##############################

# include error and status messages 
# create a directory to put reports in if not already existent 
# restore points? get creation date and how many days ago that was from curr date
# count number of processes with null hash

Write-Output "Beginning reporting process..."

# ISO Compliant 
$titleDate=Get-Date -format yyyy-MM-dd
$text = $titleDate + '_Report'
New-Item -Path "C:\Desktop" -Name $text -ItemType "file" 

# Gets the current date (DayofWeek, Month Day, Year)
$date=Get-Date -DisplayHint Date

# Gets current time of machine and converts it to UTC
$time=Get-Date -DisplayHint time
$time.ToUniversalTime()

# Computer name 
$compName=$env:computername

Write-Output "Beginning Current Processes Section..."

#PROCESSES

# Get List of Current Processes
$processArray=Get-Process | Select-Object -Property ProcessName
$processPath=Get-Process | Select-Object -Property Path

# Get hash for all current processes
$nullCount = 0
[System.Collections.ArrayList]$processhash=@()
foreach($proc in $processArray){
	try{
		$hash = Get-FileHash $proc.path -Algorithm MD5 -ErrorAction continue
		$processhash.Add($hash)
	}
	catch{
		$processhash.Add("NULL")
		$nullCount = $nullCount + 1
	}
}

$table=@(@{Process=$processArray; Path=$processPath; Hash=$processhash})
$table.ForEach({[PSCustomObject]$_}) | Format-Table

# need to compare to known good hashes, display outliers in a table??

# Display count of current processes and count of null hash processes
$procCount=$processArray.Count
#$nullCount


# RESTORE POINTS
$restorePoints=Get-ComputerRestorePoint | Format-Table SequenceNumber, @{Label="Date"; Expression={$_.ConvertToDateTime($_.CreationTime)}}, Description -Auto

# USER LOG ONS
# get username, session, id, logon time
#query user


# REGISTRY KEYS

# FILE SYSTEM


# Append to file
$text | Out-File "report.txt" -Append

Write-Output "Reporting Process Finished..."
