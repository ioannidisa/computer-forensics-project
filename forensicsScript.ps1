##############################
# POWERSHELL SCRIPT
# 
# Authors: Alexandra Ioannidis
#	         Jathan Anandham
#
##############################

$text = 'Report'

# Gets the current date (DayofWeek, Month Day, Year)
$date=Get-Date -DisplayHint Date

# Gets current time of machine and converts it to UTC
$time=Get-Date -DisplayHint time
$time.ToUniversalTime()

#PROCESSES

# Get List of Current Processes
$processArray=Get-Process | Select-Object -Property ProcessName
$processPath=Get-Process | Select-Object -Property Path
[System.Collections.ArrayList]$processhash=@()
foreach($proc in $processArray){
	try{
		$hash = Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction continue
		$processhash.Add($hash)
	}
	catch{
		$processhash.Add("NULL")
	}
}

$table=@(@{Process=$processArray; Path=$processPath; Hash=$processhash})
$table.ForEach({[PSCustomObject]$_}) | Format-Table

$processArray

# Display count of current processes 
$processArray.Count

foreach ($element in $processArray) {
	$element
}

#FILES



# Create the file
$text | Out-File 'report.txt'

# Append to file
$text | Out-File 'report.txt' -Append
