# VERITAS
Windows YARA Toolkit and Process Script

Script by: Alexandra Ioannidis and Jathan Anandham


# Functionality
We have created a Powershell script that can provide various forensic artifacts relating to processes that can be used in a forensic investigation or for finding anomalous activity within a Windows system. We utilize YARA in relation to rules for Tookits to sort and find anomalies on the Windows System in the directories/files it searches. Our tool creates a .txt report that displays the date, time, computer name, process and service information, as well as a YARA Toolkit analysis of different directories. 

With this script, the user is able to specify if they want the report to be emailed and also if they want the YARA rules to search a specific directory. 

# Prerequisites
Powershell must be run as an Admin. 

Yara must be installed on the Windows machine. This script is configured for 64-bit operating systems and specifies the  yara64.exe file for use of YARA.

Link to download YARA:
https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0

Based on the setup of your box, download the appropriate version of YARA. 
After downloading the binary, unzip the file and put the yara.exe and yarac.exe anywhere on your box.

# How to Use
In order to use this script, you can download and save the script as well as save the .yar file to your box.  
Once you have downloaded and saved the files, you can run the veritas.ps1 file in Powershell. Reports are saved to a folder called "Windows Artifact Reports" on the current users Desktop. 

# Contact
If you have any questions regarding this repository please contact us through email:

axi9993@g.rit.edu

ja7185@g.rit.edu
