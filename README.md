# VERITAS
Windows YARA and Process Script

Script by: Alexandra Ioannidis and Jathan Anandham


# Functionality
We have created a Powershell script that can provide various forensic artifacts relating to processes that can be used in a forensic investigation or for finding anomalous activity within a Windows system. Our tool creates a .txt report that displays the date, time, computer name, process and service information, as well as a YARA analysis of different directories. 

# Prerequisites
Powershell must be run as an Admin. 

Yara must be installed on the Windows machine. 

Link to download YARA:
https://www.dropbox.com/sh/umip8ndplytwzj1/AADdLRsrpJL1CM1vPVAxc5JZa?dl=0

Based on the setup of your box, download the appropriate version of YARA. 
After downloading the binary, unzip the file and put the yara.exe and yarac.exe anywhere on your box. 

# How to Use
In order to use this script, you can download and save the script as well as save the .yar file to your box.  
