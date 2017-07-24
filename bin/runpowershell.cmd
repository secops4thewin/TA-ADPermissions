@ECHO OFF
set SplunkApp=TA-ADPermissions

powershell.exe -executionPolicy RemoteSigned -command ". '%SPLUNK_HOME%\etc\apps\%SplunkApp%\bin\%1'"

