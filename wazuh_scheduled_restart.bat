REM Basic batch script for creating a local script and local scheduled task for running aforementioned script.
REM Author: Jeff Starke


REM Create service restart script
(
echo net stop wazuh  2>&1>nul
echo net start wazuh
)>"C:\wazuh_restart.bat"

REM Create scheduled task to run script
SCHTASKS /DELETE /TN "Microsoft\Windows\Wazuh\Restart Wazuh" /F  2>&1>nul
SCHTASKS /CREATE /SC DAILY /NP /TN "Microsoft\Windows\Wazuh\Restart Wazuh" /TR "C:wazuh_restart.sh" /ST 23:00

REM Restart service now
echo net stop wazuh  2>&1>nul
echo net start wazuh
