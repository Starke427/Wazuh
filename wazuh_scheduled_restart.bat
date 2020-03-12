REM Basic batch script for creating a local script and local scheduled task for running aforementioned script.
REM Author: Jeff Starke

(
echo net stop wazuh
echo net start wazuh
)>"C:\wazuh_restart.bat"

SCHTASKS /DELETE /TN "Microsoft\Windows\Wazuh\Restart Wazuh" /F
SCHTASKS /CREATE /SC DAILY /NP /TN "Microsoft\Windows\Wazuh\Restart Wazuh" /TR "C:wazuh_restart.sh" /ST 23:00

net stop wazuh
net start wazuh
