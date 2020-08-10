pushd %~dp0
set sysmon=sysmon.exe
if exist sysmon64.exe set sysmon=sysmon64.exe
%sysmon% -accepteula -i sysmonconfig-export.xml
pause
popd
