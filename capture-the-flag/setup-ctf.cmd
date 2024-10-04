GOTO MAIN
:FindPython
# Locate which python.exe will be used...
for /F "tokens=*" %%i in ('where python.exe') do set PYTHONEXE="%%i" & exit /B
exit /B 1

:AddFirewallAppRule
netsh.exe advfirewall firewall add rule name="Python-CTF" dir=in action=allow program=%1 description="CTF Python Listener" profile=any
exit /B

:StartPythonListener
start "CTF" %PYTHONEXE% "%~dp0echo-server.py"
exit /B

:ConfigureScheduledTask
schtasks /create /tn "CTF-Python" /tr "\"%~dp0setup-ctf.cmd\"" /RU System /sc onstart /F
exit /B


:MAIN
CALL :FindPython
if ERRORLEVEL 1 @echo Did not find python.exe in the path & exit /B 1

echo Python is at %PYTHONEXE%
CALL :AddFirewallAppRule %PYTHONEXE%
CALL :StartPythonListener
CALL :ConfigureScheduledTask
exit /B