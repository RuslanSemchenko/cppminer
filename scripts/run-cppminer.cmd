@echo off
setlocal
set "ROOT=%~dp0"
"%ROOT%bin\cppminer.exe" %*
exit /b %ERRORLEVEL%
