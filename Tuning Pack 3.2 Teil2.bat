
@ECHO OFF
COLOR 1F
SET V=1.7
TITLE Windows 10 Registry tweaks: TGF
ECHO #########################################################
ECHO #                                                       #
ECHO #  WINDOWS 10 Tweaker                                   #
ECHO #                                                       #
ECHO #                                                       #
ECHO #  AUTOR: TheGeekFreaks - Alexander Zuber               #
ECHO #                                                       #
ECHO #########################################################

REM ======================= Registry tweaks =======================
ECHO.
:regstart
set /p registry="Apply Registry tweaks? y/n: "
if '%registry%' == 'n' goto servstart
if /i "%registry%" neq "y" goto regstart

:reg0start
set /p reg0="Replace Utilman with CMD? y/n: "
if '%reg0%' == 'n' goto reg1start
if /i "%reg0%" neq "y" goto reg0start
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > NUL 2>&1

:reg1start
set /p reg1="Disable Quick Access as default view in Explorer? y/n: "
if '%reg1%' == 'n' goto reg2start
if /i "%reg1%" neq "y" goto reg1start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d 0 > NUL 2>&1

:reg2start
set /p reg2="Show computer shortcut on desktop? y/n: "
if '%reg2%' == 'n' goto reg3start
if /i "%reg2%" neq "y" goto reg2start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg3start
set /p reg3="Show file extensions? y/n: "
if '%reg3%' == 'n' goto reg4start
if /i "%reg3%" neq "y" goto reg3start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg4start
set /p reg4="Disable lockscreen? y/n: "
if '%reg4%' == 'n' goto reg5start
if /i "%reg4%" neq "y" goto reg4start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg5start
set /p reg5="Enable classic control panel view? y/n: "
if '%reg5%' == 'n' goto reg6start
if /i "%reg5%" neq "y" goto reg5start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg6start
set /p reg6="Hide indication for compressed NTFS files? y/n: "
if '%reg6%' == 'n' goto reg7start
if /i "%reg6%" neq "y" goto reg6start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > NUL 2>&1

:reg7start
set /p reg7="Disable Windows Update sharing? y/n: "
if '%reg7%' == 'n' goto reg8start
if /i "%reg7%" neq "y" goto reg7start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg8start
set /p reg8="Remove Pin to start? y/n: "
if '%reg8%' == 'n' goto reg9start
if /i "%reg8%" neq "y" goto reg8start
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1

:reg9start
set /p reg9="Classic vertical icon spacing? y/n: "
if '%reg9%' == 'n' goto reg10start
if /i "%reg9%" neq "y" goto reg9start
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > NUL 2>&1

:reg10start
set /p reg10="Remove versioning tab from properties? y/n: "
if '%reg10%' == 'n' goto reg11start
if /i "%reg10%" neq "y" goto reg10start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > NUL 2>&1

:reg11start
set /p reg11="Disable jump lists? y/n: "
if '%reg11%' == 'n' goto reg12start
if /i "%reg11%" neq "y" goto reg11start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg12start
set /p reg12="Remove telemetry and data collection? y/n: "
if '%reg12%' == 'n' goto reg13start
if /i "%reg12%" neq "y" goto reg12start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg13start
set /p reg13="Apply Internet Explorer 11 tweaks? y/n: "
if '%reg13%' == 'n' goto reg14start
if /i "%reg13%" neq "y" goto reg13start
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg14start
set /p reg14="Disable Cortana, Bing Search and Searchbar? y/n: "
if '%reg14%' == 'n' goto reg15start
if /i "%reg14%" neq "y" goto reg14start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg15start
set /p reg15="Change Logon screen background with accent color? y/n: "
if '%reg15%' == 'n' goto reg16start
if /i "%reg15%" neq "y" goto reg15start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg16start
set /p reg16="Disable Windows Error Reporting? y/n: "
if '%reg16%' == 'n' goto reg17start
if /i "%reg16%" neq "y" goto reg16start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg17start
set /p reg17="Disable automatic Windows Updates? y/n: "
if '%reg17%' == 'n' goto reg18start
if /i "%reg17%" neq "y" goto reg17start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > NUL 2>&1

:reg18start
set /p reg18="Disable Hibernation? y/n: "
if '%reg18%' == 'n' goto servstart
if /i "%reg18%" neq "y" goto reg18start
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

ECHO Done...

REM ======================= Removing services =======================
ECHO.
:servstart
set /p services="Apply Registry tweaks? y/n: "
if '%services%' == 'n' goto schedstart
if /i "%services%" neq "n" if /i "%services%" neq "y" goto servstart

:serv0start
set /p serv0="Disable tracking services? y/n: "
if '%serv0%' == 'n' goto serv1start
if /i "%serv0%" neq "y" goto serv0start
sc config DiagTrack start= disabled > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled > NUL 2>&1
sc config TrkWks start= disabled > NUL 2>&1
sc config WMPNetworkSvc start= disabled > NUL 2>&1

:serv1start
set /p serv1="Disable WAP Push Message Routing Service? y/n: "
if '%serv1%' == 'n' goto serv2start
if /i "%serv1%" neq "y" goto serv1start
sc config dmwappushservice start= disabled > NUL 2>&1

:serv2start
set /p serv2="Disable Windows Search? y/n: "
if '%serv2%' == 'n' goto serv3start
if /i "%serv2%" neq "y" goto serv2start
sc config WSearch start= disabled > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

:serv3start
set /p serv3="Disable Superfetch? y/n: "
if '%serv3%' == 'n' goto serv4start
if /i "%serv3%" neq "y" goto serv3start
sc config SysMain start= disabled > NUL 2>&1

:serv4start
set /p serv4="Disable Windows Defender? y/n: "
if '%serv4%' == 'n' goto schedstart
if /i "%serv4%" neq "y" goto serv4start
sc config WinDefend start= disabled > NUL 2>&1
sc config WdNisSvc start= disabled > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > NUL 2>&1

ECHO Done...

REM ======================= Removing scheduled tasks =======================
ECHO.
:schedstart
set /p schedules="Removing scheduled tasks? y/n: "
if '%schedules%' == 'n' goto winappstart
if /i "%schedules%" neq "n" if /i "%schedules%" neq "y" goto schedstart

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1

ECHO Done...

REM ======================= Removing Windows default apps =======================
ECHO.
:winappstart
set /p winapps="Removing Windows default apps? y/n: "
if '%winapps%' == 'n' goto odrivestart
if /i "%winapps%" neq "n" if /i "%winapps%" neq "y" goto winappstart

powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > NUL 2>&1

ECHO Done...

REM ======================= Disable / Remove OneDrive =======================
ECHO.
:odrivestart
set /p onedrive="Disable OneDrive? y/n: "
if '%onedrive%' == 'n' goto hoststart
if /i "%onedrive%" neq "y" goto odrivestart
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1

ECHO Done...

REM ======================= Blocking Telemetry Servers =======================
ECHO.
:hoststart
set /p hostsblock="Blocking Telemetry Servers? y/n: "
if '%hostsblock%' == 'n' goto finish
if /i "%hostsblock%" neq "n" if /i "%hostsblock%" neq "y" goto hoststart

copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > NUL 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1

@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

:: ---------------------------------------------------  !!! Incorrect Data Found !!!  -------------------------------------------------------------
:: HKEY_CURRENT_USER\Control Panel\Mouse --> SmoothMouseXCurve"=hex:\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,00,00,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> C0,CC,0C,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 80,99,19,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 40,66,26,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,33,33,00,00,00,00,00
:: HKEY_CURRENT_USER\Control Panel\Mouse --> SmoothMouseYCurve"=hex:\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,00,00,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,00,38,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,00,70,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,00,A8,00,00,00,00,00,\
:: HKEY_CURRENT_USER\Control Panel\Mouse --> 00,00,E0,00,00,00,00,00
:: ------------------------------------------------------------------------------------------------------------------------------------------------

REM ; Windows_10+8.x_MouseFix_ItemsSize=100%_Scale=1-to-1_@6-of-11
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Exit

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof

rem ========== Pre ==========

rem Don't echo to standard output
@echo off
rem Set version info
set V=4.2.3
rem Change colors
color 1F
rem Set title
title Windows 10 Tweaks (x64) Version %V% by: TheGeekFreaks

rem ========== Start ==========

cls
echo ###############################################################################
echo #                                                                             #
echo #  Windows10 Tweaks Version %V%                                     #
echo #                                                                             #
echo #  Microsoft Windows 10                       #
echo #                                                                             #
echo #  AUTHOR: TheGeekFreaks                          #
echo #                                                                             #
echo #                                                                             #
echo #  Features                                                                   #
echo #                                                                             #
echo #  1. Registry Tweaks                                                         #
echo #  2. Removing Services                                                       #
echo #  3. Removing Scheduled Tasks                                                #
echo #  4. Removing Windows Default Apps                                           #
echo #  5. Disable / Remove OneDrive                                               #
echo #  6. Blocking Telemetry Servers                                              #
echo #  7. Blocking More Windows Servers                                           #
echo #  8. Disable Windows Error Recovery on Startup                               #
echo #  9. Internet Explorer 11 Tweaks                                             #
echo #  10. Libraries Tweaks                                                       #
echo #  11. Windows Update Tweaks                                                  #
echo #  12. Windows Defender Tweaks                                                #
echo #                                                                             #
echo ###############################################################################
echo.
timeout /T 1 /NOBREAK > nul

rem ========== Automatically Check & Get Admin Rights ==========

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>nul 2>nul
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
echo.
echo ###############################################################################
echo #  Invoking UAC for Privilege Escalation                                      #
echo ###############################################################################

echo Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
echo args = "ELEV " >> "%vbsGetPrivileges%"
echo For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
echo args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
echo Next >> "%vbsGetPrivileges%"
echo UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

rem ========== Initializing ==========

set PMax=0
set PRun=0
set PAct=0

rem ========== 1. Registry Tweaks ==========

echo.
echo ###############################################################################
echo #  1. Registry Tweaks  --  Start                                              #
echo ###############################################################################
echo.

:1000
set /A Pline=1000
set PMax=37
set PRun=0
rem set PAct=0
echo Apply Registry tweaks (%PMax%).
set /p Pselect="Continue? y/n/a: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+2
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:1001
set myMSG=Show computer shortcut on desktop.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1002
rem 0 = show icon, 1 = don't show icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1003
set myMSG=Show Network shortcut on desktop.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1004
rem 0 = show icon, 1 = don't show icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1005
set myMSG=Classic vertical icon spacing.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1006
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > nul 2>&1set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1007
set myMSG=Lock the Taskbar.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1008
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1009
set myMSG=Always show all icons on the taskbar (next to clock).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1010
rem 0 = Show all icons
rem 1 = Hide icons on the taskbar
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1011
set myMSG=Delay taskbar thumbnail pop-ups to 10 seconds.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1012
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "10000" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1013
set myMSG=Enable classic control panel view.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1014
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1015
set myMSG=Turn OFF Sticky Keys when SHIFT is pressed 5 times.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1016
rem 506 = Off, 510 = On (default)
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1017
set myMSG=Turn OFF Filter Keys when SHIFT is pressed for 8 seconds.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1018
rem 122 = Off, 126 = On (default)
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1019
set myMSG=Disable Hibernation.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1020
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1021
set myMSG=Underline keyboard shortcuts and access keys.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1022
reg add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1023
set myMSG=Show known file extensions in Explorer.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1024
rem 0 = extensions are visible
rem 1 = extensions are hidden
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1025
set myMSG=Hide indication for compressed NTFS files.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1026
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1027
set myMSG=Show Hidden files in Explorer.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1028
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1029
set myMSG=Show Super Hidden System files in Explorer.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1030
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1031
set myMSG=Prevent both Windows and Office from creating LNK files in the Recents folder.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1032
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1033
set myMSG=Replace Utilman with CMD.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1034
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1035
set myMSG=Add the option "Processor performance core parking min cores".
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1036
rem Option will be added to: Power Options > High Performance > Change Plan Settings > Change advanced power settings > Processor power management
rem Default data is 1 (option hidden)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f  > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1037
set myMSG=Add the option "Disable CPU Core Parking".
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1038
rem Default value is 100 decimal.
rem Basically "Core parking" means that the OS can use less CPU cores when they are not needed, and saving power.
rem This, however, can somewhat hamper performance, so advanced users prefer to disable this feature.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f  > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1039
set myMSG=Remove Logon screen wallpaper/background. Will use solid color instead (Accent color).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1040
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f  > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1041
set myMSG=Disable lockscreen.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1042
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1043
set myMSG=Remove versioning tab from properties.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1044
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1045
set myMSG=Disable jump lists.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1046
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1047
set myMSG=Disable Windows Error Reporting.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1048
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1049
set myMSG=Disable Cortana (Speech Search Assistant, which also sends information to Microsoft).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1050
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1051
set myMSG=Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1052
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1053
set myMSG=Disable MRU lists (jump lists) of XAML apps in Start Menu.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1054
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1055
set myMSG=Set Windows Explorer to start on This PC instead of Quick Access.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1056
rem 1 = This PC, 2 = Quick access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1057
set myMSG=Disable Disk Quota tab, which appears as a tab when right-clicking on drive letter - Properties.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1058
rem 1 = This PC, 2 = Quick access
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DiskQuota" /v "Enable" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1059
set myMSG=Disable creation of an Advertising ID.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1060
rem 1 = This PC, 2 = Quick access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1061
set myMSG=Remove Pin to start (3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1062
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1063
set myMSG=Disable Cortana, Bing Search and Searchbar (4).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1064
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1065
set myMSG=Turn off the Error Dialog (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1066
reg add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1067
set myMSG=Disable Administrative shares (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1068
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1069
set myMSG=Add "Reboot to Recovery" to right-click menu of "This PC" (4).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1070
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d %SystemRoot%\System32\imageres.dll,-110" /f > nul 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1071
set myMSG=Change Clock and Date formats of current user to: 24H, metric (Sign out required to see changes) (6).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1072
rem Apply to all users by using the key: HKLM\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International
reg add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "0" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "iNegCurr" /t REG_SZ /d "1" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d "1" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "yyyy/MM/dd" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "H:mm:ss" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+6
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1073
set myMSG=Enable Developer Mode (enables you to run XAML apps you develop in Visual Studio which haven't been certified yet) (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1074
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowAllTrustedApps" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowDevelopmentWithoutDevLicense" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1075
set myMSG=Remove telemetry and data collection (14).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1076
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > nul 2>&1

reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1077
:1078

:1100
echo.
echo ###############################################################################
echo #  1. Registry Tweaks  --  End                                                #
echo ###############################################################################
echo.

rem ========== 2. Removing Services ==========

echo.
echo ###############################################################################
echo #  2. Removing Services  --  Start                                            #
echo ###############################################################################
echo.

:2000
set /A Pline=2000
set PMax=36
set PRun=0
rem set PAct=0
echo Removing Services (%PMax%).
set /p Pselect="Continue? y/n/a: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+2
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:2001
set myMSG=Disable Connected User Experiences and Telemetry (To turn off Telemetry and Data Collection).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2002
sc config DiagTrack start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2003
set myMSG=Disable Diagnostic Policy Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2004
sc config DPS start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2005
set myMSG=Disable Distributed Link Tracking Client (If your computer is not connected to any network).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2006
sc config TrkWks start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2007
set myMSG=Disable WAP Push Message Routing Service (To turn off Telemetry and Data Collection).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2008
sc config dmwappushservice start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2009
set myMSG=Disable Downloaded Maps Manager (If you don't use Maps app).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2010
sc config MapsBroker start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2011
set myMSG=Disable IP Helper (If you don't use IPv6 connection).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2012
sc config iphlpsvc start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2013
set myMSG=Disable Program Compatibility Assistant Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2014
sc config PcaSvc start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2015
set myMSG=Disable Print Spooler (If you don't have a printer).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2016
sc config Spooler start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2017
set myMSG=Disable Remote Registry (You can set it to DISABLED for Security purposes).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2018
sc config RemoteRegistry start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2019
set myMSG=Disable Secondary Logon.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2020
sc config seclogon start= Disabled > nul 2>&1 	
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2021
set myMSG=Disable Security Center.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2022
sc config wscsvc start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2023
set myMSG=Disable TCP/IP NetBIOS Helper (If you are not in a workgroup network).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2024
sc config lmhosts start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2025
set myMSG=Disable Touch Keyboard and Handwriting Panel Service (If you don't want to use touch keyboard and handwriting features.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2026
sc config TabletInputService start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2027
set myMSG=Disable Windows Error Reporting Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2028
sc config WerSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2029
set myMSG=Disable Windows Image Acquisition (WIA) (If you don't have a scanner).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2030
sc config stisvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2031
set myMSG=Disable Windows Search.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2032
sc config WSearch start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2033
set myMSG=Disable tracking services (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2034
sc config diagnosticshub.standardcollector.service start= Disabled > nul 2>&1
sc config WMPNetworkSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2035
set myMSG=Disable Superfetch.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2036
sc config SysMain start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2037
set myMSG=Disable Xbox Services (5).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2038
rem Xbox Accessory Management Service
sc config XboxGipSvc start= Disabled > nul 2>&1
rem Xbox Game Monitoring
sc config xbgm start= Disabled > nul 2>&1
rem Xbox Live Auth Manager
sc config XblAuthManager start= Disabled > nul 2>&1
rem Xbox Live Game Save
sc config XblGameSave start= Disabled > nul 2>&1
rem Xbox Live Networking Service
sc config XboxNetApiSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+5
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2039
set myMSG=Disable AllJoyn Router Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2040
rem  This service is used for routing the AllJoyn messages for AllJoyn clients.
sc config AJRouter start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2041
set myMSG=Disable Bluetooth Services (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2042
rem Bluetooth Handsfree Service
sc config BthHFSrv start= Disabled > nul 2>&1
rem Bluetooth Support Service
sc config bthserv start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2043
set myMSG=Disable Geolocation Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2044
sc config lfsvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2045
set myMSG=Disable Phone Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2046
sc config PhoneSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2047
set myMSG=Disable Windows Biometric Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2048
sc config WbioSrvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2049
set myMSG=Disable Windows Mobile Hotspot Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2050
sc config icssvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2051
set myMSG=Disable Windows Media Player Network Sharing Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2052
sc config WMPNetworkSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2053
set myMSG=Disable Windows Update Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2054
sc config wuauserv start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2055
set myMSG=Disable Enterprise App Management Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2056
sc config EntAppSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2057
set myMSG=Disable Hyper-V Services (9).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2058
rem HV Host Service
sc config HvHost start= Disabled > nul 2>&1
rem Hyper-V Data Exchange Service
sc config vmickvpexchange start= Disabled > nul 2>&1
rem Hyper-V Guest Service Interface
sc config vmicguestinterface start= Disabled > nul 2>&1
rem Hyper-V Guest Shutdown Service
sc config vmicshutdown start= Disabled > nul 2>&1
rem Hyper-V Heartbeat Service
sc config vmicheartbeat start= Disabled > nul 2>&1
rem Hyper-V PowerShell Direct Service
sc config vmicvmsession start= Disabled > nul 2>&1
rem Hyper-V Remote Desktop Virtualization Service
sc config vmicrdv start= Disabled > nul 2>&1
rem Hyper-V Time Synchronization Service
sc config vmictimesync start= Disabled > nul 2>&1
rem Hyper-V Volume Shadow Copy Requestor
sc config vmicvss start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+9
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2059
set myMSG=Disable HomeGroup Listener.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2060
sc config HomeGroupListener start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2061
set myMSG=Disable HomeGroup Provider.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2062
sc config HomeGroupProvider start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2063
set myMSG=Disable Net.Tcp Port Sharing Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2064
sc config NetTcpPortSharing start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2065
set myMSG=Disable Routing and Remote Access.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2066
sc config RemoteAccess start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2067
set myMSG=Disable Internet Connection Sharing (ICS).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2068
sc config RemoteAccess start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2069
set myMSG=Disable Superfetch (A must for SSD drives, but good to do in general)(3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2070
rem Disabling this service prevents further creation of PF files in C:\Windows\Prefetch.
rem After disabling this service, it is completely safe to delete everything in that folder, except for the ReadyBoot folder.
sc config SysMain start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2071
set myMSG=Disable Action Center & Security Center.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2072
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d 0 /f
sc config wscsvc start= disabled
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2073
:2074

:2100
echo.
echo ###############################################################################
echo #  2. Removing Services  --  End                                              #
echo ###############################################################################
echo.

rem ========== 3. Removing Scheduled Tasks ==========

echo.
echo ###############################################################################
echo #  3. Removing Scheduled Tasks  --  Start                                     #
echo ###############################################################################
echo.

:3000
set /A Pline=3000
set PMax=1
set PRun=0
rem set PAct=0
echo Removing scheduled tasks (17).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:3001
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+17
echo Done %PRun% / %PMax% Removing Scheduled Tasks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:3100
echo.
echo ###############################################################################
echo #  3. Removing Scheduled Tasks  --  End                                       #
echo ###############################################################################
echo.

rem ========== 4. Removing Windows Default Apps ==========

echo.
echo ###############################################################################
echo #  4. Removing Windows Default Apps  --  Start                                #
echo ###############################################################################
echo.

:4000
set /A Pline=4000
set PMax=1
set PRun=0
rem set PAct=0
echo Removing Windows default apps (12).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:4001
powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+12
echo Done %PRun% / %PMax% Removing Windows Default Apps. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:4100
echo.
echo ###############################################################################
echo #  4. Removing Windows Default Apps  --  End                                  #
echo ###############################################################################
echo.

rem ========== 5. Disable / Remove OneDrive ==========

echo.
echo ###############################################################################
echo #  5. Disable / Remove OneDrive  --  Start                                    #
echo ###############################################################################
echo.

:5000
set /A Pline=5000
set PMax=1
set PRun=0
rem set PAct=0
echo Disable OneDrive (7).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:5001
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > nul 2>&1

reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKCU\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1

:: Detete OneDrive icon on explorer.exe (Only 64 Bits)
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t reg_DWORD /d 0 /f > nul 2>&1
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t reg_DWORD /d 0 /f > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+7
echo Done %PRun% / %PMax% Disable / Remove OneDrive. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:5100
echo.
echo ###############################################################################
echo #  5. Disable / Remove OneDrive  --  End                                      #
echo ###############################################################################
echo.

rem ========== 6. Blocking Telemetry Servers ==========

echo.
echo ###############################################################################
echo #  6. Blocking Telemetry Servers  --  Start                                   #
echo ###############################################################################
echo.

:6000
set /A Pline=6000
set PMax=1
set PRun=0
rem set PAct=0
echo Blocking Telemetry Servers (25).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:6001
copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > nul 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1
find /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+25
echo Done %PRun% / %PMax% Blocking Telemetry Servers. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:6100
echo.
echo ###############################################################################
echo #  6. Blocking Telemetry Servers  --  End                                     #
echo ###############################################################################
echo.

rem ========== 7. Blocking More Windows Servers ==========

echo.
echo ###############################################################################
echo #  7. Blocking More Windows Servers  --  Start                                #
echo ###############################################################################
echo.

:7000
set /A Pline=7000
set PMax=1
set PRun=0
rem set PAct=0
echo Blocking More Telemetry Servers (109).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:7001
copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > nul 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1
find /C /I "184-86-53-99.deploy.static.akamaitechnologies.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 184-86-53-99.deploy.static.akamaitechnologies.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.ads1.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.ads1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.ads2.msads.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.ads2.msads.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.ads2.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.ads2.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.rad.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.rad.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0001.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0001.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0002.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0002.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0003.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0003.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0004.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0004.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0005.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0005.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0006.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0006.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0007.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0007.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0008.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0008.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0009.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0009.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a1621.g.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a1621.g.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a1856.g2.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a1856.g2.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a1961.g.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a1961.g.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a978.i6g1.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a978.i6g1.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ac3.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ac3.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ad.doubleclick.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ad.doubleclick.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "adnexus.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 adnexus.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "adnxs.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 adnxs.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ads.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ads.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ads1.msads.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ads1.msads.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ads1.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ads1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "aidps.atdmt.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 aidps.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "aka-cdn-ns.adtech.de" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 aka-cdn-ns.adtech.de>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "any.edge.bing.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 any.edge.bing.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "az361816.vo.msecnd.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 az361816.vo.msecnd.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "az512334.vo.msecnd.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 az512334.vo.msecnd.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "b.ads1.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 b.ads1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "b.ads2.msads.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 b.ads2.msads.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "b.rad.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 b.rad.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "bingads.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 bingads.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "bs.serving-sys.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 bs.serving-sys.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "c.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 c.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cdn.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cdn.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cds26.ams9.msecn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cds26.ams9.msecn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "compatexchange.cloudapp.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 compatexchange.cloudapp.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "corp.sts.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 corp.sts.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "corpext.msitadfs.glbdns2.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cs1.wpc.v0cdn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cs1.wpc.v0cdn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cy2.vortex.data.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cy2.vortex.data.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "db3aqu.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 db3aqu.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "diagnostics.support.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 diagnostics.support.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e2835.dspb.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e2835.dspb.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e7341.g.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e7341.g.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e7502.ce.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e7502.ce.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e8218.ce.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e8218.ce.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ec.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ec.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "fe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 fe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "fe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 fe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "feedback.microsoft-hohm.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 feedback.microsoft-hohm.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "feedback.search.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 feedback.search.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "feedback.windows.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 feedback.windows.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "flex.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 flex.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "g.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 g.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "h1.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 h1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "h2.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 h2.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "hostedocsp.globalsign.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 hostedocsp.globalsign.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "i1.services.social.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 i1.services.social.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "i1.services.social.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 i1.services.social.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ipv6.msftncsi.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ipv6.msftncsi.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ipv6.msftncsi.com.edgesuite.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ipv6.msftncsi.com.edgesuite.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "lb1.www.ms.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 lb1.www.ms.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "live.rads.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 live.rads.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "m.adnxs.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 m.adnxs.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "m.hotmail.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 m.hotmail.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msftncsi.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msftncsi.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msnbot-65-55-108-23.search.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msnbot-65-55-108-23.search.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msntest.serving-sys.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msntest.serving-sys.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "onesettings-db5.metron.live.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 onesettings-db5.metron.live.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "pre.footprintpredict.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 pre.footprintpredict.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "preview.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 preview.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "rad.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 rad.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "rad.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 rad.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "s0.2mdn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 s0.2mdn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "schemas.microsoft.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 schemas.microsoft.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "secure.adnxs.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 secure.adnxs.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "secure.flashtalking.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 secure.flashtalking.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "settings-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 settings-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sls.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sls.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ssw.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ssw.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "static.2mdn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 static.2mdn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe1.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe1.ws.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe2.update.microsoft.com.akadns.net," %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe2.update.microsoft.com.akadns.net,>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe2.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe2.ws.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "survey.watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 survey.watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "survey.watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 survey.watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "view.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 view.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-bn2.metron.live.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-bn2.metron.live.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-cy2.metron.live.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-cy2.metron.live.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "win10.ipv6.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 win10.ipv6.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "www.bingads.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 www.bingads.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "www.go.microsoft.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 www.go.microsoft.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "www.msftncsi.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 www.msftncsi.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a248.e.akamai.net" %WINDIR%\system32\drivers\etc\hosts
rem skype & itunes issues 
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a248.e.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "apps.skype.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 apps.skype.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "c.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 c.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "pricelist.skype.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 pricelist.skype.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "s.gateway.messenger.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 s.gateway.messenger.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ui.skype.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ui.skype.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+109
echo Done %PRun% / %PMax% Blocking More Windows Servers. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:7100
echo.
echo ###############################################################################
echo #  7. Blocking More Windows Servers  --  End                                  #
echo ###############################################################################
echo.

rem ========== 8. Disable Windows Error Recovery on Startup ==========

echo.
echo ###############################################################################
echo #  8. Disable Windows Error Recovery on Startup   --  Start                   #
echo ###############################################################################
echo.

:8000
set /A Pline=8000
set PMax=1
set PRun=0
rem set PAct=0
echo Disable Windows Error Recovery on Startup (2).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:8001
bcdedit /set recoveryenabled NO > nul 2>&1
bcdedit /set {current} bootstatuspolicy ignoreallfailures > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Disable Windows Error Recovery on Startup. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:8100
echo.
echo ###############################################################################
echo #  8. Disable Windows Error Recovery on Startup  --  End                      #
echo ###############################################################################
echo.

rem ========== 9. Internet Explorer 11 Tweaks ==========

echo.
echo ###############################################################################
echo #  9. Internet Explorer 11 Tweaks  --  Start                                  #
echo ###############################################################################
echo.

:9000
set /A Pline=9000
set PMax=3
set PRun=0
rem set PAct=0
echo Internet Explorer 11 Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:9001
set myMSG=Internet Explorer 11 Tweaks (Basic)(15).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:9002
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.com" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.com" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1

reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "PlaySounds" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d PMEM /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+15
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:9003
set myMSG=Disable IE Suggested Sites & Flip ahead (page prediction which sends browsing history to Microsoft).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:9004
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "DataStreamEnabledState" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\FlipAhead" /v "FPEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:9005
set myMSG=Add Google as search provider for IE11, and make it the default (11).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:9006
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f  > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "DisplayName" /t REG_SZ /d "Google" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURL" /t REG_SZ /d "http://www.google.com/favicon.ico" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.google.com/favicon.ico" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "OSDFileURL" /t REG_SZ /d "http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "ShowSearchSuggestions" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURL" /t REG_SZ /d "http://clients5.google.com/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "TopResultURLFallback" /t REG_SZ /d "" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "URL" /t REG_SZ /d "http://www.google.com/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+11
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:9007
:9008

:9100
echo.
echo ###############################################################################
echo #  9. Internet Explorer 11 Tweaks  --  End                                    #
echo ###############################################################################
echo.

rem ========== 10. Libraries Tweaks ==========

echo.
echo ###############################################################################
echo #   10. Libraries Tweaks  --  Start                                           #
echo ###############################################################################
echo.

:10000
set /A Pline=10000
set PMax=8
set PRun=0
rem set PAct=0
echo Libraries Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:10001
set myMSG=Remove Music, Pictures & Videos from Start Menu places (Settings > Personalization > Start > Choose which folders appear on Start)(3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10002
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\05 - Music.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\06 - Pictures.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\07 - Videos.lnk"
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10003
set myMSG=Remove Music, Pictures & Videos from Libraries (3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10004
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms"
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10005
set myMSG=Remove Libraries (60).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10006
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\system32\windows.storage.dll,-50691" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+60
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10007
set myMSG=Remove "Show Libraries" from Folder Options -> View tab (Advanced Settings).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10008
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\NavPane\ShowLibraries" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10009
set myMSG=Remove Music (appears under This PC in File Explorer)(28).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10010
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyMusic" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+28
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10011
set myMSG=Remove Pictures (appears under This PC in File Explorer) (41).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10012
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyPictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\System32\Windows.UI.Immersive.dll,-38304" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartPanel\PinnedItems\Pictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{4dcafe13-e6a7-4c28-be02-ca8c2126280d}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+41
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10013
set myMSG=Remove Videos (appears under This PC in File Explorer) (29).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10014
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ea25fbd7-3bf7-409e-b97f-3352240903f4}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{292108be-88ab-4f33-9a26-7748e62e37ad}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{5fa96407-7e77-483c-ac93-691d05850de8}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+29
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10015
set myMSG=Remove Pictures, Music, Videos from MUIcache (5).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10016
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34584" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34595" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34620" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+5
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10017
:10018

:10100
echo.
echo ###############################################################################
echo #  10. Libraries Tweaks  --  End                                              #
echo ###############################################################################
echo.


rem ========== 11. Windows Update Tweaks ==========

echo.
echo ###############################################################################
echo #  11. Windows Update Tweaks --  Start                                        #
echo ###############################################################################
echo.

:11000
set /A Pline=11000
set PMax=4
set PRun=0
rem set PAct=0
echo Windows Update Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:11001
set myMSG=Windows Update - Notify first.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11002
net stop wuauserv > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AutoInstallMinorUpdates" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f > nul 2>&1
net start wuauserv > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+5
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11003
set myMSG=Change how Windows Updates are delivered - allow only directly from Microsoft.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11004
rem 0 = Off (only directly from Microsoft)
rem 1 = Get updates from Microsoft and PCs on your local network
rem 3 = Get updates from Microsoft, PCs on your local network & PCs on the Internet (like how torrents work)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11005
set myMSG=Disable Windows Update sharing (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11006
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11007
set myMSG=Disable automatic Windows Updates.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11008
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11009
:11010

:11100
echo.
echo ###############################################################################
echo #  11. Windows Update Tweaks  --  End                                         #
echo ###############################################################################
echo.


rem ========== 12. Windows Defender Tweaks ==========

echo.
echo ###############################################################################
echo #  12. Windows Defender Tweaks --  Start                                      #
echo ###############################################################################
echo.

:12000
set /A Pline=12000
set PMax=2
set PRun=0
rem set PAct=0
echo Windows Defender Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:12001
set myMSG=Don't allow Windows Defender to submit samples to MAPS (formerly SpyNet) (4).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:12002
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:12003
set myMSG=Disable Windows Defender (8).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:12004
sc config WinDefend start= Disabled > nul 2>&1
sc config WdNisSvc start= Disabled > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > nul 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:12005
:12006

:12100
echo.
echo ###############################################################################
echo #  12. Windows Defender Tweaks  --  End                                       #
echo ###############################################################################
echo.

rem ========== Finish ==========

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]"
set "line04="AllowCortana"=dword:00000000"
set "line05="DisableWebSearch"=dword:00000001"
set "line06="AllowSearchToUseLocation"=dword:00000000"
set "line07="ConnectedSearchUseWeb"=dword:00000000"
set "line08="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo/

) > "Win 10 Cortana vollstaendig deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 Cortana vollstaendig deaktivieren.reg"
del /F /Q "%~dp0Win 10 Cortana vollstaendig deaktivieren.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive]"
set "line04="DisableLibrariesDefaultSaveToOneDrive"=dword:00000001"
set "line05="DisableFileSync"=dword:00000001"
set "line06="DisableMeteredNetworkFileSync"=dword:00000001"
set "line07="
set "line08=[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive]"
set "line09="DisableLibrariesDefaultSaveToOneDrive"=dword:00000001"
set "line10="DisableFileSync"=dword:00000001"
set "line11="DisableMeteredNetworkFileSync"=dword:00000001"
set "line12="
set "line13=[HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line14="Attributes"=dword:f090004d"
set "line15="
set "line16=[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line17="Attributes"=dword:f090004d"
set "line18="
set "line19=[HKEY_CURRENT_USER\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line20="Attributes"=dword:f090004d"
set "line21="
set "line22=[HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line23="Attributes"=dword:f090004d"
set "line24="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo/
  echo !line13!
  echo !line14!
  echo/
  echo !line16!
  echo !line17!
  echo/
  echo !line19!
  echo !line20!
  echo/
  echo !line22!
  echo !line23!
  echo/

) > "Win 10 One Drive deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 One Drive deaktivieren.reg"
del /F /Q "%~dp0Win 10 One Drive deaktivieren.reg"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0\z3.ps1""' -Verb RunAs}"

net user administrator /active:yes 

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]"
set "line04="FilterAdministratorToken"=dword:00000001"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
REGEDIT.EXE /S "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
del /F /Q "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]"
set "line04="ShowRecent"=dword:00000000"
set "line05="ShowFrequent"=dword:00000000"
set "line06="EnableAutoTray"=dword:00000000"
set "line07="
set "line08=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]"
set "line09="FolderContentsInfoTip"=dword:00000000"
set "line10="HideFileExt"=dword:00000000"
set "line11="ShowSuperHidden"=dword:00000001"
set "line12="AlwaysShowMenus"=dword:00000001"
set "line13="AutoCheckSelect"=dword:00000001"
set "line14="Hidden"=dword:00000001"
set "line15="Start_TrackDocs"=dword:00000000"
set "line16="DisablePreviewDesktop"=dword:00000000"
set "line17="TaskbarAnimations"=dword:00000000"
set "line18="ShowTaskViewButton"=dword:00000000"
set "line19="TaskbarGlomLevel"=dword:00000001"
set "line20="
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications]"
set "line22="ToastEnabled"=dword:00000000"
set "line23="
set "line24=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]"
set "line25="SoftLandingEnabled"=dword:00000000"
set "line26="SystemPaneSuggestionsEnabled"=dword:00000000"
set "line27="
set "line28=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers]"
set "line29="DisableAutoplay"=dword:00000001"
set "line30="
set "line31=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]"
set "line32="ColorPrevalence"=dword:00000001"
set "line33="
set "line34=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\DWM]"
set "line35="ColorPrevalence"=dword:00000001"
set "line36="
set "line37=[HKEY_USERS\%myvar%\Control Panel\International\User Profile]"
set "line38="HttpAcceptLanguageOptOut"=dword:00000001"
set "line39="
set "line40=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass]"
set "line41="UserAuthPolicy"=dword:00000000"
set "line42="
set "line43=[HKEY_USERS\%myvar%\Control Panel\Desktop\WindowMetrics]"
set "line44="MinAnimate"=dword:00000000"
set "line45="
set "line46=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]"
set "line47="SearchboxTaskbarMode"=dword:00000000"
set "line48="
set "line49=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel]"
set "line50="AllItemsIconView"=dword:00000000"
set "line51="StartupPage"=dword:00000001"
set "line52="
set "line53=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config]"
set "line54="DODownloadMode"=dword:00000000"
set "line55="
set "line56=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows]"
set "line57="CEIPEnable"=dword:00000000"
set "line58="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo !line26!
  echo/
  echo !line28!
  echo !line29!
  echo/
  echo !line31!
  echo !line32!
  echo/
  echo !line34!
  echo !line35!
  echo/
  echo !line37!
  echo !line38!
  echo/
  echo !line40!
  echo !line41!
  echo/
  echo !line43!
  echo !line44!
  echo/
  echo !line46!
  echo !line47!
  echo/
  echo !line49!
  echo !line50!
  echo !line51!
  echo/
  echo !line53!
  echo !line54!
  echo/
  echo !line56!
  echo !line57!
  echo/

) > "Win 10 Explorer Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Explorer Einstellungen.reg"
del /F /Q "%~dp0Win 10 Explorer Einstellungen.reg"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate]"
set "line04="AutoDownload"=dword:00000002"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Auto App Updates deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 Auto App Updates deaktivieren.reg"
del /F /Q "%~dp0Win 10 Auto App Updates deaktivieren.reg"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*


:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start

taskkill /f /IM "SearchUI.exe"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=<?xml version="1.0" encoding="UTF-16"?>"
set "line02=<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"
set "line03=  <RegistrationInfo>"
set "line04=    <URI>\Microsoft\Windows\UpdateOrchestrator\Reboot</URI>"
set "line05=  </RegistrationInfo>"
set "line06=  <Triggers>"
set "line07=    <TimeTrigger>"
set "line08=      <StartBoundary>2016-09-14T00:20:38+02:00</StartBoundary>"
set "line09=      <Enabled>true</Enabled>"
set "line10=    </TimeTrigger>"
set "line11=  </Triggers>"
set "line12=  <Principals>"
set "line13=    <Principal id="Author">"
set "line14=      <UserId>S-1-5-18</UserId>"
set "line15=      <RunLevel>LeastPrivilege</RunLevel>"
set "line16=    </Principal>"
set "line17=  </Principals>"
set "line18=  <Settings>"
set "line19=    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
set "line20=    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>"
set "line21=    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
set "line22=    <AllowHardTerminate>true</AllowHardTerminate>"
set "line23=    <StartWhenAvailable>true</StartWhenAvailable>"
set "line24=    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
set "line25=    <IdleSettings>"
set "line26=      <Duration>PT10M</Duration>"
set "line27=      <WaitTimeout>PT1H</WaitTimeout>"
set "line28=      <StopOnIdleEnd>true</StopOnIdleEnd>"
set "line29=      <RestartOnIdle>false</RestartOnIdle>"
set "line30=    </IdleSettings>"
set "line31=    <AllowStartOnDemand>true</AllowStartOnDemand>"
set "line32=    <Enabled>false</Enabled>"
set "line33=    <Hidden>false</Hidden>"
set "line34=    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
set "line35=    <WakeToRun>true</WakeToRun>"
set "line36=    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>"
set "line37=    <Priority>7</Priority>"
set "line38=    <RestartOnFailure>"
set "line39=      <Interval>PT10M</Interval>"
set "line40=      <Count>3</Count>"
set "line41=    </RestartOnFailure>"
set "line42=  </Settings>"
set "line43=  <Actions Context="Author">"
set "line44=    <Exec>"
set "line45=      <Command>%systemroot%\system32\MusNotification.exe</Command>"
set "line46=      <Arguments>RebootDialog</Arguments>"
set "line47=    </Exec>"
set "line48=  </Actions>"
set "line49=</Task>"

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo !line02!
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo !line20!
  echo !line21!
  echo !line22!
  echo !line23!
  echo !line24!
  echo !line25!
  echo !line26!
  echo !line27!
  echo !line28!
  echo !line29!
  echo !line30!
  echo !line31!
  echo !line32!
  echo !line33!
  echo !line34!
  echo !line35!
  echo !line36!
  echo !line37!
  echo !line38!
  echo !line39!
  echo !line40!
  echo !line41!
  echo !line42!
  echo !line43!
  echo !line44!
  echo !line45!
  echo !line46!
  echo !line47!
  echo !line48!
  echo !line49!

) > "Win 10 Reboot deaktivieren.xml"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:System;p:read"
schtasks /delete /F /tn "Microsoft\Windows\UpdateOrchestrator\Reboot"
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\Reboot" /xml "%~dp0Win 10 Reboot deaktivieren.xml"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:System;p:read"
del /F /Q "%~dp0Win 10 Reboot deaktivieren.xml"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=<?xml version="1.0" encoding="UTF-16"?>"
set "line02=<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"
set "line03=  <RegistrationInfo>"
set "line04=    <Date>2016-08-06T12:40:47.6863074</Date>"
set "line05=    <Author>System</Author>"
set "line06=    <URI>\Disable Windows Lock Screen</URI>"
set "line07=  </RegistrationInfo>"
set "line08=  <Triggers>"
set "line09=    <LogonTrigger>"
set "line10=      <Enabled>true</Enabled>"
set "line11=    </LogonTrigger>"
set "line12=    <SessionStateChangeTrigger>"
set "line13=      <Enabled>true</Enabled>"
set "line14=      <StateChange>SessionUnlock</StateChange>"
set "line15=    </SessionStateChangeTrigger>"
set "line16=  </Triggers>"
set "line17=  <Principals>"
set "line18=    <Principal id="Author">"
set "line19=      <UserId>%myvar%</UserId>"
set "line20=      <LogonType>InteractiveToken</LogonType>"
set "line21=      <RunLevel>HighestAvailable</RunLevel>"
set "line22=    </Principal>"
set "line23=  </Principals>"
set "line24=  <Settings>"
set "line25=    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
set "line26=    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
set "line27=    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>"
set "line28=    <AllowHardTerminate>true</AllowHardTerminate>"
set "line29=    <StartWhenAvailable>false</StartWhenAvailable>"
set "line30=    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
set "line31=    <IdleSettings>"
set "line32=      <StopOnIdleEnd>true</StopOnIdleEnd>"
set "line33=      <RestartOnIdle>false</RestartOnIdle>"
set "line34=    </IdleSettings>"
set "line35=    <AllowStartOnDemand>true</AllowStartOnDemand>"
set "line36=    <Enabled>true</Enabled>"
set "line37=    <Hidden>false</Hidden>"
set "line38=    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
set "line39=    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>"
set "line40=    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>"
set "line41=    <WakeToRun>false</WakeToRun>"
set "line42=    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>"
set "line43=    <Priority>7</Priority>"
set "line44=  </Settings>"
set "line45=  <Actions Context="Author">"
set "line46=    <Exec>"
set "line47=      <Command>reg</Command>"
set "line48=      <Arguments>add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f</Arguments>"
set "line49=    </Exec>"
set "line50=  </Actions>"
set "line51=</Task>"

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo !line02!
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo !line20!
  echo !line21!
  echo !line22!
  echo !line23!
  echo !line24!
  echo !line25!
  echo !line26!
  echo !line27!
  echo !line28!
  echo !line29!
  echo !line30!
  echo !line31!
  echo !line32!
  echo !line33!
  echo !line34!
  echo !line35!
  echo !line36!
  echo !line37!
  echo !line38!
  echo !line39!
  echo !line40!
  echo !line41!
  echo !line42!
  echo !line43!
  echo !line44!
  echo !line45!
  echo !line46!
  echo !line47!
  echo !line48!
  echo !line49!
  echo !line50!
  echo !line51!

) > "Win 10 Lockscreen deaktivieren.xml"
schtasks /create /tn "Disable Windows Lock Screen" /xml "%~dp0Win 10 Lockscreen deaktivieren.xml"
del /F /Q "%~dp0Win 10 Lockscreen deaktivieren.xml"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\ /v Start /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility\ /v DiagnosticErrorText /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticErrorText /t REG_SZ /d "" /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticLinkText /t REG_SZ /d "" /f

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
sc stop MapsBroker
sc config MapsBroker start= disabled
sc stop DoSvc
sc config DoSvc start= disabled
sc stop WSearch
sc config WSearch start= disabled

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
@ECHO off
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)
set myvar2=""
:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02= "
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line04="Cookies"=dword:00000001"
set "line05= "
set "line06=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line07="Cookies"=dword:00000001"
set "line08= "
set "line09=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line10="EnableCortana"=dword:00000000"
set "line11= "
set "line12=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line13="EnableCortana"=dword:00000000"
set "line14= "
set "line15=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons]"
set "line16="FlashPlayerEnabled"=dword:00000000"
set "line17= "
set "line18=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons]"
set "line19="FlashPlayerEnabled"=dword:00000000"
set "line20= "
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes]"
set "line22="ShowSearchSuggestionsGlobal"=dword:00000000"
set "line23= "
set "line24=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes]"
set "line25="ShowSearchSuggestionsGlobal"=dword:00000000"
set "line26= "
set "line27=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ContinuousBrowsing]"
set "line28="Enabled"=dword:00000001"
set "line29= "
set "line30=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ContinuousBrowsing]"
set "line31="Enabled"=dword:00000001"
set "line32= "
set "line33=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line34="NewTabPageDisplayOption"=dword:00000002"
set "line35= "
set "line36=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line37="NewTabPageDisplayOption"=dword:00000002"
set "line38= "
set "line39=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line40="FormSuggest Passwords"="no""
set "line41= "
set "line42=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line43="FormSuggest Passwords"="no""
set "line44= "
set "line45=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Extensions]"
set "line46="EnableExtensionDevelopment"=dword:00000001"
set "line47= "
set "line48=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Extensions]"
set "line49="EnableExtensionDevelopment"=dword:00000001"
set "line50= "

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/
  echo !line06!
  echo !line07!
  echo/
  echo !line09!
  echo !line10!
  echo/
  echo !line12!
  echo !line13!
  echo/
  echo !line15!
  echo !line16!
  echo/
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo/
  echo !line27!
  echo !line28!
  echo/
  echo !line30!
  echo !line31!
  echo/
  echo !line33!
  echo !line34!
  echo/
  echo !line36!
  echo !line37!
  echo/
  echo !line39!
  echo !line40!
  echo/
  echo !line42!
  echo !line43!
  echo/
  echo !line45!
  echo !line46!
  echo/
  echo !line48!
  echo !line49!
  echo/

) > "Win 10 Edge sichere Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Edge sichere Einstellungen.reg"
del /F /Q "%~dp0Win 10 Edge sichere Einstellungen.reg"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]"
set "line04="IconVerticalSpacing"="-1125""
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Desktopicon Abstand vertikal anpassen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
del /F /Q "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
xcopy /Y "%~dp0LayoutModification.xml" "C:\"
cd %~dp0
LGPO.exe /u "%~dp0\registry.pol"

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)
set myvar2=""
:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02= "
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Policies\Microsoft\Windows\Explorer]"
set "line04="LockedStartLayout"=dword:00000000"
set "line05= "

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 LayoutModification.reg"
REGEDIT.EXE /S "%~dp0Win 10 LayoutModification.reg"
del /F /Q "%~dp0Win 10 LayoutModification.reg"
del /F /Q "C:\LayoutModification.xml"

@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

:: ---------------------------------------------------  !!! Incorrect Data Found !!!  -------------------------------------------------------------
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control --> “WaitToKillServiceTimeout”=”3000”
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem --> “NtfsMftZoneReservation”=dword: 00000002
:: HKEY_CURRENT_USER\Control Panel\Desktop --> “MenuShowDelay”=”0”
:: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced --> “DisableThumbnailCache”=dword:00000000
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch --> “Start”=dword: 00000004
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cisvc --> “Start”=dword: 00000004
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management --> “ClearPageFileAtShutDown”=1
:: HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6} --> System.IsPinnedToNameSpaceTree"=0
:: ------------------------------------------------------------------------------------------------------------------------------------------------

REM ; Created by: The Geek Freaks - CC Alexander Zuber
REM ; http://www.thegeekfreaks.de
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /f
Reg.exe add "HKCU\Control Panel\Desktop" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cisvc" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCR\Directory\shell\runas" /f
Reg.exe add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Directory\Background\shell\runas" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\Background\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Drive\shell\runas" /f
Reg.exe add "HKCR\Drive\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Drive\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe add "HKCR\*\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f

@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
powercfg /H off

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*
exit /B

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]"
set "line04="FilterAdministratorToken"=dword:00000001"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
REGEDIT.EXE /S "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
del /F /Q "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"

@rem *** Disable Some Service ***
sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop WMPNetworkSvc
sc stop WSearch

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
REM sc config RemoteRegistry start= disabled
REM sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config WSearch start= disabled
REM sc config SysMain start= disabled

REM *** SCHEDULED TASKS tweaks ***
REM schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

REM schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
REM schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
REM schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
REM schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
REM schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
REM schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
REM The stubborn task Microsoft\Windows\SettingSync\BackgroundUploadTask can be Disabled using a simple bit change. I use a REG file for that (attached to this post).
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable


@rem *** Remove Telemetry & Data Collection ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

@REM Settings -> Privacy -> General -> Let apps use my advertising ID...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
REM - SmartScreen Filter for Store Apps: Disable
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
REM - Let websites provide locally...
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

@REM WiFi Sense: HotSpot Sharing: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
@REM WiFi Sense: Shared HotSpot Auto-Connect: Disable
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f

@REM Change Windows Updates to "Notify to schedule restart"
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
@REM Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f


REM *** Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for ***
REM 0 = hide completely, 1 = show only icon, 2 = show long search box
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

REM *** Disable MRU lists (jump lists) of XAML apps in Start Menu ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

REM *** Set Windows Explorer to start on This PC instead of Quick Access ***
REM 1 = This PC, 2 = Quick access
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

@rem Remove Apps
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
REM PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
REM PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Drawboard PDF* | Remove-AppxPackage"


@rem NOW JUST SOME TWEAKS
REM *** Show hidden files in Explorer ***
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

REM *** Show super hidden system files in Explorer ***
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

REM *** Show file extensions in Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f



REM *** Uninstall OneDrive ***
start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
rd C:\OneDriveTemp /Q /S >NUL 2>&1
rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
echo OneDrive has been removed. Windows Explorer needs to be restarted.
pause
start /wait TASKKILL /F /IM explorer.exe
start explorer.exe

@ECHO OFF

REM -- Sets global variables
COLOR 1F
SET V=6.5.6
TITLE Windows 10 TNBT: The Next Big Tweak v%V%

REM -- Checks boot state and skips elevation in safemode
COLOR 1F
wmic COMPUTERSYSTEM GET BootupState | findstr /i "fail-safe" > NUL
IF %ERRORLEVEL% EQU 0 GOTO menu_start

REM -- Elevates script if necessary
"%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system" > NUL 2>&1
IF '%ERRORLEVEL%' NEQ '0' (GOTO admin_no) ELSE (GOTO admin_yes)
:admin_no
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\runasadmin.vbs"
ECHO UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\runasadmin.vbs"
"%TEMP%\runasadmin.vbs"
EXIT /B
:admin_yes
IF EXIST "%TEMP%\runasadmin.vbs" ( DEL "%TEMP%\runasadmin.vbs" )
PUSHD "%CD%"
CD /D "%~dp0"

REM -- Checks your Windows version
ver | findstr /i "10.0.10586" > NUL
IF %ERRORLEVEL% EQU 0 SET B=VERSION 1511 (BUILD 10586)&GOTO menu_start
ver | findstr /i "10.0.14393" > NUL
IF %ERRORLEVEL% EQU 0 SET B=VERSION 1607 (BUILD 14393)&GOTO menu_start
SET B=YOUR VERSION IS UNTESTED! 
GOTO win_untested

REM -- Warns user that the script was not tested with his Windows version
:win_untested
COLOR 4F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  WARNING                                            º
ECHO º  The Windows version you are using was not tested   º
ECHO º  with this revision of TNBT. You might encounter    º
ECHO º  errors or system malfunctions when using certain   º
ECHO º  tweaks and features.                               º
ECHO º                                                     º
ECHO º  Use TNBT anyway?                                   º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  [1] I'll take the risk        [2] Exit script      º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
SET /p menu0="Select: "
IF '%menu0%' == '1' GOTO menu_start
IF '%menu0%' == '2' EXIT

REM -- Main Menu
:menu_start
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  MAIN MENU                                          º
ECHO º    [1] Windows Tweaks                               º
ECHO º    [2] Windows Features                             º
ECHO º    [3] Windows Network                              º
ECHO º    [4] Diagnostic / Repair Tools                    º
ECHO º    [5] Windows Activation Tools                     º
ECHO º    [6] Anti-Ransomware Process Faker                º
ECHO º                                                     º
ECHO º    [7] Check Windows Version                        º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Exit                                         º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu1="Select: "
IF '%menu1%' == '1' GOTO menu_tweaks
IF '%menu1%' == '2' GOTO menu_features
IF '%menu1%' == '3' GOTO menu_network
IF '%menu1%' == '4' GOTO menu_diagnostic
IF '%menu1%' == '5' GOTO menu_activation
IF '%menu1%' == '6' GOTO menu_fakeprocess
IF '%menu1%' == '7' WINVER & GOTO menu_start
IF '%menu1%' == '0' EXIT
GOTO menu_start

REM -- Tweaks Menu
:menu_tweaks
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  WINDOWS TWEAKS                                     º
ECHO º    [1] Apply Registry Tweaks                        º
ECHO º    [2] Apply Services Tweaks                        º
ECHO º    [3] Apply Thirdparty Services Tweaks             º
ECHO º    [4] Apply Scheduled Tasks Tweaks                 º
ECHO º                                                     º
ECHO º    [5] Recover Registry                             º
ECHO º    [6] Recover Services                             º
ECHO º    [7] Recover Thirdparty Services                  º
ECHO º    [8] Recover Scheduled Tasks                      º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Main Menu                            º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu2="Select: "
IF '%menu2%' == '1' GOTO seq_tweakregistry
IF '%menu2%' == '2' GOTO seq_tweakservices
IF '%menu2%' == '3' GOTO seq_tweaktpservices
IF '%menu2%' == '4' GOTO seq_tweakscheduled
IF '%menu2%' == '5' GOTO seq_recoverregistry
IF '%menu2%' == '6' GOTO seq_recoverservices
IF '%menu2%' == '7' GOTO seq_recovertpservices
IF '%menu2%' == '8' GOTO seq_recoverscheduled
IF '%menu2%' == '0' GOTO menu_start
GOTO menu_start

REM -- Registry Tweaks start
:seq_tweakregistry
COLOR 2F
ECHO.

REM -- Disables automatic app updates
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d 4 /f > NUL 2>&1

REM -- Disables Aero Shake
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v NoWindowMinimizingShortcuts /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoWindowMinimizingShortcuts /t REG_DWORD /d 1 /f

REM -- Disables Notifications in File Explorer in Windows 10
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f

REM -- Enables Transparency, sets accent color, activates window/taskbar colorization
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v AccentColor /t REG_DWORD /d 0x00d77800 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v Composition /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationColor /t REG_DWORD /d 0xc40078d7 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationAfterglow /t REG_DWORD /d 0xc40078d7 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationGlassAttribute /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableWindowColorization /t REG_DWORD /d 1 /f

REM -- Enables an additional security feature for Windows Defender
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v MpEnablePus /t REG_DWORD /d 1 /f

REM -- Disables Driver Signing
reg add "HKLM\Software\Microsoft\Driver Signing" /v "Policy" /t REG_BINARY /d "01" /f

REM -- Sets Logon Background to accent color
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f

REM -- Removes Pin to start from context menus
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1

REM -- Disables various Telemetry and data collection/synchronization settings (ShutUp10 equivalent)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t "REG_DWORD" /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t "REG_DWORD" /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t "REG_DWORD" /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Biometrics" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableSensors /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v SpynetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v SubmitSamplesConsent /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WMDRM" /v DisableOnline /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\System\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v Start /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncPolicy /t REG_DWORD /d 5 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Deny /f

REM -- Enables "This PC" icon on deksktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f

REM -- Enables classic Control Panel view
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f

reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f

REM -- Disables bing web search
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f

REM -- Disables automatic driver downloads from Windows Update
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 2 /f

REM -- Shows file extensions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

REM -- Sets default view for explorer to "This PC"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

REM -- Hides Task View Button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f

REM -- Disable Tips, Notifications and Notification Center
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SoftLanding" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f

REM -- Disables security warnings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d 1808 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f

REM -- Sets timeout for the System to end processes/services after the user tries to shutdown
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "10000" /f
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "10000" /f

REM -- Improves responsiveness of your system by removing delays
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 75 /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 75 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 75 /f

REM -- Disables automatic maintenance
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f

REM -- Disables Encrypting File System
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableEncryption" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f

REM -- Disables Active Desktop
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d 1 /f

REM -- Disables Smart Screen
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t "REG_DWORD" /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d 0 /f

REM -- Disables Lockscreen (no longer working on Windows Core/Pro 1607)
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f

REM -- Disables Wifi Sense
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f

REM -- Disables sending files to encrypted drives
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d 0 /f

REM -- Disables OneDrive Sync
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

REM -- Disables settings synchronization
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f

REM -- Increases wallpaper image quality
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f

REM -- Disables automatic update for downloaded maps
reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t "REG_DWORD" /d 0 /f

REM -- Removes OneDrive from autorun and explorer
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f > NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f > NUL 2>&1

REM -- Deactivate screensaver
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d 0 /f

REM -- Disables GameDVR
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f

REM -- Removes frequent/recent entries from explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f

REM -- Disables CD/DVD/USB autorun
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutorun" /t REG_DWORD /d "0xFF" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutorun" /t REG_DWORD /d "0xFF" /f

REM -- Sets computers active hours to 10-22h
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "10" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "22" /f

REM -- Removes "Scan with Windows defender" from context menu (only works if WD is disabled)
reg delete "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\EPP" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\EPP" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\EPP" /f > NUL 2>&1

REM -- Disables reveal password button
reg add "HKLM\Software\Policies\Microsoft\Windows\CredUI" /v DisablePasswordReveal /t REG_DWORD /d 1 /f

REM -- Internet Explorer / Microsoft Edge optimizations
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer" /v AllowServicePoweredQSA /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v AutoSuggest /t REG_SZ /d no /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" /v NoUpdateCheck /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v PolicyDisableGeolocation /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "Use FormSuggest" /t REG_SZ /d no /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v DoNotTrack /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v ShowSearchSuggestionsGlobal /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 0 /f

REM -- Prevent device metadata retrieval from the Internet
reg add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f

REM -- Disable Windows Updates for Malicious Software Removal Tool
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f

REM -- Disables Aero Peek
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisablePreviewDesktop /t REG_DWORD /d 1 /f

REM -- Sets Windows sound scheme to "No Sounds"
reg add "HKCU\AppEvents\Schemes" /t REG_SZ /d ".None" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\AppGPFault\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\CCSelect\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\ChangeTheme\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Close\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Maximize\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\MenuCommand\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\MenuPopup\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Minimize\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm10\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm2\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm3\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm4\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm5\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm6\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm7\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm8\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Alarm9\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call10\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call2\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call3\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call4\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call5\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call6\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call7\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call8\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Looping.Call9\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\Open\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\PrintComplete\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreDown\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\RestoreUp\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\ShowBand\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExit\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\SystemQuestion\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsLogoff\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsLogon\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUnlock\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.Current" /t REG_SZ /d "" /f
reg add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.Current" /t REG_SZ /d "" /f

REM -- Restarts explorer.exe to make registry tweaks visible without reboot
taskkill /IM explorer.exe /F & explorer.exe > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Services Tweaks start
:seq_tweakservices
COLOR 2F
ECHO.

REM -- Disables Windows Telemetry services
sc config diagnosticshub.standardcollector.service start= disabled
net stop diagnosticshub.standardcollector.service > NUL 2>&1
sc config DiagTrack start= disabled
net stop DiagTrack > NUL 2>&1
sc config dmwappushservice start= disabled
net stop dmwappushservice > NUL 2>&1

REM -- Disables OneDrive service
sc config OneSyncSvc start= disabled
net stop OneSyncSvc > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\OneSyncSvc_Session1" /v "Start" /t REG_DWORD /d 4 /f > NUL 2>&1

REM -- Disables RetailDemo service
sc config RetailDemo start=disabled
net stop RetailDemo > NUL 2>&1

REM -- Disables Windows Search service
sc config WSearch start= disabled
net stop WSearch > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

REM -- Disables Adobe services if installed
sc config AdobeARMservice start= disabled > NUL 2>&1
net stop AdobeARMservice > NUL 2>&1
sc config AGSService start= disabled > NUL 2>&1
net stop AGSService > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Disabled third party services
:seq_tweaktpservices
COLOR 2F
ECHO.
ECHO Disabling third party services...

REM -- Disables Google Chrome Update services
sc config gupdate start= demand > NUL 2>&1
net stop gupdate > NUL 2>&1

REM -- Disables Adobe services
sc config AdobeARMservice start= demand > NUL 2>&1
net stop AdobeARMservice > NUL 2>&1
sc config AGSService start= demand > NUL 2>&1
net stop AGSService > NUL 2>&1
sc config AdobeFlashPlayerUpdateSvc start= demand > NUL 2>&1
net stop AdobeFlashPlayerUpdateSvc > NUL 2>&1

REM -- Disables NVIDIA Geforce Experience service
sc config GfExperienceService start= demand > NUL 2>&1
net stop GfExperienceService > NUL 2>&1

REM -- Disables AMD service
sc config "AMD External Events Utility" start= demand > NUL 2>&1
net stop "AMD External Events Utility" > NUL 2>&1

REM -- Disables Conexant Audio Message Service
sc config CxAudMsg start= demand > NUL 2>&1
net stop CxAudMsg > NUL 2>&1
sc config SAService start= demand > NUL 2>&1
net stop SAService > NUL 2>&1

REM -- Disables Yandex Browser Update service
sc config YandexBrowserService start= demand > NUL 2>&1
net stop YandexBrowserService > NUL 2>&1

ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Scheduled Tasks Tweaks start
:seq_tweakscheduled
COLOR 2F
ECHO.
ECHO Disabling Windows scheduled tasks...
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Offline Files\Background Synchronization" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Offline Files\Logon Synchronization" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable > NUL 2>&1
schtasks /Change /TN "Driver Easy Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Registry Recovery start
:seq_recoverregistry
COLOR 2F
ECHO.

REM -- Recovers the default Windows registry settings - see Registry Tweaks for detailed information
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d 4 /f > NUL 2>&1
reg delete "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v NoWindowMinimizingShortcuts /f > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoWindowMinimizingShortcuts /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v AccentColor /t REG_DWORD /d 0x00d77800 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v Composition /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationColor /t REG_DWORD /d 0xc40078d7 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationAfterglow /t REG_DWORD /d 0xc40078d7 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v ColorizationGlassAttribute /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v EnableWindowColorization /t REG_DWORD /d 1 /f
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Driver Signing" /v "Policy" /t REG_BINARY /d "00" /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 1 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /f > NUL 2>&1
reg add "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /t REG_SZ /d {470C0EBD-5D73-4d58-9CED-E91E22E23282} /f > NUL 2>&1
reg add "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /t REG_SZ /d {470C0EBD-5D73-4d58-9CED-E91E22E23282} /f > NUL 2>&1
reg add "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /t REG_SZ /d {470C0EBD-5D73-4d58-9CED-E91E22E23282} /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 1 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /f > NUL 2>&1
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "510" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "126" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /f > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /f > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /f > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /f > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 1 /f
reg delete "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 1 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SoftLanding" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /f > NUL 2>&1
reg delete "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /f > NUL 2>&1
reg delete "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /f > NUL 2>&1
reg delete "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "5000" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableEncryption" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 0 /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /f > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 1 /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /f > NUL 2>&1
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 400 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 400 /f
reg delete "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /f > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t "REG_DWORD" /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t "REG_DWORD" /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t "REG_DWORD" /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t "REG_DWORD" /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t "REG_DWORD" /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /t REG_SZ /d ""%LocalAppData%\Microsoft\OneDrive\OneDrive.exe" /background" /f
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 1 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutorun" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutorun" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Siuf" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "8" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "17" /f
reg add "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\EPP" /t REG_SZ /d "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg add "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\EPP" /t REG_SZ /d "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg add "HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\EPP" /t REG_SZ /d "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Biometrics" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontReportInfectionInformation /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CredUI" /v DisablePasswordReveal /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableSensors /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v PreventHandwritingDataSharing /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v SpynetReporting /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v SubmitSamplesConsent /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WMDRM" /v DisableOnline /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f
reg add "HKLM\System\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer" /v AllowServicePoweredQSA /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v AutoSuggest /t REG_SZ /d yes /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Infodelivery\Restrictions" /v NoUpdateCheck /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v PolicyDisableGeolocation /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "Use FormSuggest" /t REG_SZ /d yes /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d yes /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v ShowSearchSuggestionsGlobal /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v Start /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncPolicy /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v Value /t REG_SZ /d Allow /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v DisablePreviewDesktop /t REG_DWORD /d 0 /f
taskkill /IM explorer.exe /F & explorer.exe > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Services recovery start
:seq_recoverservices
COLOR 2F
ECHO.

REM -- Recovers the default Windows services - see Services Tweaks for detailed information
sc config diagnosticshub.standardcollector.service start= auto
net start diagnosticshub.standardcollector.service > NUL 2>&1
sc config DiagTrack start= auto
net start DiagTrack > NUL 2>&1
sc config dmwappushservice start= auto
net start dmwappushservice > NUL 2>&1
sc config OneSyncSvc start= auto
net start OneSyncSvc > NUL 2>&1
sc config RetailDemo start= demand
sc config WSearch start= auto
net start WSearch > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Recover third party services
:seq_recovertpservices
COLOR 2F
ECHO.
ECHO Recovering third party services...
sc config gupdate start= delayed-auto > NUL 2>&1
net start gupdate > NUL 2>&1
sc config AdobeARMservice start= auto > NUL 2>&1
net start AdobeARMservice > NUL 2>&1
sc config AGSService start= auto > NUL 2>&1
net start AGSService > NUL 2>&1
sc config GfExperienceService start= auto > NUL 2>&1
net start GfExperienceService > NUL 2>&1
sc config AdobeFlashPlayerUpdateSvc start= auto > NUL 2>&1
net start AdobeFlashPlayerUpdateSvc > NUL 2>&1
sc config "AMD External Events Utility" start= auto > NUL 2>&1
net start "AMD External Events Utility" > NUL 2>&1
sc config CxAudMsg start= auto > NUL 2>&1
net start CxAudMsg > NUL 2>&1
sc config SAService start= auto > NUL 2>&1
net start SAService > NUL 2>&1
sc config YandexBrowserService start= auto > NUL 2>&1
net start YandexBrowserService > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Scheduled Tasks recovery start
:seq_recoverscheduled
COLOR 2F
ECHO.

REM -- Recovers the default Scheduled Tasks
ECHO Recovering Windows scheduled tasks
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetCfg\BindingWorkItemQueueHandler" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Offline Files\Background Synchronization" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Offline Files\Logon Synchronization" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /Enable > NUL 2>&1
schtasks /Change /TN "Driver Easy Scheduled Scan" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Enable > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_tweaks

REM -- Features Menu
:menu_features
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  WINDOWS FEATURES                                   º
ECHO º    [1] Disable Windows Defender                     º
ECHO º    [2] Disable Hibernation                          º
ECHO º    [3] Disable OneDrive                             º
ECHO º    [4] Disable Windows Update                       º
ECHO º    [5] Remove Windows Apps except store             º
ECHO º    [6] Remove all Windows Apps                      º
ECHO º    [7] Enable OS compression                        º
ECHO º                                                     º
ECHO º    [8] Recover Windows Defender                     º
ECHO º    [9] Recover Hibernation                          º
ECHO º   [10] Recover OneDrive                             º
ECHO º   [11] Recover Windows Update                       º
ECHO º   [12] Recover all Windows Apps                     º
ECHO º   [13] Disable OS compression                       º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Main Menu                            º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu3="Select: "
IF '%menu3%' == '1' GOTO seq_disabledefender
IF '%menu3%' == '2' GOTO seq_disablehybernation
IF '%menu3%' == '3' GOTO seq_disableonedrive
IF '%menu3%' == '4' GOTO seq_disablewinupdate
IF '%menu3%' == '5' GOTO seq_removeappsexceptstore
IF '%menu3%' == '6' GOTO seq_removeapps
IF '%menu3%' == '7' GOTO seq_enablecompression
IF '%menu3%' == '8' GOTO seq_recoverdefender
IF '%menu3%' == '9' GOTO seq_recoverhybernation
IF '%menu3%' == '10' GOTO seq_recoveronedrive
IF '%menu3%' == '11' GOTO seq_recoverwinupdate
IF '%menu3%' == '12' GOTO seq_recoverapps
IF '%menu3%' == '13' GOTO seq_disablecompression
IF '%menu3%' == '0' GOTO menu_start
GOTO menu_start

REM -- Disables Windows Defender
:seq_disabledefender
COLOR 2F
ECHO.
sc config Sense start= disabled > NUL 2>&1
net stop Sense > NUL 2>&1
sc config WdFilter start= disabled > NUL 2>&1
net stop WdFilter > NUL 2>&1
sc config WdNisSvc start= disabled > NUL 2>&1
net stop WdNisSvc Track > NUL 2>&1
sc config WinDefend start= disabled > NUL 2>&1
net stop WinDefend > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d 0 /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Disables Hybrid Boot aka Hibernation
:seq_disablehybernation
COLOR 2F
ECHO.
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f
powercfg /hibernate off > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Disables OneDrive
:seq_disableonedrive
COLOR 2F
ECHO.
taskkill /F /IM OneDrive.exe /T > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f
sc config OneSyncSvc start= disabled
net stop OneSyncSvc > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d 4 /f > NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Disables Windows Update so you can update via Windows Update MiniTool instead
:seq_disablewinupdate
COLOR 2F
ECHO.
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "3G" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "4G" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "Default" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "Ethernet" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "WiFi" /t REG_DWORD /d 2 /f > NUL 2>&1
sc config wuauserv start= disabled
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Refresh Settings" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sih" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sihboot" /Disable > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "DeferUpgrade" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AlwaysAutoRebootAtScheduledTime" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Removes all windows apps excluding the windows store
:seq_removeappsexceptstore
COLOR 2F
ECHO.
PowerShell.exe -Command "Get-AppxPackage | where-object {$_.name -notlike '*store*'} | Remove-AppxPackage" -ErrorAction SilentlyContinue
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Removes all windows apps including the windows store
:seq_removeapps
COLOR 2F
ECHO.
PowerShell.exe -Command "Get-AppxPackage | Remove-AppxPackage" -ErrorAction SilentlyContinue
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Enables Windows OS compression which uses zip to compress OS files
:seq_enablecompression
COLOR 2F
ECHO.
compact.exe /CompactOS:always /Q
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Recovers the Windows Defender
:seq_recoverdefender
COLOR 2F
ECHO.
sc config Sense start= demand > NUL 2>&1
net start Sense > NUL 2>&1
sc config WdFilter start= boot > NUL 2>&1
net start WdFilter > NUL 2>&1
sc config WdNisSvc start= demand > NUL 2>&1
net start WdNisSvc > NUL 2>&1
sc config WinDefend start= auto > NUL 2>&1
net start WinDefend > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "3" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "3" /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Enable > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Policy Manager" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /t REG_EXPAND_SZ /d "%ProgramFiles%\Windows Defender\MSASCuiL.exe" /f
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Recovers Hybrid Boot
:seq_recoverhybernation
COLOR 2F
ECHO.
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 1 /f
powercfg /hibernate on > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Recovers OneDrive
:seq_recoveronedrive
COLOR 2F
ECHO.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /t REG_SZ /d ""C:\Users\Test\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background"C:\Users\Test\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background" /f > NUL 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 0 /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /f > NUL 2>&1
sc config OneSyncSvc start= auto
net start OneSyncSvc > NUL 2>&1
reg add "HKLM\System\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 1 /f > NUL 2>&1
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Recovers Windows Update
:seq_recoverwinupdate
COLOR 2F
ECHO.
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Enable > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d 4 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "3G" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "4G" /t REG_DWORD /d 2 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "Default" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "Ethernet" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost" /v "WiFi" /t REG_DWORD /d 1 /f > NUL 2>&1
sc config wuauserv start= demand
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Refresh Settings" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sih" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sihboot" /Enable > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /f > NUL 2>&1
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "DeferUpgrade" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /f > NUL 2>&1
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Reinstalls all default windows apps
:seq_recoverapps
COLOR 2F
ECHO.
PowerShell.exe -Command "Get-AppxPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register ($_.InstallLocation + '\AppXManifest.xml')}" -ErrorAction SilentlyContinue
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Disables Windows OS compression
:seq_disablecompression
COLOR 2F
ECHO.
compact.exe /CompactOS:never /Q
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_features

REM -- Network Menu
:menu_network
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  WINDOWS NETWORK                                    º
ECHO º    [1] Set Network as Private                       º
ECHO º    [2] Set Network as Public                        º
ECHO º    [3] Show Network Configuration                   º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Main Menu                            º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu4="Select: "
IF '%menu4%' == '1' GOTO net_setprivate
IF '%menu4%' == '2' GOTO net_setpublic
IF '%menu4%' == '3' GOTO net_showconfig
IF '%menu4%' == '0' GOTO menu_start
GOTO menu_start

REM -- Sets your current network interface to private
:net_setprivate
COLOR 2F
ECHO.
ECHO Loading Current Network(s)...
PowerShell.exe -Command "Get-NetConnectionProfile"
SET /p netindex="Select InterfaceIndex: "
PowerShell.exe -Command "Set-NetConnectionProfile -InterfaceIndex %netindex% -NetworkCategory Private"
ECHO.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_network

REM -- Sets your current network interface to public
:net_setpublic
COLOR 2F
ECHO.
ECHO Loading Current Network(s)...
PowerShell.exe -Command "Get-NetConnectionProfile"
SET /p netindex="Select InterfaceIndex: "
PowerShell.exe -Command "Set-NetConnectionProfile -InterfaceIndex %netindex% -NetworkCategory Public"
ECHO.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_network

REM -- Outputs your current network interfaces
:net_showconfig
COLOR 2F
ECHO.
ipconfig /all
ECHO.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_network

REM -- Diagnostic Menu
:menu_diagnostic
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  DIAGNOSTIC / REPAIR TOOLS                          º
ECHO º    [1] Complete Windows Integrity Check             º
ECHO º    [2] Fix Windows Network                          º
ECHO º    [3] Fix Windows Update                           º
ECHO º    [4] Clean Up Windows                             º
ECHO º    [5] Setup System CMD on Login (Safemode)         º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Main Menu                            º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu5="Select: "
IF '%menu5%' == '1' GOTO fix_integrety
IF '%menu5%' == '2' GOTO fix_network
IF '%menu5%' == '3' GOTO fix_winupdate
IF '%menu5%' == '4' GOTO fix_cleanup
IF '%menu5%' == '5' GOTO fix_systemcmd
IF '%menu5%' == '0' GOTO menu_start
GOTO menu_start

REM -- performs an integrety check for system files
:fix_integrety
COLOR 2F
ECHO.
chkdsk /scan
net start RpcLocator > NUL 2>&1
dism /Online /Cleanup-Image /CheckHealth
dism /Online /Cleanup-Image /ScanHealth
dism /Online /Cleanup-Image /RestoreHealth
sfc /scannow
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_diagnostic

REM -- Script to reset network related services and caches
:fix_network
COLOR 2F
ECHO.
sc config BFE start= auto
sc config Dhcp start= auto
sc config Dnscache start= auto
sc config DPS start= auto
sc config lmhosts start= auto
sc config MpsSvc start= auto
sc config NlaSvc start= auto
sc config nsi start= auto
sc config Wcmsvc start= auto
sc config Winmgmt start= auto
sc config NcbService start= demand
sc config Netman start= demand
sc config netprofm start= demand
sc config WinHttpAutoProxySvc start= demand
sc config WlanSvc start= demand
sc config WwanSvc start= demand
net start DPS > NUL 2>&1
net start BFE > NUL 2>&1
net start MpsSvc > NUL 2>&1
net start nsi > NUL 2>&1
net start NlaSvc > NUL 2>&1
net start Dnscache > NUL 2>&1
net start Dhcp > NUL 2>&1
net start Wcmsvc > NUL 2>&1
wmic path win32_networkadapter where index=0 call disable > NUL 2>&1
wmic path win32_networkadapter where index=1 call disable > NUL 2>&1
wmic path win32_networkadapter where index=2 call disable > NUL 2>&1
wmic path win32_networkadapter where index=3 call disable > NUL 2>&1
wmic path win32_networkadapter where index=4 call disable > NUL 2>&1
wmic path win32_networkadapter where index=5 call disable > NUL 2>&1
wmic path win32_networkadapter where index=0 call enable > NUL 2>&1
wmic path win32_networkadapter where index=1 call enable > NUL 2>&1
wmic path win32_networkadapter where index=2 call enable > NUL 2>&1
wmic path win32_networkadapter where index=3 call enable > NUL 2>&1
wmic path win32_networkadapter where index=4 call enable > NUL 2>&1
wmic path win32_networkadapter where index=5 call enable > NUL 2>&1
netsh advfirewall reset > NUL 2>&1
route -f > NUL 2>&1
arp -d * > NUL 2>&1
nbtstat -r > NUL 2>&1
nbtstat -rr > NUL 2>&1
ipconfig /release > NUL 2>&1
ipconfig /renew > NUL 2>&1
ipconfig /flushdns > NUL 2>&1
ipconfig /registerdns > NUL 2>&1
netsh int 6to4 reset all > NUL 2>&1
netsh int httpstunnel reset all > NUL 2>&1
netsh int ipv4 reset all > NUL 2>&1
netsh int ipv6 reset all > NUL 2>&1
netsh int isatap reset all > NUL 2>&1
netsh int portproxy reset all > NUL 2>&1
netsh int tcp reset all > NUL 2>&1
netsh int teredo reset all > NUL 2>&1
netsh winsock reset > NUL 2>&1
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_diagnostic

REM -- Script to reset Windows Update related services, caches and registry keys
:fix_winupdate
COLOR 2F
ECHO.
sc config TrkWks start= auto
net start TrkWks > NUL 2>&1
fsutil usn deletejournal /d /n c: > NUL 2>&1
chkdsk /scan > NUL 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies" /f > NUL 2>&1
reg delete "HKCU\Software\Microsoft\WindowsSelfHost" /f > NUL 2>&1
reg delete "HKCU\Software\Policies" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Policies" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /f > NUL 2>&1
reg delete "HKLM\Software\Microsoft\WindowsSelfHost" /f > NUL 2>&1
reg delete "HKLM\Software\Policies" /f > NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Policies" /f > NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f > NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f > NUL 2>&1
reg delete "HKLM\Software\WOW6432Node\Policies" /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Refresh Settings" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sih" /Enable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sihboot" /Enable > NUL 2>&1
sc config bits start= disabled
sc config cryptSvc start= disabled
sc config UsoSvc start= disabled
sc config winmgmt start= disabled
sc config wuauserv start= disabled
taskkill /im TiWorker.exe /f > NUL 2>&1
net stop bits /y > NUL 2>&1
net stop cryptSvc /y > NUL 2>&1
net stop UsoSvc /y > NUL 2>&1
net stop winmgmt /y > NUL 2>&1
winmgmt /salvagerepository > NUL 2>&1
taskkill /im TiWorker.exe /f > NUL 2>&1
net stop wuauserv /y > NUL 2>&1
rmdir "%systemroot%\SoftwareDistribution\Download\" /s /q > NUL 2>&1
del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr0.dat" > NUL 2>&1
del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr1.dat" > NUL 2>&1
sc config BFE start= auto
sc config Dhcp start= auto
sc config MpsSvc start= auto
sc config netprofm start= auto
sc config NlaSvc start= auto
sc config nsi start= auto
sc config WinHttpAutoProxySvc start= auto
sc config Wcmsvc start= auto
net start DPS > NUL 2>&1
net start BFE > NUL 2>&1
net start MpsSvc > NUL 2>&1
net start nsi > NUL 2>&1
net start NlaSvc > NUL 2>&1
net start Dhcp > NUL 2>&1
net start BITS > NUL 2>&1
net start wuauserv > NUL 2>&1
net start WinHttpAutoProxySvc > NUL 2>&1
net start Wcmsvc > NUL 2>&1
wmic path win32_networkadapter where index=0 call disable > NUL 2>&1
wmic path win32_networkadapter where index=1 call disable > NUL 2>&1
wmic path win32_networkadapter where index=2 call disable > NUL 2>&1
wmic path win32_networkadapter where index=3 call disable > NUL 2>&1
wmic path win32_networkadapter where index=4 call disable > NUL 2>&1
wmic path win32_networkadapter where index=5 call disable > NUL 2>&1
wmic path win32_networkadapter where index=0 call enable > NUL 2>&1
wmic path win32_networkadapter where index=1 call enable > NUL 2>&1
wmic path win32_networkadapter where index=2 call enable > NUL 2>&1
wmic path win32_networkadapter where index=3 call enable > NUL 2>&1
wmic path win32_networkadapter where index=4 call enable > NUL 2>&1
wmic path win32_networkadapter where index=5 call enable > NUL 2>&1
route -f > NUL 2>&1
arp -d * > NUL 2>&1
nbtstat -r > NUL 2>&1
nbtstat -rr > NUL 2>&1
ipconfig /release > NUL 2>&1
ipconfig /renew > NUL 2>&1
ipconfig /flushdns > NUL 2>&1
ipconfig /registerdns > NUL 2>&1
Dism /Online /Cleanup-Image /RestoreHealth > NUL 2>&1
Dism /Online /Cleanup-Image /StartComponentCleanup > NUL 2>&1
cleanmgr /sageset:65535 & cleanmgr /sagerun:65535
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_diagnostic

REM -- Removes various junk like temp files, shadowcopies and recyclebin
:fix_cleanup
COLOR 2F
ECHO.
fsutil usn deletejournal /d /n c: > NUL 2>&1
chkdsk /scan > NUL 2>&1
Dism /Online /Cleanup-Image /CheckHealth > NUL 2>&1
Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase > NUL 2>&1
winmgmt /salvagerepository > NUL 2>&1
compact /CompactOs:never > NUL 2>&1
del "%temp%\*" /s /f /q > NUL 2>&1
del "C:\$Recycle.bin\*" /s /f /q > NUL 2>&1
del "D:\$Recycle.bin\*" /s /f /q > NUL 2>&1
del "%systemroot%\temp\*" /s /f /q > NUL 2>&1
vssadmin delete shadows /for=c: /all /quiet > NUL 2>&1
cleanmgr /sageset:65535 & cleanmgr /sagerun:65535
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_diagnostic

REM -- Checks current system state (normal or safemode)
:fix_systemcmd
COLOR 2F
wmic COMPUTERSYSTEM GET BootupState | findstr /i "fail-safe" > NUL
IF %errorlevel% EQU 0 GOTO fix_safemode
IF %errorlevel% EQU 1 GOTO fix_normalmode

REM -- If running in Safemode, gives option to install the system CMD on Login screen
:fix_safemode
ECHO System running in Safemode. Do you want to install or uninstall System CMD^? [install^|uninstall]
SET /p systemcmd="Select: "
IF '%systemcmd%' == 'install' GOTO systemcmdinstall
IF '%systemcmd%' == 'uninstall' GOTO systemcmduninstall

REM -- Takes own of utilman.exe, creates a backup and replaces utilman.exe with cmd.exe
:systemcmdinstall
ECHO Installing System CMD on Login...
icacls "%SYSTEMROOT%\system32\Utilman.exe" /grant:r %username%:F /T /C /Q > NUL 2>&1
IF NOT EXIST "%SYSTEMROOT%\system32\Utilman.bak" (COPY /Y "%SYSTEMROOT%\system32\Utilman.exe" "%SYSTEMROOT%\system32\Utilman.bak") > NUL 2>&1
DEL "%SYSTEMROOT%\system32\Utilman.exe" > NUL 2>&1
COPY /Y "%SYSTEMROOT%\system32\cmd.exe" "%SYSTEMROOT%\system32\Utilman.exe" > NUL 2>&1
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
msconfig
GOTO menu_diagnostic

REM -- Reverts original utilman.exe
:systemcmduninstall
ECHO Uninstalling System CMD on Login...
DEL "%SYSTEMROOT%\system32\Utilman.exe" > NUL 2>&1
COPY /Y "%SYSTEMROOT%\system32\Utilman.bak" "%SYSTEMROOT%\system32\Utilman.exe" > NUL 2>&1
ECHO.
ECHO Done...
ECHO You should reboot your computer now.
ECHO Press any key to got back to the menu.
PAUSE > NUL
msconfig
GOTO menu_diagnostic

REM -- If running in normal mode, just shows a warning message
:fix_normalmode
ECHO.
ECHO Note: This needs to be done in Windows Safemode, otherwise it won't work.
ECHO Restart your computer and boot into Safemode (minimal).
ECHO.
ECHO Press any key to got back to the menu.
PAUSE > NUL
msconfig
GOTO menu_diagnostic

REM -- Activation Menu
:menu_activation
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  WINDOWS ACTIVATION TOOLS                           º
ECHO º    [1] Uninstall Windows Key                        º
ECHO º    [2] Install Windows Key                          º
ECHO º    [3] Change KMS Server                            º
ECHO º    [4] Inject Windows GVLK Key                      º
ECHO º    [5] Inject Office GVLK Key                       º
ECHO º    [6] Show Windows/Office Activation Status        º
ECHO º    [7] Activate Windows/Office with KMS             º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Main Menu                            º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu6="Select: "
IF '%menu6%' == '1' GOTO act_uninstallkey
IF '%menu6%' == '2' GOTO act_installkey
IF '%menu6%' == '3' GOTO act_changekms
IF '%menu6%' == '4' GOTO act_injectkeywindows
IF '%menu6%' == '5' GOTO act_injectkeyoffice
IF '%menu6%' == '6' GOTO act_activationstatus
IF '%menu6%' == '7' GOTO act_activatenow
IF '%menu6%' == '0' GOTO menu_start
GOTO menu_start

REM -- Uninstalls the current Windows key
:act_uninstallkey
COLOR 2F
ECHO.
START /WAIT slmgr -upk
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Option to manually install a new Windows key
:act_installkey
COLOR 2F
ECHO.
SET /p winkey="Insert Key: "
START /WAIT slmgr -ipk %winkey%
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Checks for current activation status for Windows and Office
:act_activationstatus
COLOR 2F
ECHO.
START /WAIT slmgr /dli
IF EXIST "%programfiles(x86)%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office16\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office16\" > NUL 2>&1
CD %opath% > NUL 2>&1
cscript ospp.vbs /dstatus
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Simple routine to change the current KMS server
:act_changekms
COLOR 2F
ECHO.
SET /p kmsserver="KMS Server IP: "
SET /p kmsport="KMS Server Port: "
IF EXIST "%programfiles(x86)%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office16\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office16\" > NUL 2>&1
CD %opath% > NUL 2>&1
ECHO Setting KMS Server to: %kmsserver%:%kmsport%...
cscript ospp.vbs /sethst:%kmsserver%
cscript ospp.vbs /setprt:%kmsport%
START /WAIT slmgr /skms %kmsserver%:%kmsport%
START /WAIT slmgr /skhc
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Windows Activation Menu
:act_injectkeywindows
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  INJECT WINDOWS GVLK KEY                            º
ECHO º    [1] Windows 10 Professional                      º
ECHO º    [2] Windows 10 Professional N                    º
ECHO º    [3] Windows 10 Education                         º
ECHO º    [4] Windows 10 Education N                       º
ECHO º    [5] Windows 10 Enterprise                        º
ECHO º    [6] Windows 10 Enterprise N                      º
ECHO º    [7] Windows 10 Enterprise 2015 LTSB              º
ECHO º    [8] Windows 10 Enterprise 2015 LTSB N            º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Activation Menu                      º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu7="Select: "
IF '%menu7%' == '1' GOTO key_w10_1
IF '%menu7%' == '2' GOTO key_w10_2
IF '%menu7%' == '3' GOTO key_w10_3
IF '%menu7%' == '4' GOTO key_w10_4
IF '%menu7%' == '5' GOTO key_w10_5
IF '%menu7%' == '6' GOTO key_w10_6
IF '%menu7%' == '7' GOTO key_w10_7
IF '%menu7%' == '8' GOTO key_w10_8
IF '%menu7%' == '0' GOTO menu_activation
GOTO act_injectkeywindows

REM -- Uninstalls current Windows key and injects GVLK key
:key_w10_1
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
GOTO key_end

:key_w10_2
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk MH37W-N47XK-V7XM9-C7227-GCQG9
GOTO key_end

:key_w10_3
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk NW6C2-QMPVW-D7KKK-3GKT6-VCFB2
GOTO key_end

:key_w10_4
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk 2WH4N-8QGBV-H22JP-CT43Q-MDWWJ
GOTO key_end

:key_w10_5
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk NPPR9-FWDCX-D2C8J-H872K-2YT43
GOTO key_end

:key_w10_6
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4
GOTO key_end

:key_w10_7
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk WNMTR-4C88C-JK8YV-HQ7T2-76DF9
GOTO key_end

:key_w10_8
COLOR 2F
START /WAIT slmgr -upk
START /WAIT slmgr -ipk 2F77B-TNFGY-69QQF-B8YKP-D69TJ
GOTO key_end

:key_end
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Office Activation Menu
:act_injectkeyoffice
COLOR 1F
IF EXIST "%programfiles(x86)%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office16\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office16\" > NUL 2>&1
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  INJECT WINDOWS GVLK KEY                            º
ECHO º    [1] Office Professional Plus 2016                º
ECHO º    [2] Office Standard 2016                         º
ECHO º    [3] Office Professional Plus 2013                º
ECHO º    [4] Office Standard 2013                         º
ECHO º    [5] Office Professional Plus 2010                º
ECHO º    [6] Office Home and Student 2010                 º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Activation Menu                      º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu8="Select: "
IF '%menu8%' == '1' GOTO key_o16_1
IF '%menu8%' == '2' GOTO key_o16_2
IF '%menu8%' == '3' GOTO key_o13_1
IF '%menu8%' == '4' GOTO key_o13_2
IF '%menu8%' == '5' GOTO key_o10_1
IF '%menu8%' == '6' GOTO key_o10_2
IF '%menu8%' == '0' GOTO menu_activation
GOTO act_injectkeyoffice

REM -- Office GVLK key injection
:key_o16_1
COLOR 2F
cd %opath%
cscript ospp.vbs /inpkey:XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99
GOTO key_endoffice

:key_o16_2
COLOR 2F
cd %opath%
cscript ospp.vbs /inpkey:JNRGM-WHDWX-FJJG3-K47QV-DRTFM
GOTO key_endoffice

:key_o13_1
COLOR 2F
cd %opath%
cscript ospp.vbs /inpkey:YC7DK-G2NP3-2QQC3-J6H88-GVGXT
GOTO key_endoffice

:key_o13_2
COLOR 2F
cd %opath%
cscript ospp.vbs /inpkey:KBKQT-2NMXY-JJWGP-M62JB-92CD4
GOTO key_endoffice

:key_o10_1
COLOR 2F
cd %opath%
cscript ospp.vbs /inpkey:MKCGC-FBXRX-BMJX6-F3Q8C-2QC6P
GOTO key_endoffice

:key_o10_2
COLOR 2F
cd %opath%
cscript ospp.vbs /inpkey:PXVMG-8F9K6-9GQYX-VJB66-FH626
GOTO key_endoffice

:key_endoffice
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Looks for Office installation folders and activates both Windows and Office
:act_activatenow
COLOR 2F
ECHO.
START /WAIT slmgr /ato
IF EXIST "%programfiles(x86)%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles(x86)%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles(x86)%\Microsoft Office\Office16\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office14\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office14\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office15\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office15\" > NUL 2>&1
IF EXIST "%programfiles%\Microsoft Office\Office16\OSPP.VBS" SET opath="%programfiles%\Microsoft Office\Office16\" > NUL 2>&1
CD %opath% > NUL 2>&1
cscript ospp.vbs /act
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_activation

REM -- Anti-Ransomware Menu
:menu_fakeprocess
COLOR 1F
CLS
ECHO ÉÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ»
ECHO º         WINDOWS 10 TNBT: THE NEXT BIG TWEAK         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  CURRENT REVISION: v%V%                           º
ECHO º  AUTHOR: SEBASTIAN KOEHLING                         º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º  DETECTED WINDOWS: %B%       º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º                                                     º
ECHO º  ANTI-RANSOMWARE PROCESS FAKER                      º
ECHO º    [1] Start Process Faker                          º
ECHO º    [2] Stop Process Faker                           º
ECHO º    [3] Install Process Faker (Autorun)              º
ECHO º    [4] Uninstall Process Faker                      º
ECHO º                                                     º
ECHO º    [5] What is this Process Faker anyway^?           º
ECHO º                                                     º
ECHO ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹
ECHO º    [0] Back to Main Menu                            º
ECHO ÈÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¼
ECHO.
SET /p menu9="Select: "
IF '%menu9%' == '1' GOTO rsw_start
IF '%menu9%' == '2' GOTO rsw_stop
IF '%menu9%' == '3' GOTO rsw_install
IF '%menu9%' == '4' GOTO rsw_uninstall
IF '%menu9%' == '5' GOTO rsw_info
IF '%menu9%' == '0' GOTO menu_start
GOTO menu_fakeprocess

REM -- Creates processfaker.ps1 and runs it manually
:rsw_start
COLOR 2F
ECHO.
IF EXIST "%~dp0processfaker.ps1" DEL "%~dp0processfaker.ps1"
ECHO param([Parameter(Mandatory=$true)][string]$action)							>> "%~dp0processfaker.ps1"
ECHO $fakeProcesses = @("wireshark.exe", "vmacthlp.exe", "VBoxService.exe",				>> "%~dp0processfaker.ps1"
ECHO     "VBoxTray.exe", "procmon.exe", "ollydbg.exe", "vmware-tray.exe",				>> "%~dp0processfaker.ps1"
ECHO     "idag.exe", "ImmunityDebugger.exe", "idaq.exe",						>> "%~dp0processfaker.ps1"
ECHO     "idaq64.exe")											>> "%~dp0processfaker.ps1"
ECHO if ($action -ceq "start") {									>> "%~dp0processfaker.ps1"
ECHO     $tmpdir = [System.Guid]::NewGuid().ToString()							>> "%~dp0processfaker.ps1"
ECHO     $binloc = Join-path $env:temp $tmpdir								>> "%~dp0processfaker.ps1"
ECHO     New-Item -Type Directory -Path $binloc								>> "%~dp0processfaker.ps1"
ECHO     $oldpwd = $pwd											>> "%~dp0processfaker.ps1"
ECHO     Set-Location $binloc										>> "%~dp0processfaker.ps1"
ECHO     foreach ($proc in $fakeProcesses) {								>> "%~dp0processfaker.ps1"
ECHO         Copy-Item c:\windows\system32\ping.exe "$binloc\$proc"					>> "%~dp0processfaker.ps1"
ECHO         Start-Process ".\$proc" -WindowStyle Hidden -ArgumentList "-t -w 600000000 -4 1.1.1.1"	>> "%~dp0processfaker.ps1"
ECHO         write-host "[+] Process $proc spawned"							>> "%~dp0processfaker.ps1"
ECHO     }												>> "%~dp0processfaker.ps1"
ECHO     Set-Location $oldpwd										>> "%~dp0processfaker.ps1"
ECHO }													>> "%~dp0processfaker.ps1"
ECHO elseif ($action -ceq "stop") {									>> "%~dp0processfaker.ps1"
ECHO     foreach ($proc in $fakeProcesses) {								>> "%~dp0processfaker.ps1"
ECHO         Stop-Process -processname "$proc".Split(".")[0]						>> "%~dp0processfaker.ps1"
ECHO         write-host "[+] Killed $proc"								>> "%~dp0processfaker.ps1"
ECHO     }												>> "%~dp0processfaker.ps1"
ECHO }													>> "%~dp0processfaker.ps1"
ECHO else {												>> "%~dp0processfaker.ps1"
ECHO     write-host "Bad usage: need '-action start' or '-action stop' parameter"			>> "%~dp0processfaker.ps1"
ECHO }													>> "%~dp0processfaker.ps1"
PowerShell.exe -ExecutionPolicy Unrestricted -File "%~dp0processfaker.ps1" -action start -ErrorAction SilentlyContinue
DEL "%~dp0processfaker.ps1"
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_fakeprocess

REM -- Creates processfaker.ps1 and stops it manually
:rsw_stop
COLOR 2F
ECHO.
IF EXIST "%~dp0processfaker.ps1" DEL "%~dp0processfaker.ps1"
ECHO param([Parameter(Mandatory=$true)][string]$action)							>> "%~dp0processfaker.ps1"
ECHO $fakeProcesses = @("wireshark.exe", "vmacthlp.exe", "VBoxService.exe",				>> "%~dp0processfaker.ps1"
ECHO     "VBoxTray.exe", "procmon.exe", "ollydbg.exe", "vmware-tray.exe",				>> "%~dp0processfaker.ps1"
ECHO     "idag.exe", "ImmunityDebugger.exe", "idaq.exe",						>> "%~dp0processfaker.ps1"
ECHO     "idaq64.exe")											>> "%~dp0processfaker.ps1"
ECHO if ($action -ceq "start") {									>> "%~dp0processfaker.ps1"
ECHO     $tmpdir = [System.Guid]::NewGuid().ToString()							>> "%~dp0processfaker.ps1"
ECHO     $binloc = Join-path $env:temp $tmpdir								>> "%~dp0processfaker.ps1"
ECHO     New-Item -Type Directory -Path $binloc								>> "%~dp0processfaker.ps1"
ECHO     $oldpwd = $pwd											>> "%~dp0processfaker.ps1"
ECHO     Set-Location $binloc										>> "%~dp0processfaker.ps1"
ECHO     foreach ($proc in $fakeProcesses) {								>> "%~dp0processfaker.ps1"
ECHO         Copy-Item c:\windows\system32\ping.exe "$binloc\$proc"					>> "%~dp0processfaker.ps1"
ECHO         Start-Process ".\$proc" -WindowStyle Hidden -ArgumentList "-t -w 600000000 -4 1.1.1.1"	>> "%~dp0processfaker.ps1"
ECHO         write-host "[+] Process $proc spawned"							>> "%~dp0processfaker.ps1"
ECHO     }												>> "%~dp0processfaker.ps1"
ECHO     Set-Location $oldpwd										>> "%~dp0processfaker.ps1"
ECHO }													>> "%~dp0processfaker.ps1"
ECHO elseif ($action -ceq "stop") {									>> "%~dp0processfaker.ps1"
ECHO     foreach ($proc in $fakeProcesses) {								>> "%~dp0processfaker.ps1"
ECHO         Stop-Process -processname "$proc".Split(".")[0]						>> "%~dp0processfaker.ps1"
ECHO         write-host "[+] Killed $proc"								>> "%~dp0processfaker.ps1"
ECHO     }												>> "%~dp0processfaker.ps1"
ECHO }													>> "%~dp0processfaker.ps1"
ECHO else {												>> "%~dp0processfaker.ps1"
ECHO     write-host "Bad usage: need '-action start' or '-action stop' parameter"			>> "%~dp0processfaker.ps1"
ECHO }													>> "%~dp0processfaker.ps1"
PowerShell.exe -ExecutionPolicy Unrestricted -File "%~dp0processfaker.ps1" -action stop -ErrorAction SilentlyContinue
DEL "%~dp0processfaker.ps1"
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_fakeprocess

REM -- Creates processfaker.ps1, copys it to C:\Windows and creates a script in autorun folder to automatically run the script on boot
:rsw_install
COLOR 2F
ECHO.
IF EXIST "%SYSTEMROOT%\processfaker.ps1" DEL "%SYSTEMROOT%\processfaker.ps1"
ECHO param([Parameter(Mandatory=$true)][string]$action)							>> "%SYSTEMROOT%\processfaker.ps1"
ECHO $fakeProcesses = @("wireshark.exe", "vmacthlp.exe", "VBoxService.exe",				>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     "VBoxTray.exe", "procmon.exe", "ollydbg.exe", "vmware-tray.exe",				>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     "idag.exe", "ImmunityDebugger.exe", "idaq.exe",						>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     "idaq64.exe")											>> "%SYSTEMROOT%\processfaker.ps1"
ECHO if ($action -ceq "start") {									>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     $tmpdir = [System.Guid]::NewGuid().ToString()							>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     $binloc = Join-path $env:temp $tmpdir								>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     New-Item -Type Directory -Path $binloc								>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     $oldpwd = $pwd											>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     Set-Location $binloc										>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     foreach ($proc in $fakeProcesses) {								>> "%SYSTEMROOT%\processfaker.ps1"
ECHO         Copy-Item c:\windows\system32\ping.exe "$binloc\$proc"					>> "%SYSTEMROOT%\processfaker.ps1"
ECHO         Start-Process ".\$proc" -WindowStyle Hidden -ArgumentList "-t -w 600000000 -4 1.1.1.1"	>> "%SYSTEMROOT%\processfaker.ps1"
ECHO         write-host "[+] Process $proc spawned"							>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     }												>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     Set-Location $oldpwd										>> "%SYSTEMROOT%\processfaker.ps1"
ECHO }													>> "%SYSTEMROOT%\processfaker.ps1"
ECHO elseif ($action -ceq "stop") {									>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     foreach ($proc in $fakeProcesses) {								>> "%SYSTEMROOT%\processfaker.ps1"
ECHO         Stop-Process -processname "$proc".Split(".")[0]						>> "%SYSTEMROOT%\processfaker.ps1"
ECHO         write-host "[+] Killed $proc"								>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     }												>> "%SYSTEMROOT%\processfaker.ps1"
ECHO }													>> "%SYSTEMROOT%\processfaker.ps1"
ECHO else {												>> "%SYSTEMROOT%\processfaker.ps1"
ECHO     write-host "Bad usage: need '-action start' or '-action stop' parameter"			>> "%SYSTEMROOT%\processfaker.ps1"
ECHO }													>> "%SYSTEMROOT%\processfaker.ps1"
IF EXIST "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat" DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat"
ECHO ^@ECHO OFF																	> "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat"
ECHO PowerShell.exe -ExecutionPolicy Unrestricted -File "%SYSTEMROOT%\processfaker.ps1" -action start -ErrorAction SilentlyContinue		>> "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat"
ECHO EXIT																	>> "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat"
PowerShell.exe -ExecutionPolicy Unrestricted -File "%SYSTEMROOT%\processfaker.ps1" -action stop -ErrorAction SilentlyContinue > NUL 2>&1
PowerShell.exe -ExecutionPolicy Unrestricted -File "%SYSTEMROOT%\processfaker.ps1" -action start -ErrorAction SilentlyContinue
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_fakeprocess

REM -- Simply stops the process faker and deletes the files created by the installer script
:rsw_uninstall
COLOR 2F
ECHO.
PowerShell.exe -ExecutionPolicy Unrestricted -File "%SYSTEMROOT%\processfaker.ps1" -action stop -ErrorAction SilentlyContinue
IF EXIST ""%SYSTEMROOT%\processfaker.ps1"" DEL ""%SYSTEMROOT%\processfaker.ps1"" > NUL 2>&1
IF EXIST "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat" DEL "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Process_Faker.bat" > NUL 2>&1
ECHO.
ECHO Done...
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_fakeprocess

REM -- Just outputs some information text about process faker
:rsw_info
COLOR 2F
ECHO.
ECHO "Simulate fake processes of analysis sandbox/VM that some malware will try to evade.
ECHO This script will just spawn ping.exe with different names (wireshark.exe, vboxtray.exe, etc.)"
ECHO Press any key to got back to the menu.
PAUSE > NUL
GOTO menu_fakeprocess

@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

:: ---------------------------------------------------  !!! Incorrect Data Found !!!  -------------------------------------------------------------
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control --> “WaitToKillServiceTimeout”=”3000”
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem --> “NtfsMftZoneReservation”=dword: 00000002
:: HKEY_CURRENT_USER\Control Panel\Desktop --> “MenuShowDelay”=”0”
:: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced --> “DisableThumbnailCache”=dword:00000000
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch --> “Start”=dword: 00000004
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cisvc --> “Start”=dword: 00000004
:: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management --> “ClearPageFileAtShutDown”=1
:: HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6} --> System.IsPinnedToNameSpaceTree"=0
:: ------------------------------------------------------------------------------------------------------------------------------------------------

REM ; Created by: The Geek Freaks - CC Alexander Zuber
REM ; http://www.thegeekfreaks.de
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /f
Reg.exe add "HKCU\Control Panel\Desktop" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cisvc" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCR\Directory\shell\runas" /f
Reg.exe add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Directory\Background\shell\runas" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\Background\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Drive\shell\runas" /f
Reg.exe add "HKCR\Drive\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Drive\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe add "HKCR\*\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f
Exit

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof


NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]"
set "line04="AllowCortana"=dword:00000000"
set "line05="DisableWebSearch"=dword:00000001"
set "line06="AllowSearchToUseLocation"=dword:00000000"
set "line07="ConnectedSearchUseWeb"=dword:00000000"
set "line08="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo/

) > "Win 10 Cortana vollstaendig deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 Cortana vollstaendig deaktivieren.reg"
del /F /Q "%~dp0Win 10 Cortana vollstaendig deaktivieren.reg"

powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -l

Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /f
Reg.exe add "HKCU\Control Panel\Desktop" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cisvc" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCR\Directory\shell\runas" /f
Reg.exe add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Directory\Background\shell\runas" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\Background\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Drive\shell\runas" /f
Reg.exe add "HKCR\Drive\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Drive\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe add "HKCR\*\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive]"
set "line04="DisableLibrariesDefaultSaveToOneDrive"=dword:00000001"
set "line05="DisableFileSync"=dword:00000001"
set "line06="DisableMeteredNetworkFileSync"=dword:00000001"
set "line07="
set "line08=[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive]"
set "line09="DisableLibrariesDefaultSaveToOneDrive"=dword:00000001"
set "line10="DisableFileSync"=dword:00000001"
set "line11="DisableMeteredNetworkFileSync"=dword:00000001"
set "line12="
set "line13=[HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line14="Attributes"=dword:f090004d"
set "line15="
set "line16=[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line17="Attributes"=dword:f090004d"
set "line18="
set "line19=[HKEY_CURRENT_USER\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line20="Attributes"=dword:f090004d"
set "line21="
set "line22=[HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line23="Attributes"=dword:f090004d"
set "line24="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo/
  echo !line13!
  echo !line14!
  echo/
  echo !line16!
  echo !line17!
  echo/
  echo !line19!
  echo !line20!
  echo/
  echo !line22!
  echo !line23!
  echo/

) > "Win 10 One Drive deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 One Drive deaktivieren.reg"
del /F /Q "%~dp0Win 10 One Drive deaktivieren.reg"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0\z3.ps1""' -Verb RunAs}"

net user administrator /active:yes 

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]"
set "line04="FilterAdministratorToken"=dword:00000001"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
REGEDIT.EXE /S "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
del /F /Q "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]"
set "line04="ShowRecent"=dword:00000000"
set "line05="ShowFrequent"=dword:00000000"
set "line06="EnableAutoTray"=dword:00000000"
set "line07="
set "line08=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]"
set "line09="FolderContentsInfoTip"=dword:00000000"
set "line10="HideFileExt"=dword:00000000"
set "line11="ShowSuperHidden"=dword:00000001"
set "line12="AlwaysShowMenus"=dword:00000001"
set "line13="AutoCheckSelect"=dword:00000001"
set "line14="Hidden"=dword:00000001"
set "line15="Start_TrackDocs"=dword:00000000"
set "line16="DisablePreviewDesktop"=dword:00000000"
set "line17="TaskbarAnimations"=dword:00000000"
set "line18="ShowTaskViewButton"=dword:00000000"
set "line19="TaskbarGlomLevel"=dword:00000001"
set "line20="
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications]"
set "line22="ToastEnabled"=dword:00000000"
set "line23="
set "line24=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]"
set "line25="SoftLandingEnabled"=dword:00000000"
set "line26="SystemPaneSuggestionsEnabled"=dword:00000000"
set "line27="
set "line28=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers]"
set "line29="DisableAutoplay"=dword:00000001"
set "line30="
set "line31=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]"
set "line32="ColorPrevalence"=dword:00000001"
set "line33="
set "line34=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\DWM]"
set "line35="ColorPrevalence"=dword:00000001"
set "line36="
set "line37=[HKEY_USERS\%myvar%\Control Panel\International\User Profile]"
set "line38="HttpAcceptLanguageOptOut"=dword:00000001"
set "line39="
set "line40=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass]"
set "line41="UserAuthPolicy"=dword:00000000"
set "line42="
set "line43=[HKEY_USERS\%myvar%\Control Panel\Desktop\WindowMetrics]"
set "line44="MinAnimate"=dword:00000000"
set "line45="
set "line46=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]"
set "line47="SearchboxTaskbarMode"=dword:00000000"
set "line48="
set "line49=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel]"
set "line50="AllItemsIconView"=dword:00000000"
set "line51="StartupPage"=dword:00000001"
set "line52="
set "line53=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config]"
set "line54="DODownloadMode"=dword:00000000"
set "line55="
set "line56=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows]"
set "line57="CEIPEnable"=dword:00000000"
set "line58="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo !line26!
  echo/
  echo !line28!
  echo !line29!
  echo/
  echo !line31!
  echo !line32!
  echo/
  echo !line34!
  echo !line35!
  echo/
  echo !line37!
  echo !line38!
  echo/
  echo !line40!
  echo !line41!
  echo/
  echo !line43!
  echo !line44!
  echo/
  echo !line46!
  echo !line47!
  echo/
  echo !line49!
  echo !line50!
  echo !line51!
  echo/
  echo !line53!
  echo !line54!
  echo/
  echo !line56!
  echo !line57!
  echo/

) > "Win 10 Explorer Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Explorer Einstellungen.reg"
del /F /Q "%~dp0Win 10 Explorer Einstellungen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate]"
set "line04="AutoDownload"=dword:00000002"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Auto App Updates deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 Auto App Updates deaktivieren.reg"
del /F /Q "%~dp0Win 10 Auto App Updates deaktivieren.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start

taskkill /f /IM "SearchUI.exe"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=<?xml version="1.0" encoding="UTF-16"?>"
set "line02=<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"
set "line03=  <RegistrationInfo>"
set "line04=    <URI>\Microsoft\Windows\UpdateOrchestrator\Reboot</URI>"
set "line05=  </RegistrationInfo>"
set "line06=  <Triggers>"
set "line07=    <TimeTrigger>"
set "line08=      <StartBoundary>2016-09-14T00:20:38+02:00</StartBoundary>"
set "line09=      <Enabled>true</Enabled>"
set "line10=    </TimeTrigger>"
set "line11=  </Triggers>"
set "line12=  <Principals>"
set "line13=    <Principal id="Author">"
set "line14=      <UserId>S-1-5-18</UserId>"
set "line15=      <RunLevel>LeastPrivilege</RunLevel>"
set "line16=    </Principal>"
set "line17=  </Principals>"
set "line18=  <Settings>"
set "line19=    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
set "line20=    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>"
set "line21=    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
set "line22=    <AllowHardTerminate>true</AllowHardTerminate>"
set "line23=    <StartWhenAvailable>true</StartWhenAvailable>"
set "line24=    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
set "line25=    <IdleSettings>"
set "line26=      <Duration>PT10M</Duration>"
set "line27=      <WaitTimeout>PT1H</WaitTimeout>"
set "line28=      <StopOnIdleEnd>true</StopOnIdleEnd>"
set "line29=      <RestartOnIdle>false</RestartOnIdle>"
set "line30=    </IdleSettings>"
set "line31=    <AllowStartOnDemand>true</AllowStartOnDemand>"
set "line32=    <Enabled>false</Enabled>"
set "line33=    <Hidden>false</Hidden>"
set "line34=    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
set "line35=    <WakeToRun>true</WakeToRun>"
set "line36=    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>"
set "line37=    <Priority>7</Priority>"
set "line38=    <RestartOnFailure>"
set "line39=      <Interval>PT10M</Interval>"
set "line40=      <Count>3</Count>"
set "line41=    </RestartOnFailure>"
set "line42=  </Settings>"
set "line43=  <Actions Context="Author">"
set "line44=    <Exec>"
set "line45=      <Command>%systemroot%\system32\MusNotification.exe</Command>"
set "line46=      <Arguments>RebootDialog</Arguments>"
set "line47=    </Exec>"
set "line48=  </Actions>"
set "line49=</Task>"

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo !line02!
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo !line20!
  echo !line21!
  echo !line22!
  echo !line23!
  echo !line24!
  echo !line25!
  echo !line26!
  echo !line27!
  echo !line28!
  echo !line29!
  echo !line30!
  echo !line31!
  echo !line32!
  echo !line33!
  echo !line34!
  echo !line35!
  echo !line36!
  echo !line37!
  echo !line38!
  echo !line39!
  echo !line40!
  echo !line41!
  echo !line42!
  echo !line43!
  echo !line44!
  echo !line45!
  echo !line46!
  echo !line47!
  echo !line48!
  echo !line49!

) > "Win 10 Reboot deaktivieren.xml"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:System;p:read"
schtasks /delete /F /tn "Microsoft\Windows\UpdateOrchestrator\Reboot"
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\Reboot" /xml "%~dp0Win 10 Reboot deaktivieren.xml"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:System;p:read"
del /F /Q "%~dp0Win 10 Reboot deaktivieren.xml"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=<?xml version="1.0" encoding="UTF-16"?>"
set "line02=<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"
set "line03=  <RegistrationInfo>"
set "line04=    <Date>2016-08-06T12:40:47.6863074</Date>"
set "line05=    <Author>System</Author>"
set "line06=    <URI>\Disable Windows Lock Screen</URI>"
set "line07=  </RegistrationInfo>"
set "line08=  <Triggers>"
set "line09=    <LogonTrigger>"
set "line10=      <Enabled>true</Enabled>"
set "line11=    </LogonTrigger>"
set "line12=    <SessionStateChangeTrigger>"
set "line13=      <Enabled>true</Enabled>"
set "line14=      <StateChange>SessionUnlock</StateChange>"
set "line15=    </SessionStateChangeTrigger>"
set "line16=  </Triggers>"
set "line17=  <Principals>"
set "line18=    <Principal id="Author">"
set "line19=      <UserId>%myvar%</UserId>"
set "line20=      <LogonType>InteractiveToken</LogonType>"
set "line21=      <RunLevel>HighestAvailable</RunLevel>"
set "line22=    </Principal>"
set "line23=  </Principals>"
set "line24=  <Settings>"
set "line25=    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
set "line26=    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
set "line27=    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>"
set "line28=    <AllowHardTerminate>true</AllowHardTerminate>"
set "line29=    <StartWhenAvailable>false</StartWhenAvailable>"
set "line30=    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
set "line31=    <IdleSettings>"
set "line32=      <StopOnIdleEnd>true</StopOnIdleEnd>"
set "line33=      <RestartOnIdle>false</RestartOnIdle>"
set "line34=    </IdleSettings>"
set "line35=    <AllowStartOnDemand>true</AllowStartOnDemand>"
set "line36=    <Enabled>true</Enabled>"
set "line37=    <Hidden>false</Hidden>"
set "line38=    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
set "line39=    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>"
set "line40=    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>"
set "line41=    <WakeToRun>false</WakeToRun>"
set "line42=    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>"
set "line43=    <Priority>7</Priority>"
set "line44=  </Settings>"
set "line45=  <Actions Context="Author">"
set "line46=    <Exec>"
set "line47=      <Command>reg</Command>"
set "line48=      <Arguments>add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f</Arguments>"
set "line49=    </Exec>"
set "line50=  </Actions>"
set "line51=</Task>"

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo !line02!
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo !line20!
  echo !line21!
  echo !line22!
  echo !line23!
  echo !line24!
  echo !line25!
  echo !line26!
  echo !line27!
  echo !line28!
  echo !line29!
  echo !line30!
  echo !line31!
  echo !line32!
  echo !line33!
  echo !line34!
  echo !line35!
  echo !line36!
  echo !line37!
  echo !line38!
  echo !line39!
  echo !line40!
  echo !line41!
  echo !line42!
  echo !line43!
  echo !line44!
  echo !line45!
  echo !line46!
  echo !line47!
  echo !line48!
  echo !line49!
  echo !line50!
  echo !line51!

) > "Win 10 Lockscreen deaktivieren.xml"
schtasks /create /tn "Disable Windows Lock Screen" /xml "%~dp0Win 10 Lockscreen deaktivieren.xml"
del /F /Q "%~dp0Win 10 Lockscreen deaktivieren.xml"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\ /v Start /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility\ /v DiagnosticErrorText /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticErrorText /t REG_SZ /d "" /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticLinkText /t REG_SZ /d "" /f
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
sc stop MapsBroker
sc config MapsBroker start= disabled
sc stop DoSvc
sc config DoSvc start= disabled
sc stop WSearch
sc config WSearch start= disabled
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
@ECHO off
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)
set myvar2=""
:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02= "
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line04="Cookies"=dword:00000001"
set "line05= "
set "line06=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line07="Cookies"=dword:00000001"
set "line08= "
set "line09=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line10="EnableCortana"=dword:00000000"
set "line11= "
set "line12=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line13="EnableCortana"=dword:00000000"
set "line14= "
set "line15=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons]"
set "line16="FlashPlayerEnabled"=dword:00000000"
set "line17= "
set "line18=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons]"
set "line19="FlashPlayerEnabled"=dword:00000000"
set "line20= "
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes]"
set "line22="ShowSearchSuggestionsGlobal"=dword:00000000"
set "line23= "
set "line24=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes]"
set "line25="ShowSearchSuggestionsGlobal"=dword:00000000"
set "line26= "
set "line27=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ContinuousBrowsing]"
set "line28="Enabled"=dword:00000001"
set "line29= "
set "line30=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ContinuousBrowsing]"
set "line31="Enabled"=dword:00000001"
set "line32= "
set "line33=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line34="NewTabPageDisplayOption"=dword:00000002"
set "line35= "
set "line36=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line37="NewTabPageDisplayOption"=dword:00000002"
set "line38= "
set "line39=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line40="FormSuggest Passwords"="no""
set "line41= "
set "line42=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line43="FormSuggest Passwords"="no""
set "line44= "
set "line45=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Extensions]"
set "line46="EnableExtensionDevelopment"=dword:00000001"
set "line47= "
set "line48=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Extensions]"
set "line49="EnableExtensionDevelopment"=dword:00000001"
set "line50= "

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/
  echo !line06!
  echo !line07!
  echo/
  echo !line09!
  echo !line10!
  echo/
  echo !line12!
  echo !line13!
  echo/
  echo !line15!
  echo !line16!
  echo/
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo/
  echo !line27!
  echo !line28!
  echo/
  echo !line30!
  echo !line31!
  echo/
  echo !line33!
  echo !line34!
  echo/
  echo !line36!
  echo !line37!
  echo/
  echo !line39!
  echo !line40!
  echo/
  echo !line42!
  echo !line43!
  echo/
  echo !line45!
  echo !line46!
  echo/
  echo !line48!
  echo !line49!
  echo/

) > "Win 10 Edge sichere Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Edge sichere Einstellungen.reg"
del /F /Q "%~dp0Win 10 Edge sichere Einstellungen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]"
set "line04="IconVerticalSpacing"="-1125""
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Desktopicon Abstand vertikal anpassen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
del /F /Q "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
xcopy /Y "%~dp0LayoutModification.xml" "C:\"
cd %~dp0
LGPO.exe /u "%~dp0\registry.pol"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)
set myvar2=""
:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02= "
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Policies\Microsoft\Windows\Explorer]"
set "line04="LockedStartLayout"=dword:00000000"
set "line05= "

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 LayoutModification.reg"
REGEDIT.EXE /S "%~dp0Win 10 LayoutModification.reg"
del /F /Q "%~dp0Win 10 LayoutModification.reg"
del /F /Q "C:\LayoutModification.xml"



:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search]"
set "line04="AllowCortana"=dword:00000000"
set "line05="DisableWebSearch"=dword:00000001"
set "line06="AllowSearchToUseLocation"=dword:00000000"
set "line07="ConnectedSearchUseWeb"=dword:00000000"
set "line08="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo/

) > "Win 10 Cortana vollstaendig deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 Cortana vollstaendig deaktivieren.reg"
del /F /Q "%~dp0Win 10 Cortana vollstaendig deaktivieren.reg"

powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -l

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Onedrive]"
set "line04="DisableLibrariesDefaultSaveToOneDrive"=dword:00000001"
set "line05="DisableFileSync"=dword:00000001"
set "line06="DisableMeteredNetworkFileSync"=dword:00000001"
set "line07="
set "line08=[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Onedrive]"
set "line09="DisableLibrariesDefaultSaveToOneDrive"=dword:00000001"
set "line10="DisableFileSync"=dword:00000001"
set "line11="DisableMeteredNetworkFileSync"=dword:00000001"
set "line12="
set "line13=[HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line14="Attributes"=dword:f090004d"
set "line15="
set "line16=[HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line17="Attributes"=dword:f090004d"
set "line18="
set "line19=[HKEY_CURRENT_USER\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line20="Attributes"=dword:f090004d"
set "line21="
set "line22=[HKEY_CURRENT_USER\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder]"
set "line23="Attributes"=dword:f090004d"
set "line24="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo/
  echo !line13!
  echo !line14!
  echo/
  echo !line16!
  echo !line17!
  echo/
  echo !line19!
  echo !line20!
  echo/
  echo !line22!
  echo !line23!
  echo/

) > "Win 10 One Drive deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 One Drive deaktivieren.reg"
del /F /Q "%~dp0Win 10 One Drive deaktivieren.reg"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0\z3.ps1""' -Verb RunAs}"

net user administrator /active:yes 

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]"
set "line04="FilterAdministratorToken"=dword:00000001"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
REGEDIT.EXE /S "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
del /F /Q "%~dp0Win 8u10 Administratorkonto den Apps Zugriff gewaehren.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]"
set "line04="ShowRecent"=dword:00000000"
set "line05="ShowFrequent"=dword:00000000"
set "line06="EnableAutoTray"=dword:00000000"
set "line07="
set "line08=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]"
set "line09="FolderContentsInfoTip"=dword:00000000"
set "line10="HideFileExt"=dword:00000000"
set "line11="ShowSuperHidden"=dword:00000001"
set "line12="AlwaysShowMenus"=dword:00000001"
set "line13="AutoCheckSelect"=dword:00000001"
set "line14="Hidden"=dword:00000001"
set "line15="Start_TrackDocs"=dword:00000000"
set "line16="DisablePreviewDesktop"=dword:00000000"
set "line17="TaskbarAnimations"=dword:00000000"
set "line18="ShowTaskViewButton"=dword:00000000"
set "line19="TaskbarGlomLevel"=dword:00000001"
set "line20="
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications]"
set "line22="ToastEnabled"=dword:00000000"
set "line23="
set "line24=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]"
set "line25="SoftLandingEnabled"=dword:00000000"
set "line26="SystemPaneSuggestionsEnabled"=dword:00000000"
set "line27="
set "line28=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers]"
set "line29="DisableAutoplay"=dword:00000001"
set "line30="
set "line31=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]"
set "line32="ColorPrevalence"=dword:00000001"
set "line33="
set "line34=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\DWM]"
set "line35="ColorPrevalence"=dword:00000001"
set "line36="
set "line37=[HKEY_USERS\%myvar%\Control Panel\International\User Profile]"
set "line38="HttpAcceptLanguageOptOut"=dword:00000001"
set "line39="
set "line40=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass]"
set "line41="UserAuthPolicy"=dword:00000000"
set "line42="
set "line43=[HKEY_USERS\%myvar%\Control Panel\Desktop\WindowMetrics]"
set "line44="MinAnimate"=dword:00000000"
set "line45="
set "line46=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]"
set "line47="SearchboxTaskbarMode"=dword:00000000"
set "line48="
set "line49=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel]"
set "line50="AllItemsIconView"=dword:00000000"
set "line51="StartupPage"=dword:00000001"
set "line52="
set "line53=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config]"
set "line54="DODownloadMode"=dword:00000000"
set "line55="
set "line56=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows]"
set "line57="CEIPEnable"=dword:00000000"
set "line58="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo !line26!
  echo/
  echo !line28!
  echo !line29!
  echo/
  echo !line31!
  echo !line32!
  echo/
  echo !line34!
  echo !line35!
  echo/
  echo !line37!
  echo !line38!
  echo/
  echo !line40!
  echo !line41!
  echo/
  echo !line43!
  echo !line44!
  echo/
  echo !line46!
  echo !line47!
  echo/
  echo !line49!
  echo !line50!
  echo !line51!
  echo/
  echo !line53!
  echo !line54!
  echo/
  echo !line56!
  echo !line57!
  echo/

) > "Win 10 Explorer Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Explorer Einstellungen.reg"
del /F /Q "%~dp0Win 10 Explorer Einstellungen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate]"
set "line04="AutoDownload"=dword:00000002"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Auto App Updates deaktivieren.reg"
REGEDIT.EXE /S "%~dp0Win 10 Auto App Updates deaktivieren.reg"
del /F /Q "%~dp0Win 10 Auto App Updates deaktivieren.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start

taskkill /f /IM "SearchUI.exe"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=<?xml version="1.0" encoding="UTF-16"?>"
set "line02=<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"
set "line03=  <RegistrationInfo>"
set "line04=    <URI>\Microsoft\Windows\UpdateOrchestrator\Reboot</URI>"
set "line05=  </RegistrationInfo>"
set "line06=  <Triggers>"
set "line07=    <TimeTrigger>"
set "line08=      <StartBoundary>2016-09-14T00:20:38+02:00</StartBoundary>"
set "line09=      <Enabled>true</Enabled>"
set "line10=    </TimeTrigger>"
set "line11=  </Triggers>"
set "line12=  <Principals>"
set "line13=    <Principal id="Author">"
set "line14=      <UserId>S-1-5-18</UserId>"
set "line15=      <RunLevel>LeastPrivilege</RunLevel>"
set "line16=    </Principal>"
set "line17=  </Principals>"
set "line18=  <Settings>"
set "line19=    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
set "line20=    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>"
set "line21=    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
set "line22=    <AllowHardTerminate>true</AllowHardTerminate>"
set "line23=    <StartWhenAvailable>true</StartWhenAvailable>"
set "line24=    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
set "line25=    <IdleSettings>"
set "line26=      <Duration>PT10M</Duration>"
set "line27=      <WaitTimeout>PT1H</WaitTimeout>"
set "line28=      <StopOnIdleEnd>true</StopOnIdleEnd>"
set "line29=      <RestartOnIdle>false</RestartOnIdle>"
set "line30=    </IdleSettings>"
set "line31=    <AllowStartOnDemand>true</AllowStartOnDemand>"
set "line32=    <Enabled>false</Enabled>"
set "line33=    <Hidden>false</Hidden>"
set "line34=    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
set "line35=    <WakeToRun>true</WakeToRun>"
set "line36=    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>"
set "line37=    <Priority>7</Priority>"
set "line38=    <RestartOnFailure>"
set "line39=      <Interval>PT10M</Interval>"
set "line40=      <Count>3</Count>"
set "line41=    </RestartOnFailure>"
set "line42=  </Settings>"
set "line43=  <Actions Context="Author">"
set "line44=    <Exec>"
set "line45=      <Command>%systemroot%\system32\MusNotification.exe</Command>"
set "line46=      <Arguments>RebootDialog</Arguments>"
set "line47=    </Exec>"
set "line48=  </Actions>"
set "line49=</Task>"

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo !line02!
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo !line20!
  echo !line21!
  echo !line22!
  echo !line23!
  echo !line24!
  echo !line25!
  echo !line26!
  echo !line27!
  echo !line28!
  echo !line29!
  echo !line30!
  echo !line31!
  echo !line32!
  echo !line33!
  echo !line34!
  echo !line35!
  echo !line36!
  echo !line37!
  echo !line38!
  echo !line39!
  echo !line40!
  echo !line41!
  echo !line42!
  echo !line43!
  echo !line44!
  echo !line45!
  echo !line46!
  echo !line47!
  echo !line48!
  echo !line49!

) > "Win 10 Reboot deaktivieren.xml"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:System;p:read"
schtasks /delete /F /tn "Microsoft\Windows\UpdateOrchestrator\Reboot"
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\Reboot" /xml "%~dp0Win 10 Reboot deaktivieren.xml"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Reboot -ot file -actn ace -ace "n:System;p:read"
del /F /Q "%~dp0Win 10 Reboot deaktivieren.xml"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=<?xml version="1.0" encoding="UTF-16"?>"
set "line02=<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"
set "line03=  <RegistrationInfo>"
set "line04=    <Date>2016-08-06T12:40:47.6863074</Date>"
set "line05=    <Author>System</Author>"
set "line06=    <URI>\Disable Windows Lock Screen</URI>"
set "line07=  </RegistrationInfo>"
set "line08=  <Triggers>"
set "line09=    <LogonTrigger>"
set "line10=      <Enabled>true</Enabled>"
set "line11=    </LogonTrigger>"
set "line12=    <SessionStateChangeTrigger>"
set "line13=      <Enabled>true</Enabled>"
set "line14=      <StateChange>SessionUnlock</StateChange>"
set "line15=    </SessionStateChangeTrigger>"
set "line16=  </Triggers>"
set "line17=  <Principals>"
set "line18=    <Principal id="Author">"
set "line19=      <UserId>%myvar%</UserId>"
set "line20=      <LogonType>InteractiveToken</LogonType>"
set "line21=      <RunLevel>HighestAvailable</RunLevel>"
set "line22=    </Principal>"
set "line23=  </Principals>"
set "line24=  <Settings>"
set "line25=    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
set "line26=    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
set "line27=    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>"
set "line28=    <AllowHardTerminate>true</AllowHardTerminate>"
set "line29=    <StartWhenAvailable>false</StartWhenAvailable>"
set "line30=    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
set "line31=    <IdleSettings>"
set "line32=      <StopOnIdleEnd>true</StopOnIdleEnd>"
set "line33=      <RestartOnIdle>false</RestartOnIdle>"
set "line34=    </IdleSettings>"
set "line35=    <AllowStartOnDemand>true</AllowStartOnDemand>"
set "line36=    <Enabled>true</Enabled>"
set "line37=    <Hidden>false</Hidden>"
set "line38=    <RunOnlyIfIdle>false</RunOnlyIfIdle>"
set "line39=    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>"
set "line40=    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>"
set "line41=    <WakeToRun>false</WakeToRun>"
set "line42=    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>"
set "line43=    <Priority>7</Priority>"
set "line44=  </Settings>"
set "line45=  <Actions Context="Author">"
set "line46=    <Exec>"
set "line47=      <Command>reg</Command>"
set "line48=      <Arguments>add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f</Arguments>"
set "line49=    </Exec>"
set "line50=  </Actions>"
set "line51=</Task>"

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo !line02!
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo !line07!
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo !line20!
  echo !line21!
  echo !line22!
  echo !line23!
  echo !line24!
  echo !line25!
  echo !line26!
  echo !line27!
  echo !line28!
  echo !line29!
  echo !line30!
  echo !line31!
  echo !line32!
  echo !line33!
  echo !line34!
  echo !line35!
  echo !line36!
  echo !line37!
  echo !line38!
  echo !line39!
  echo !line40!
  echo !line41!
  echo !line42!
  echo !line43!
  echo !line44!
  echo !line45!
  echo !line46!
  echo !line47!
  echo !line48!
  echo !line49!
  echo !line50!
  echo !line51!

) > "Win 10 Lockscreen deaktivieren.xml"
schtasks /create /tn "Disable Windows Lock Screen" /xml "%~dp0Win 10 Lockscreen deaktivieren.xml"
del /F /Q "%~dp0Win 10 Lockscreen deaktivieren.xml"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop dmwappushservice
sc config dmwappushservice start= disabled
reg add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\ /v Start /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\ /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility\ /v DiagnosticErrorText /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticErrorText /t REG_SZ /d "" /f
reg add HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\ /v DiagnosticLinkText /t REG_SZ /d "" /f
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
sc stop MapsBroker
sc config MapsBroker start= disabled
sc stop DoSvc
sc config DoSvc start= disabled
sc stop WSearch
sc config WSearch start= disabled
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
@ECHO off
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)
set myvar2=""
:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02= "
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line04="Cookies"=dword:00000001"
set "line05= "
set "line06=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line07="Cookies"=dword:00000001"
set "line08= "
set "line09=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line10="EnableCortana"=dword:00000000"
set "line11= "
set "line12=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line13="EnableCortana"=dword:00000000"
set "line14= "
set "line15=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons]"
set "line16="FlashPlayerEnabled"=dword:00000000"
set "line17= "
set "line18=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons]"
set "line19="FlashPlayerEnabled"=dword:00000000"
set "line20= "
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes]"
set "line22="ShowSearchSuggestionsGlobal"=dword:00000000"
set "line23= "
set "line24=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes]"
set "line25="ShowSearchSuggestionsGlobal"=dword:00000000"
set "line26= "
set "line27=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ContinuousBrowsing]"
set "line28="Enabled"=dword:00000001"
set "line29= "
set "line30=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ContinuousBrowsing]"
set "line31="Enabled"=dword:00000001"
set "line32= "
set "line33=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line34="NewTabPageDisplayOption"=dword:00000002"
set "line35= "
set "line36=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI]"
set "line37="NewTabPageDisplayOption"=dword:00000002"
set "line38= "
set "line39=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line40="FormSuggest Passwords"="no""
set "line41= "
set "line42=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main]"
set "line43="FormSuggest Passwords"="no""
set "line44= "
set "line45=[HKEY_USERS\%myvar%\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Extensions]"
set "line46="EnableExtensionDevelopment"=dword:00000001"
set "line47= "
set "line48=[HKEY_USERS\%myvar%_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Extensions]"
set "line49="EnableExtensionDevelopment"=dword:00000001"
set "line50= "

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/
  echo !line06!
  echo !line07!
  echo/
  echo !line09!
  echo !line10!
  echo/
  echo !line12!
  echo !line13!
  echo/
  echo !line15!
  echo !line16!
  echo/
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo/
  echo !line27!
  echo !line28!
  echo/
  echo !line30!
  echo !line31!
  echo/
  echo !line33!
  echo !line34!
  echo/
  echo !line36!
  echo !line37!
  echo/
  echo !line39!
  echo !line40!
  echo/
  echo !line42!
  echo !line43!
  echo/
  echo !line45!
  echo !line46!
  echo/
  echo !line48!
  echo !line49!
  echo/

) > "Win 10 Edge sichere Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Edge sichere Einstellungen.reg"
del /F /Q "%~dp0Win 10 Edge sichere Einstellungen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]"
set "line04="IconVerticalSpacing"="-1125""
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Desktopicon Abstand vertikal anpassen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
del /F /Q "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
xcopy /Y "%~dp0LayoutModification.xml" "C:\"
cd %~dp0
LGPO.exe /u "%~dp0\registry.pol"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)
set myvar2=""
:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02= "
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Policies\Microsoft\Windows\Explorer]"
set "line04="LockedStartLayout"=dword:00000000"
set "line05= "

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 LayoutModification.reg"
REGEDIT.EXE /S "%~dp0Win 10 LayoutModification.reg"
del /F /Q "%~dp0Win 10 LayoutModification.reg"
del /F /Q "C:\LayoutModification.xml"



:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )



:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*


:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]"
set "line04="ShowRecent"=dword:00000000"
set "line05="ShowFrequent"=dword:00000000"
set "line06="EnableAutoTray"=dword:00000000"
set "line07="
set "line08=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced]"
set "line09="FolderContentsInfoTip"=dword:00000000"
set "line10="HideFileExt"=dword:00000000"
set "line11="ShowSuperHidden"=dword:00000001"
set "line12="AlwaysShowMenus"=dword:00000001"
set "line13="AutoCheckSelect"=dword:00000001"
set "line14="Hidden"=dword:00000001"
set "line15="Start_TrackDocs"=dword:00000000"
set "line16="DisablePreviewDesktop"=dword:00000000"
set "line17="TaskbarAnimations"=dword:00000000"
set "line18="ShowTaskViewButton"=dword:00000000"
set "line19="TaskbarGlomLevel"=dword:00000001"
set "line20="
set "line21=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications]"
set "line22="ToastEnabled"=dword:00000000"
set "line23="
set "line24=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]"
set "line25="SoftLandingEnabled"=dword:00000000"
set "line26="SystemPaneSuggestionsEnabled"=dword:00000000"
set "line27="
set "line28=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers]"
set "line29="DisableAutoplay"=dword:00000001"
set "line30="
set "line31=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]"
set "line32="ColorPrevalence"=dword:00000001"
set "line33="
set "line34=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\DWM]"
set "line35="ColorPrevalence"=dword:00000001"
set "line36="
set "line37=[HKEY_USERS\%myvar%\Control Panel\International\User Profile]"
set "line38="HttpAcceptLanguageOptOut"=dword:00000001"
set "line39="
set "line40=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass]"
set "line41="UserAuthPolicy"=dword:00000000"
set "line42="
set "line43=[HKEY_USERS\%myvar%\Control Panel\Desktop\WindowMetrics]"
set "line44="MinAnimate"=dword:00000000"
set "line45="
set "line46=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]"
set "line47="SearchboxTaskbarMode"=dword:00000000"
set "line48="
set "line49=[HKEY_USERS\%myvar%\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel]"
set "line50="AllItemsIconView"=dword:00000000"
set "line51="StartupPage"=dword:00000001"
set "line52="
set "line53=[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config]"
set "line54="DODownloadMode"=dword:00000000"
set "line55="
set "line56=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows]"
set "line57="CEIPEnable"=dword:00000000"
set "line58="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo !line05!
  echo !line06!
  echo/
  echo !line08!
  echo !line09!
  echo !line10!
  echo !line11!
  echo !line12!
  echo !line13!
  echo !line14!
  echo !line15!
  echo !line16!
  echo !line17!
  echo !line18!
  echo !line19!
  echo/
  echo !line21!
  echo !line22!
  echo/
  echo !line24!
  echo !line25!
  echo !line26!
  echo/
  echo !line28!
  echo !line29!
  echo/
  echo !line31!
  echo !line32!
  echo/
  echo !line34!
  echo !line35!
  echo/
  echo !line37!
  echo !line38!
  echo/
  echo !line40!
  echo !line41!
  echo/
  echo !line43!
  echo !line44!
  echo/
  echo !line46!
  echo !line47!
  echo/
  echo !line49!
  echo !line50!
  echo !line51!
  echo/
  echo !line53!
  echo !line54!
  echo/
  echo !line56!
  echo !line57!
  echo/

) > "Win 10 Explorer Einstellungen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Explorer Einstellungen.reg"
del /F /Q "%~dp0Win 10 Explorer Einstellungen.reg"
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*


:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:Start

taskkill /f /IM "SearchUI.exe"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)

setlocal DisableDelayedExpansion
set "batchPath=%~0"
setlocal EnableDelayedExpansion
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\OEgetPrivileges.vbs"
ECHO args = "ELEV " >> "%temp%\OEgetPrivileges.vbs"
ECHO For Each strArg in WScript.Arguments >> "%temp%\OEgetPrivileges.vbs"
ECHO args = args ^& strArg ^& " "  >> "%temp%\OEgetPrivileges.vbs"
ECHO Next >> "%temp%\OEgetPrivileges.vbs"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%temp%\OEgetPrivileges.vbs"
"%SystemRoot%\System32\WScript.exe" "%temp%\OEgetPrivileges.vbs" %*

:gotPrivileges
if '%1'=='ELEV' shift /1
setlocal & pushd .
cd /d %~dp0

:START
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]"
set "line04="IconVerticalSpacing"="-1125""
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Desktopicon Abstand vertikal anpassen.reg"
REGEDIT.EXE /S "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
del /F /Q "%~dp0Win 10 Desktopicon Abstand vertikal anpassen.reg"
@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
)
Cls
goto:eof

















@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /f
Reg.exe add "HKCU\Control Panel\Desktop" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cisvc" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCR\Directory\shell\runas" /f
Reg.exe add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Directory\Background\shell\runas" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Directory\Background\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\Background\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe delete "HKCR\Drive\shell\runas" /f
Reg.exe add "HKCR\Drive\shell\runas" /ve /t REG_SZ /d "Open Command Window Here as Administrator" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Drive\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /s /k pushd \"%%V\"" /f
Reg.exe add "HKCR\*\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\*\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\exefile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\Directory\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /ve /t REG_SZ /d "Take ownership" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKCR\dllfile\shell\takeownership\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /f
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause
)
Cls
goto:eof

@Echo Off
Title Reg Converter v1.2 & Color 1A
cd %systemroot%\system32
call :IsAdmin

Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /ve /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /ve /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f


:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
)
Cls
goto:eof

@ECHO OFF
COLOR 1F
SET V=1.7
TITLE Windows 10 Registry tweaks(x64) by: TheGeekFreaks
ECHO #########################################################
ECHO #                                                       #
ECHO #  WINDOWS 10 TWEAKS - SKIPBAR!!!                       #
ECHO #                                                       #
ECHO #                                                       #
ECHO #  AUTOR: TGF - DIESES SCRIPT IS KEIN  MUSS!            #
ECHO #                                                       #
ECHO #########################################################

REM ======================= Registry tweaks =======================
ECHO.
:regstart
set /p registry="Tweaks starten? y/n: "
if '%registry%' == 'n' goto servstart
if /i "%registry%" neq "y" goto regstart

:reg0start
set /p reg0="CMD mit Utilman ersetzen? y/n: "
if '%reg0%' == 'n' goto reg1start
if /i "%reg0%" neq "y" goto reg0start
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > NUL 2>&1

:reg1start
set /p reg1="Schnellzugriff als Default in Windows Explorer ausschalten? y/n: "
if '%reg1%' == 'n' goto reg2start
if /i "%reg1%" neq "y" goto reg1start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v "LaunchTo" /t REG_DWORD /d 0 > NUL 2>&1

:reg2start
set /p reg2="PC Shortcut auf Desktop? y/n: "
if '%reg2%' == 'n' goto reg3start
if /i "%reg2%" neq "y" goto reg2start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg3start
set /p reg3="`Dateiendungen anzeigen? y/n: "
if '%reg3%' == 'n' goto reg4start
if /i "%reg3%" neq "y" goto reg3start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg4start
set /p reg4="Sperrbildschirm deaktivieren? y/n: "
if '%reg4%' == 'n' goto reg5start
if /i "%reg4%" neq "y" goto reg4start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg5start
set /p reg5="Klassik  Control Panel anschalten? y/n: "
if '%reg5%' == 'n' goto reg6start
if /i "%reg5%" neq "y" goto reg5start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg6start
set /p reg6="Verstecke die Anzeige für komprimierte NTFS Laufwerke? y/n: "
if '%reg6%' == 'n' goto reg7start
if /i "%reg6%" neq "y" goto reg6start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > NUL 2>&1

:reg7start
set /p reg7="Updatesharing ausschalten? y/n: "
if '%reg7%' == 'n' goto reg8start
if /i "%reg7%" neq "y" goto reg7start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg8start
set /p reg8="Weg mit Pin zum starten? y/n: "
if '%reg8%' == 'n' goto reg9start
if /i "%reg8%" neq "y" goto reg8start
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1

:reg9start
set /p reg9="Vertikales Icon platzieren? y/n: "
if '%reg9%' == 'n' goto reg10start
if /i "%reg9%" neq "y" goto reg9start
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > NUL 2>&1

:reg10start
set /p reg10="Entfernen Sie die Registerkarte "Versionierung" aus den Eigenschaften? y/n: "
if '%reg10%' == 'n' goto reg11start
if /i "%reg10%" neq "y" goto reg10start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > NUL 2>&1

:reg11start
set /p reg11="Jump Listen auschschalten? y/n: "
if '%reg11%' == 'n' goto reg12start
if /i "%reg11%" neq "y" goto reg11start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg12start
set /p reg12="Telemetrie und Datenerfassung entfernen? y/n: "
if '%reg12%' == 'n' goto reg13start
if /i "%reg12%" neq "y" goto reg12start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg13start
set /p reg13="Internet Explorer 11 tweaks? y/n: "
if '%reg13%' == 'n' goto reg14start
if /i "%reg13%" neq "y" goto reg13start
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg14start
set /p reg14="Deaktivieren Sie Cortana, Bing Search und Searchbar? y/n: "
if '%reg14%' == 'n' goto reg15start
if /i "%reg14%" neq "y" goto reg14start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg15start
set /p reg15="Ändern Sie den Anmeldebildschirmhintergrund mit Akzentfarbe? y/n: "
if '%reg15%' == 'n' goto reg16start
if /i "%reg15%" neq "y" goto reg15start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg16start
set /p reg16=" Windows Error Reporting auschschalten? y/n: "
if '%reg16%' == 'n' goto reg17start
if /i "%reg16%" neq "y" goto reg16start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg17start
set /p reg17="Deaktivieren Sie automatische Windows-Updates? y/n: "
if '%reg17%' == 'n' goto reg18start
if /i "%reg17%" neq "y" goto reg17start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > NUL 2>&1

:reg18start
set /p reg18="Ruhezustand deaktivieren? y/n: "
if '%reg18%' == 'n' goto servstart
if /i "%reg18%" neq "y" goto reg18start
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

ECHO Done...

REM ======================= Removing services =======================
ECHO.
:servstart
set /p services="Apply Registry tweaks? y/n: "
if '%services%' == 'n' goto schedstart
if /i "%services%" neq "n" if /i "%services%" neq "y" goto servstart

:serv0start
set /p serv0="Disable tracking services? y/n: "
if '%serv0%' == 'n' goto serv1start
if /i "%serv0%" neq "y" goto serv0start
sc config DiagTrack start= disabled > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled > NUL 2>&1
sc config TrkWks start= disabled > NUL 2>&1
sc config WMPNetworkSvc start= disabled > NUL 2>&1

:serv1start
set /p serv1="Disable WAP Push Message Routing Service? y/n: "
if '%serv1%' == 'n' goto serv2start
if /i "%serv1%" neq "y" goto serv1start
sc config dmwappushservice start= disabled > NUL 2>&1

:serv2start
set /p serv2="Disable Windows Search? y/n: "
if '%serv2%' == 'n' goto serv3start
if /i "%serv2%" neq "y" goto serv2start
sc config WSearch start= disabled > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

:serv3start
set /p serv3="Disable Superfetch? y/n: "
if '%serv3%' == 'n' goto serv4start
if /i "%serv3%" neq "y" goto serv3start
sc config SysMain start= disabled > NUL 2>&1

:serv4start
set /p serv4="Disable Windows Defender? y/n: "
if '%serv4%' == 'n' goto schedstart
if /i "%serv4%" neq "y" goto serv4start
sc config WinDefend start= disabled > NUL 2>&1
sc config WdNisSvc start= disabled > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > NUL 2>&1

ECHO Done...

REM ======================= Removing scheduled tasks =======================
ECHO.
:schedstart
set /p schedules="Removing scheduled tasks? y/n: "
if '%schedules%' == 'n' goto winappstart
if /i "%schedules%" neq "n" if /i "%schedules%" neq "y" goto schedstart

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1

ECHO Done...

REM ======================= Removing Windows default apps =======================
ECHO.
:winappstart
set /p winapps="Removing Windows default apps? y/n: "
if '%winapps%' == 'n' goto odrivestart
if /i "%winapps%" neq "n" if /i "%winapps%" neq "y" goto winappstart

powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > NUL 2>&1

ECHO Done...

REM ======================= Disable / Remove OneDrive =======================
ECHO.
:odrivestart
set /p onedrive="Disable OneDrive? y/n: "
if '%onedrive%' == 'n' goto hoststart
if /i "%onedrive%" neq "y" goto odrivestart
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1

ECHO Done...

REM ======================= Blocking Telemetry Servers =======================
ECHO.
:hoststart
set /p hostsblock="Blocking Telemetry Servers? y/n: "
if '%hostsblock%' == 'n' goto finish
if /i "%hostsblock%" neq "n" if /i "%hostsblock%" neq "y" goto hoststart

copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > NUL 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1

:finish
CLS

ECHO Script 1 Fertig!
ECHO BITTE BELIEBIGE TASTE DRÜCKEN UM WEITER ZU MACHEN!
PAUSE > NUL

rem ========== Pre ==========

rem Don't echo to standard output
@echo off
rem Set version info
set V=4.2.3
rem Change colors
color 1F
rem Set title
title Windows 10 (x64) Version 0.2 by: TheGeekFreaks

rem ========== Start ==========

cls
echo ###############################################################################
echo #                                                                             #
echo #  Windows10 Tweakscript 2   Version 0.2 beta                                 #
echo #                                                                             #
echo #  Microsoft Windows 10  alle Versionen kompatiibel!                          #
echo #                                                                             #
echo #  AUTHOR: TheGeekFreaks                                                      #
echo #                                                                             #
echo #                                                                             #
echo #  Features                                                                   #
echo #                                                                             #
echo #  1. Registry Tweaks                                                         #
echo #  2. Removing Services                                                       #
echo #  3. Removing Scheduled Tasks                                                #
echo #  4. Removing Windows Default Apps                                           #
echo #  5. Disable / Remove OneDrive                                               #
echo #  6. Blocking Telemetry Servers                                              #
echo #  7. Blocking More Windows Servers                                           #
echo #  8. Disable Windows Error Recovery on Startup                               #
echo #  9. Internet Explorer 11 Tweaks                                             #
echo #  10. Libraries Tweaks                                                       #
echo #  11. Windows Update Tweaks                                                  #
echo #  12. Windows Defender Tweaks                                                #
echo #                                                                             #
echo ###############################################################################
echo.
timeout /T 1 /NOBREAK > nul

rem ========== Automatically Check & Get Admin Rights ==========

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>nul 2>nul
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
echo.
echo ###############################################################################
echo #  Invoking UAC for Privilege Escalation                                      #
echo ###############################################################################

echo Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
echo args = "ELEV " >> "%vbsGetPrivileges%"
echo For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
echo args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
echo Next >> "%vbsGetPrivileges%"
echo UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

rem ========== Initializing ==========

set PMax=0
set PRun=0
set PAct=0

rem ========== 1. Registry Tweaks ==========

echo.
echo ###############################################################################
echo #  1. Registry Tweaks  --  Start                                              #
echo ###############################################################################
echo.

:1000
set /A Pline=1000
set PMax=37
set PRun=0
rem set PAct=0
echo Apply Registry tweaks (%PMax%).
set /p Pselect="Continue? y/n/a: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+2
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:1001
set myMSG=Show computer shortcut on desktop.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1002
rem 0 = show icon, 1 = don't show icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1003
set myMSG=Show Network shortcut on desktop.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1004
rem 0 = show icon, 1 = don't show icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1005
set myMSG=Classic vertical icon spacing.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1006
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > nul 2>&1set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1007
set myMSG=Lock the Taskbar.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1008
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1009
set myMSG=Always show all icons on the taskbar (next to clock).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1010
rem 0 = Show all icons
rem 1 = Hide icons on the taskbar
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1011
set myMSG=Delay taskbar thumbnail pop-ups to 10 seconds.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1012
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "10000" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1013
set myMSG=Enable classic control panel view.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1014
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1015
set myMSG=Turn OFF Sticky Keys when SHIFT is pressed 5 times.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1016
rem 506 = Off, 510 = On (default)
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1017
set myMSG=Turn OFF Filter Keys when SHIFT is pressed for 8 seconds.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1018
rem 122 = Off, 126 = On (default)
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1019
set myMSG=Disable Hibernation.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1020
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1021
set myMSG=Underline keyboard shortcuts and access keys.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1022
reg add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1023
set myMSG=Show known file extensions in Explorer.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1024
rem 0 = extensions are visible
rem 1 = extensions are hidden
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1025
set myMSG=Hide indication for compressed NTFS files.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1026
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1027
set myMSG=Show Hidden files in Explorer.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1028
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1029
set myMSG=Show Super Hidden System files in Explorer.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1030
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1031
set myMSG=Prevent both Windows and Office from creating LNK files in the Recents folder.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1032
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1033
set myMSG=Replace Utilman with CMD.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1034
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1035
set myMSG=Add the option "Processor performance core parking min cores".
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1036
rem Option will be added to: Power Options > High Performance > Change Plan Settings > Change advanced power settings > Processor power management
rem Default data is 1 (option hidden)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f  > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1037
set myMSG=Add the option "Disable CPU Core Parking".
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1038
rem Default value is 100 decimal.
rem Basically "Core parking" means that the OS can use less CPU cores when they are not needed, and saving power.
rem This, however, can somewhat hamper performance, so advanced users prefer to disable this feature.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f  > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1039
set myMSG=Remove Logon screen wallpaper/background. Will use solid color instead (Accent color).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1040
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f  > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1041
set myMSG=Disable lockscreen.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1042
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1043
set myMSG=Remove versioning tab from properties.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1044
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1045
set myMSG=Disable jump lists.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1046
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1047
set myMSG=Disable Windows Error Reporting.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1048
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1049
set myMSG=Disable Cortana (Speech Search Assistant, which also sends information to Microsoft).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1050
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1051
set myMSG=Hide the search box from taskbar. You can still search by pressing the Win key and start typing what you're looking for.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1052
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1053
set myMSG=Disable MRU lists (jump lists) of XAML apps in Start Menu.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1054
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1055
set myMSG=Set Windows Explorer to start on This PC instead of Quick Access.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1056
rem 1 = This PC, 2 = Quick access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1057
set myMSG=Disable Disk Quota tab, which appears as a tab when right-clicking on drive letter - Properties.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1058
rem 1 = This PC, 2 = Quick access
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DiskQuota" /v "Enable" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1059
set myMSG=Disable creation of an Advertising ID.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1060
rem 1 = This PC, 2 = Quick access
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1061
set myMSG=Remove Pin to start (3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1062
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1063
set myMSG=Disable Cortana, Bing Search and Searchbar (4).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1064
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1065
set myMSG=Turn off the Error Dialog (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1066
reg add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1067
set myMSG=Disable Administrative shares (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1068
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1069
set myMSG=Add "Reboot to Recovery" to right-click menu of "This PC" (4).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1070
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery" /v "Icon" /t REG_SZ /d %SystemRoot%\System32\imageres.dll,-110" /f > nul 2>&1
reg add "HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell\Reboot to Recovery\command" /ve /d "shutdown.exe -r -o -f -t 00" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1071
set myMSG=Change Clock and Date formats of current user to: 24H, metric (Sign out required to see changes) (6).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1072
rem Apply to all users by using the key: HKLM\SYSTEM\CurrentControlSet\Control\CommonGlobUserSettings\Control Panel\International
reg add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "0" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "iNegCurr" /t REG_SZ /d "1" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d "1" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "yyyy/MM/dd" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f > nul 2>&1
reg add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "H:mm:ss" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+6
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1073
set myMSG=Enable Developer Mode (enables you to run XAML apps you develop in Visual Studio which haven't been certified yet) (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1074
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowAllTrustedApps" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v "AllowDevelopmentWithoutDevLicense" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1075
set myMSG=Remove telemetry and data collection (14).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:1076
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > nul 2>&1

reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Registry Tweaks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:1077
:1078

:1100
echo.
echo ###############################################################################
echo #  1. Registry Tweaks  --  End                                                #
echo ###############################################################################
echo.

rem ========== 2. Removing Services ==========

echo.
echo ###############################################################################
echo #  2. Removing Services  --  Start                                            #
echo ###############################################################################
echo.

:2000
set /A Pline=2000
set PMax=36
set PRun=0
rem set PAct=0
echo Removing Services (%PMax%).
set /p Pselect="Continue? y/n/a: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+2
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:2001
set myMSG=Disable Connected User Experiences and Telemetry (To turn off Telemetry and Data Collection).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2002
sc config DiagTrack start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2003
set myMSG=Disable Diagnostic Policy Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2004
sc config DPS start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2005
set myMSG=Disable Distributed Link Tracking Client (If your computer is not connected to any network).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2006
sc config TrkWks start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2007
set myMSG=Disable WAP Push Message Routing Service (To turn off Telemetry and Data Collection).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2008
sc config dmwappushservice start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2009
set myMSG=Disable Downloaded Maps Manager (If you don't use Maps app).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2010
sc config MapsBroker start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2011
set myMSG=Disable IP Helper (If you don't use IPv6 connection).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2012
sc config iphlpsvc start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2013
set myMSG=Disable Program Compatibility Assistant Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2014
sc config PcaSvc start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2015
set myMSG=Disable Print Spooler (If you don't have a printer).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2016
sc config Spooler start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2017
set myMSG=Disable Remote Registry (You can set it to DISABLED for Security purposes).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2018
sc config RemoteRegistry start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2019
set myMSG=Disable Secondary Logon.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2020
sc config seclogon start= Disabled > nul 2>&1 	
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2021
set myMSG=Disable Security Center.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2022
sc config wscsvc start= Disabled > nul 2>&1 
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2023
set myMSG=Disable TCP/IP NetBIOS Helper (If you are not in a workgroup network).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2024
sc config lmhosts start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2025
set myMSG=Disable Touch Keyboard and Handwriting Panel Service (If you don't want to use touch keyboard and handwriting features.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2026
sc config TabletInputService start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2027
set myMSG=Disable Windows Error Reporting Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2028
sc config WerSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2029
set myMSG=Disable Windows Image Acquisition (WIA) (If you don't have a scanner).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2030
sc config stisvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2031
set myMSG=Disable Windows Search.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2032
sc config WSearch start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2033
set myMSG=Disable tracking services (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2034
sc config diagnosticshub.standardcollector.service start= Disabled > nul 2>&1
sc config WMPNetworkSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2035
set myMSG=Disable Superfetch.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2036
sc config SysMain start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2037
set myMSG=Disable Xbox Services (5).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2038
rem Xbox Accessory Management Service
sc config XboxGipSvc start= Disabled > nul 2>&1
rem Xbox Game Monitoring
sc config xbgm start= Disabled > nul 2>&1
rem Xbox Live Auth Manager
sc config XblAuthManager start= Disabled > nul 2>&1
rem Xbox Live Game Save
sc config XblGameSave start= Disabled > nul 2>&1
rem Xbox Live Networking Service
sc config XboxNetApiSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+5
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2039
set myMSG=Disable AllJoyn Router Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2040
rem  This service is used for routing the AllJoyn messages for AllJoyn clients.
sc config AJRouter start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2041
set myMSG=Disable Bluetooth Services (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2042
rem Bluetooth Handsfree Service
sc config BthHFSrv start= Disabled > nul 2>&1
rem Bluetooth Support Service
sc config bthserv start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2043
set myMSG=Disable Geolocation Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2044
sc config lfsvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2045
set myMSG=Disable Phone Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2046
sc config PhoneSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2047
set myMSG=Disable Windows Biometric Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2048
sc config WbioSrvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2049
set myMSG=Disable Windows Mobile Hotspot Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2050
sc config icssvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2051
set myMSG=Disable Windows Media Player Network Sharing Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2052
sc config WMPNetworkSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2053
set myMSG=Disable Windows Update Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2054
sc config wuauserv start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2055
set myMSG=Disable Enterprise App Management Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2056
sc config EntAppSvc start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2057
set myMSG=Disable Hyper-V Services (9).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2058
rem HV Host Service
sc config HvHost start= Disabled > nul 2>&1
rem Hyper-V Data Exchange Service
sc config vmickvpexchange start= Disabled > nul 2>&1
rem Hyper-V Guest Service Interface
sc config vmicguestinterface start= Disabled > nul 2>&1
rem Hyper-V Guest Shutdown Service
sc config vmicshutdown start= Disabled > nul 2>&1
rem Hyper-V Heartbeat Service
sc config vmicheartbeat start= Disabled > nul 2>&1
rem Hyper-V PowerShell Direct Service
sc config vmicvmsession start= Disabled > nul 2>&1
rem Hyper-V Remote Desktop Virtualization Service
sc config vmicrdv start= Disabled > nul 2>&1
rem Hyper-V Time Synchronization Service
sc config vmictimesync start= Disabled > nul 2>&1
rem Hyper-V Volume Shadow Copy Requestor
sc config vmicvss start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+9
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2059
set myMSG=Disable HomeGroup Listener.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2060
sc config HomeGroupListener start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2061
set myMSG=Disable HomeGroup Provider.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2062
sc config HomeGroupProvider start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2063
set myMSG=Disable Net.Tcp Port Sharing Service.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2064
sc config NetTcpPortSharing start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2065
set myMSG=Disable Routing and Remote Access.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2066
sc config RemoteAccess start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2067
set myMSG=Disable Internet Connection Sharing (ICS).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2068
sc config RemoteAccess start= Disabled > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2069
set myMSG=Disable Superfetch (A must for SSD drives, but good to do in general)(3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2070
rem Disabling this service prevents further creation of PF files in C:\Windows\Prefetch.
rem After disabling this service, it is completely safe to delete everything in that folder, except for the ReadyBoot folder.
sc config SysMain start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2071
set myMSG=Disable Action Center & Security Center.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:2072
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d 0 /f
sc config wscsvc start= disabled
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Services Remove. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:2073
:2074

:2100
echo.
echo ###############################################################################
echo #  2. Removing Services  --  End                                              #
echo ###############################################################################
echo.

rem ========== 3. Removing Scheduled Tasks ==========

echo.
echo ###############################################################################
echo #  3. Removing Scheduled Tasks  --  Start                                     #
echo ###############################################################################
echo.

:3000
set /A Pline=3000
set PMax=1
set PRun=0
rem set PAct=0
echo Removing scheduled tasks (17).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:3001
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+17
echo Done %PRun% / %PMax% Removing Scheduled Tasks. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:3100
echo.
echo ###############################################################################
echo #  3. Removing Scheduled Tasks  --  End                                       #
echo ###############################################################################
echo.

rem ========== 4. Removing Windows Default Apps ==========

echo.
echo ###############################################################################
echo #  4. Removing Windows Default Apps  --  Start                                #
echo ###############################################################################
echo.

:4000
set /A Pline=4000
set PMax=1
set PRun=0
rem set PAct=0
echo Removing Windows default apps (12).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:4001
powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > nul 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+12
echo Done %PRun% / %PMax% Removing Windows Default Apps. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:4100
echo.
echo ###############################################################################
echo #  4. Removing Windows Default Apps  --  End                                  #
echo ###############################################################################
echo.

rem ========== 5. Disable / Remove OneDrive ==========

echo.
echo ###############################################################################
echo #  5. Disable / Remove OneDrive  --  Start                                    #
echo ###############################################################################
echo.

:5000
set /A Pline=5000
set PMax=1
set PRun=0
rem set PAct=0
echo Disable OneDrive (7).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:5001
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > nul 2>&1

reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
reg delete "HKCU\SOFTWARE\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1

:: Detete OneDrive icon on explorer.exe (Only 64 Bits)
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t reg_DWORD /d 0 /f > nul 2>&1
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t reg_DWORD /d 0 /f > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+7
echo Done %PRun% / %PMax% Disable / Remove OneDrive. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:5100
echo.
echo ###############################################################################
echo #  5. Disable / Remove OneDrive  --  End                                      #
echo ###############################################################################
echo.

rem ========== 6. Blocking Telemetry Servers ==========

echo.
echo ###############################################################################
echo #  6. Blocking Telemetry Servers  --  Start                                   #
echo ###############################################################################
echo.

:6000
set /A Pline=6000
set PMax=1
set PRun=0
rem set PAct=0
echo Blocking Telemetry Servers (25).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:6001
copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > nul 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1
find /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+25
echo Done %PRun% / %PMax% Blocking Telemetry Servers. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:6100
echo.
echo ###############################################################################
echo #  6. Blocking Telemetry Servers  --  End                                     #
echo ###############################################################################
echo.

rem ========== 7. Blocking More Windows Servers ==========

echo.
echo ###############################################################################
echo #  7. Blocking More Windows Servers  --  Start                                #
echo ###############################################################################
echo.

:7000
set /A Pline=7000
set PMax=1
set PRun=0
rem set PAct=0
echo Blocking More Telemetry Servers (109).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:7001
copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > nul 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1
find /C /I "184-86-53-99.deploy.static.akamaitechnologies.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 184-86-53-99.deploy.static.akamaitechnologies.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.ads1.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.ads1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.ads2.msads.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.ads2.msads.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.ads2.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.ads2.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a.rad.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a.rad.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0001.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0001.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0002.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0002.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0003.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0003.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0004.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0004.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0005.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0005.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0006.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0006.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0007.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0007.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0008.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0008.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-0009.a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-0009.a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a1621.g.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a1621.g.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a1856.g2.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a1856.g2.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a1961.g.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a1961.g.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a978.i6g1.akamai.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a978.i6g1.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ac3.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ac3.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ad.doubleclick.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ad.doubleclick.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "adnexus.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 adnexus.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "adnxs.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 adnxs.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ads.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ads.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ads1.msads.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ads1.msads.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ads1.msn.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ads1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "aidps.atdmt.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 aidps.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "aka-cdn-ns.adtech.de" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 aka-cdn-ns.adtech.de>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a-msedge.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a-msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "any.edge.bing.com" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 any.edge.bing.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "az361816.vo.msecnd.net" %WINDIR%\system32\drivers\etc\hosts	
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 az361816.vo.msecnd.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "az512334.vo.msecnd.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 az512334.vo.msecnd.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "b.ads1.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 b.ads1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "b.ads2.msads.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 b.ads2.msads.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "b.rad.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 b.rad.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "bingads.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 bingads.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "bs.serving-sys.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 bs.serving-sys.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "c.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 c.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cdn.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cdn.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cds26.ams9.msecn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cds26.ams9.msecn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "compatexchange.cloudapp.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 compatexchange.cloudapp.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "corp.sts.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 corp.sts.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "corpext.msitadfs.glbdns2.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cs1.wpc.v0cdn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cs1.wpc.v0cdn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "cy2.vortex.data.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 cy2.vortex.data.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "db3aqu.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 db3aqu.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "diagnostics.support.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 diagnostics.support.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e2835.dspb.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e2835.dspb.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e7341.g.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e7341.g.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e7502.ce.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e7502.ce.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "e8218.ce.akamaiedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 e8218.ce.akamaiedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ec.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ec.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "fe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 fe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "fe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 fe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "feedback.microsoft-hohm.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 feedback.microsoft-hohm.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "feedback.search.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 feedback.search.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "feedback.windows.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 feedback.windows.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "flex.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 flex.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "g.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 g.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "h1.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 h1.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "h2.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 h2.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "hostedocsp.globalsign.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 hostedocsp.globalsign.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "i1.services.social.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 i1.services.social.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "i1.services.social.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 i1.services.social.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ipv6.msftncsi.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ipv6.msftncsi.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ipv6.msftncsi.com.edgesuite.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ipv6.msftncsi.com.edgesuite.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "lb1.www.ms.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 lb1.www.ms.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "live.rads.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 live.rads.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "m.adnxs.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 m.adnxs.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "m.hotmail.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 m.hotmail.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msedge.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msedge.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msftncsi.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msftncsi.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msnbot-65-55-108-23.search.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msnbot-65-55-108-23.search.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "msntest.serving-sys.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 msntest.serving-sys.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "onesettings-db5.metron.live.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 onesettings-db5.metron.live.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "pre.footprintpredict.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 pre.footprintpredict.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "preview.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 preview.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "rad.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 rad.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "rad.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 rad.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "s0.2mdn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 s0.2mdn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "schemas.microsoft.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 schemas.microsoft.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "secure.adnxs.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 secure.adnxs.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "secure.flashtalking.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 secure.flashtalking.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "settings-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 settings-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "sls.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 sls.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ssw.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ssw.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "static.2mdn.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 static.2mdn.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe1.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe1.ws.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe2.update.microsoft.com.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe2.update.microsoft.com.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe2.update.microsoft.com.akadns.net," %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe2.update.microsoft.com.akadns.net,>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "statsfe2.ws.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 statsfe2.ws.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "survey.watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 survey.watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "survey.watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 survey.watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "view.atdmt.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 view.atdmt.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-bn2.metron.live.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-bn2.metron.live.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "vortex-cy2.metron.live.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 vortex-cy2.metron.live.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "win10.ipv6.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 win10.ipv6.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "www.bingads.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 www.bingads.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "www.go.microsoft.akadns.net" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 www.go.microsoft.akadns.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "www.msftncsi.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 www.msftncsi.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "a248.e.akamai.net" %WINDIR%\system32\drivers\etc\hosts
rem skype & itunes issues 
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 a248.e.akamai.net>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "apps.skype.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 apps.skype.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "c.msn.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 c.msn.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "pricelist.skype.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 pricelist.skype.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "s.gateway.messenger.live.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 s.gateway.messenger.live.com>>%WINDIR%\system32\drivers\etc\hosts
find /C /I "ui.skype.com" %WINDIR%\system32\drivers\etc\hosts
if %ERRORLEVEL% NEQ 0 echo ^0.0.0.0 ui.skype.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+109
echo Done %PRun% / %PMax% Blocking More Windows Servers. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:7100
echo.
echo ###############################################################################
echo #  7. Blocking More Windows Servers  --  End                                  #
echo ###############################################################################
echo.

rem ========== 8. Disable Windows Error Recovery on Startup ==========

echo.
echo ###############################################################################
echo #  8. Disable Windows Error Recovery on Startup   --  Start                   #
echo ###############################################################################
echo.

:8000
set /A Pline=8000
set PMax=1
set PRun=0
rem set PAct=0
echo Disable Windows Error Recovery on Startup (2).
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:8001
bcdedit /set recoveryenabled NO > nul 2>&1
bcdedit /set {current} bootstatuspolicy ignoreallfailures > nul 2>&1

set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax% Disable Windows Error Recovery on Startup. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul

:8100
echo.
echo ###############################################################################
echo #  8. Disable Windows Error Recovery on Startup  --  End                      #
echo ###############################################################################
echo.

rem ========== 9. Internet Explorer 11 Tweaks ==========

echo.
echo ###############################################################################
echo #  9. Internet Explorer 11 Tweaks  --  Start                                  #
echo ###############################################################################
echo.

:9000
set /A Pline=9000
set PMax=3
set PRun=0
rem set PAct=0
echo Internet Explorer 11 Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:9001
set myMSG=Internet Explorer 11 Tweaks (Basic)(15).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:9002
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.com" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.com" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > nul 2>&1

reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "PlaySounds" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d PMEM /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d 1 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+15
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:9003
set myMSG=Disable IE Suggested Sites & Flip ahead (page prediction which sends browsing history to Microsoft).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:9004
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "DataStreamEnabledState" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\FlipAhead" /v "FPEnabled" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:9005
set myMSG=Add Google as search provider for IE11, and make it the default (11).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:9006
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f  > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "DisplayName" /t REG_SZ /d "Google" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURL" /t REG_SZ /d "http://www.google.com/favicon.ico" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.google.com/favicon.ico" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "OSDFileURL" /t REG_SZ /d "http://www.iegallery.com/en-us/AddOns/DownloadAddOn?resourceId=813" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "ShowSearchSuggestions" /t REG_DWORD /d 1 /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURL" /t REG_SZ /d "http://clients5.google.com/complete/search?q={searchTerms}&client=ie8&mw={ie:maxWidth}&sh={ie:sectionHeight}&rh={ie:rowHeight}&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://clients5.google.com/complete/search?hl={language}&q={searchTerms}&client=ie8&inputencoding={inputEncoding}&outputencoding={outputEncoding}" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "TopResultURLFallback" /t REG_SZ /d "" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /v "URL" /t REG_SZ /d "http://www.google.com/search?q={searchTerms}&sourceid=ie7&rls=com.microsoft:{language}:{referrer:source}&ie={inputEncoding?}&oe={outputEncoding?}" /f > nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{89418666-DF74-4CAC-A2BD-B69FB4A0228A}" /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+11
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:9007
:9008

:9100
echo.
echo ###############################################################################
echo #  9. Internet Explorer 11 Tweaks  --  End                                    #
echo ###############################################################################
echo.

rem ========== 10. Libraries Tweaks ==========

echo.
echo ###############################################################################
echo #   10. Libraries Tweaks  --  Start                                           #
echo ###############################################################################
echo.

:10000
set /A Pline=10000
set PMax=8
set PRun=0
rem set PAct=0
echo Libraries Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:10001
set myMSG=Remove Music, Pictures & Videos from Start Menu places (Settings > Personalization > Start > Choose which folders appear on Start)(3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10002
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\05 - Music.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\06 - Pictures.lnk"
del "C:\ProgramData\Microsoft\Windows\Start Menu Places\07 - Videos.lnk"
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10003
set myMSG=Remove Music, Pictures & Videos from Libraries (3).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10004
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Music.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Pictures.library-ms"
del "%userprofile%\AppData\Roaming\Microsoft\Windows\Libraries\Videos.library-ms"
set /A PRun=%PRun%+1
set /A PAct=%PAct%+3
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10005
set myMSG=Remove Libraries (60).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10006
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{59BD6DD1-5CEC-4d7e-9AD2-ECC64154418D}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{C4D98F09-6124-4fe0-9942-826416082DA9}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\UsersLibraries" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\system32\windows.storage.dll,-50691" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Namespace\Windows\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\WindowsSettingHandlers\UserLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.NavPaneShowLibraries" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF324EC-F905-4c69-851A-DDC8795F71F2}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{51F649D3-4BFF-42f6-A253-6D878BE1651D}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+60
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10007
set myMSG=Remove "Show Libraries" from Folder Options -> View tab (Advanced Settings).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10008
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\NavPane\ShowLibraries" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10009
set myMSG=Remove Music (appears under This PC in File Explorer)(28).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10010
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyMusic" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonMusic" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+28
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10011
set myMSG=Remove Pictures (appears under This PC in File Explorer) (41).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10012
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyPictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@C:\Windows\System32\Windows.UI.Immersive.dll,-38304" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\StartMenu\StartPanel\PinnedItems\Pictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0b2baaeb-0042-4dca-aa4d-3ee8648d03e5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{4dcafe13-e6a7-4c28-be02-ca8c2126280d}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{b3690e58-e961-423b-b687-386ebfd83239}" /f

reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{c1f8339f-f312-4c97-b1c6-ecdf5910c5c0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonPictures" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+41
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10013
set myMSG=Remove Videos (appears under This PC in File Explorer) (29).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10014
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /f
reg delete "HKEY_CLASSES_ROOT\SystemFileAssociations\MyVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{ea25fbd7-3bf7-409e-b97f-3352240903f4}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{292108be-88ab-4f33-9a26-7748e62e37ad}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{5fa96407-7e77-483c-ac93-691d05850de8}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CommonVideo" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{51294DA1-D7B1-485b-9E9A-17CFFE33E187}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+29
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10015
set myMSG=Remove Pictures, Music, Videos from MUIcache (5).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:10016
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34584" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34595" /f
reg delete "HKCU\SOFTWARE\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-34620" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MuiCache\1\52C64B7E" /v "@windows.storage.dll,-21790" /f
set /A PRun=%PRun%+1
set /A PAct=%PAct%+5
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:10017
:10018

:10100
echo.
echo ###############################################################################
echo #  10. Libraries Tweaks  --  End                                              #
echo ###############################################################################
echo.


rem ========== 11. Windows Update Tweaks ==========

echo.
echo ###############################################################################
echo #  11. Windows Update Tweaks --  Start                                        #
echo ###############################################################################
echo.

:11000
set /A Pline=11000
set PMax=4
set PRun=0
rem set PAct=0
echo Windows Update Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:11001
set myMSG=Windows Update - Notify first.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11002
net stop wuauserv > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AutoInstallMinorUpdates" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f > nul 2>&1
net start wuauserv > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+5
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11003
set myMSG=Change how Windows Updates are delivered - allow only directly from Microsoft.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11004
rem 0 = Off (only directly from Microsoft)
rem 1 = Get updates from Microsoft and PCs on your local network
rem 3 = Get updates from Microsoft, PCs on your local network & PCs on the Internet (like how torrents work)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11005
set myMSG=Disable Windows Update sharing (2).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11006
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+2
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11007
set myMSG=Disable automatic Windows Updates.
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:11008
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+1
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:11009
:11010

:11100
echo.
echo ###############################################################################
echo #  11. Windows Update Tweaks  --  End                                         #
echo ###############################################################################
echo.


rem ========== 12. Windows Defender Tweaks ==========

echo.
echo ###############################################################################
echo #  12. Windows Defender Tweaks --  Start                                      #
echo ###############################################################################
echo.

:12000
set /A Pline=12000
set PMax=2
set PRun=0
rem set PAct=0
echo Windows Defender Tweaks.
set /p Pselect="Continue? y/n: "
if '%Pselect%' == 'y' set /A Pline=%Pline%+1
if '%Pselect%' == 'n' set /A Pline=%Pline%+100
goto %Pline%

:12001
set myMSG=Don't allow Windows Defender to submit samples to MAPS (formerly SpyNet) (4).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:12002
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn setowner -ownr "n:Administrators" -rec yes
%SystemRoot%\System32\setaclx64 -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" -ot reg -actn ace -ace "n:Administrators;p:full" -rec yes
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f > nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 0 /f > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:12003
set myMSG=Disable Windows Defender (8).
echo %myMSG%
set /p regTweak="Continue? y/n: "
if '%regTweak%' == 'y' set /A Pline=%Pline%+1
if '%regTweak%' == 'n' set /A Pline=%Pline%+2
goto %Pline%
:12004
sc config WinDefend start= Disabled > nul 2>&1
sc config WdNisSvc start= Disabled > nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > nul 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > nul 2>&1
set /A PRun=%PRun%+1
set /A PAct=%PAct%+4
echo Done %PRun% / %PMax%. Total Actions %PAct%.
timeout /T 1 /NOBREAK > nul
set /A Pline=%Pline%+1
if '%Pselect%' == 'a' set /A Pline=%Pline%+1
goto %Pline%

:12005
:12006

:12100
echo.
echo ###############################################################################
echo #  12. Windows Defender Tweaks  --  End                                       #
echo ###############################################################################
echo.

rem ========== Finish ==========

:finish
echo.
echo ###############################################################################
echo #                                                                             #
echo #  FERTIG                                                                     #
echo #                                                                             #
echo #  AUTHOR: TheGeekFreaks 2019                                                 #
echo #                                                                             #
echo ###############################################################################
echo #  Total Actions %PAct%.
echo ###############################################################################
echo #                                                                             #
echo #  Finish. Ready for GAMING!                                                  #
echo #                                                                             #
echo #                                                                             #
echo ###############################################################################