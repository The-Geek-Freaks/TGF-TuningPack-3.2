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
exit /B

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
for /f "delims= " %%a in ('"wmic useraccount where name='%username%' get sid"') do (
   if not "%%a"=="SID" (          
      set myvar=%%a
      goto :loop_end
   )   
)

:loop_end
set "line01=Windows Registry Editor Version 5.00"
set "line02="
set "line03=[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine]"
set "line04="MpEnablePus"=dword:00000001"
set "line05="

setlocal EnableDelayedExpansion
(
  echo !line01!
  echo/
  echo !line03!
  echo !line04!
  echo/

) > "Win 10 Defender Malware Schutz.reg"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ot reg -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
REGEDIT.EXE /S "%~dp0Win 10 Defender Malware Schutz.reg"
del /F /Q "%~dp0Win 10 Defender Malware Schutz.reg"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ot reg -actn ace -ace "n:%USERNAME%;p:read"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -ot reg -actn setowner -ownr "n:SYSTEM"

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

