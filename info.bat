@echo off
title [SearchEngine]
setlocal enabledelayedexpansion
chcp 65001 >nul
set "starttime=%time%"
set "folder=Data_%COMPUTERNAME%_%random%"
cls
echo Name:    [%folder%] 
echo Begin: [%starttime%]
echo Status: [1\4]
echo Work: [Basic environment data]
md %folder%
cd %folder%
md system_information
cd system_information

echo ===============================
echo Имя пользователя: %USERNAME% > "./Основные_данные.txt"
echo Имя компьютера: %COMPUTERNAME% >> "./Основные_данные.txt"
echo Домашний каталог: %USERPROFILE%  >> "./Основные_данные.txt"
whoami /all >> "./Основные_данные.txt"
qwinsta  >> "./Основные_данные.txt"
wmic os get osarchitecture >> "./Основные_данные.txt"

echo Local profiles
(dir /b  %USERPROFILE%\.. 2>nul) > "./Локальные_профили.txt"

echo Sessions
(klist sessions 2>nul) > "./Сессии.txt"

echo Переменные среды
(set 2>nul) > "./Переменные.txt"

echo Запущенные процессы
(tasklist 2>nul) > "./Процессы.txt"

echo IP-конфигурация
(ipconfig /all 2>nul) > "./Конфигурация_IP.txt"

echo Кэш DNS
(ipconfig /displaydns 2>nul) > "./DNS.txt"

echo Кэш ARP
(arp -a 2>nul) > "./ARP.txt"

echo таблица маршрутищации 
(route print 2>nul) > "./Маршрутизация_табло.txt"

echo Группы
(net localgroup 2>nul) > "./Группы.txt"

echo Группы домена
(net group /domain 2>nul) > "./Домены.txt"

echo Залогиненные юзеры
(quser 2>nul) > "./Юзеры_логин.txt"

echo Юзер в домене 
(net user %USERNAME% /domain 2>nul) > "./Права_домен.txt"

echo Пользователи домена
(net user /domain 2>nul) > "./Пользователи.txt"

echo Сетевые диски
(net use 2>nul) > "./Сетевые_диски.txt"

echo Запущенные службы
(net start 2>nul) > "./Службы.txt"

echo Установленные службы
(sc queryex 2>nul) >> "./Службы.txt"

echo Общие ресурсы
(net share 2>nul) > "./Общие_ресурсы.txt"

echo Сетевые ресурсы
(net view 2>nul) > "./Сетевые_Ресурсы.txt"

echo Информация о железе
(systeminfo 2>nul) > "./Железо.txt"

echo Подключения
(netstat -n -o -q -a 2>nul) > "./Подключения.txt"

echo Маршрутизация
(netstat -r 2>nul) > "./Маршрутизация.txt"

echo Установленное ПО
(wmic product get Name, Version 2>nul) > "./ПО.txt"

echo Логистические диски
(wmic path win32_logicaldisk 2>nul) > "./Диски.txt"
(wmic logicaldisk get caption 2>nul | more) >> "./Диски.txt"

echo Сетевые адаптеры
(wmic path win32_networkadapter 2>nul) > "./Адаптеры.txt"

echo Драйвера
(driverquery /SI 2>nul) > "./Драйвера.txt"

echo Credentials manager / Windows vault
(cmdkey /list 2>nul) > "./cmdkey.txt"

echo икеты кербероса
(klist 2>nul) > "./Керберос_тикеты.txt"

echo Дамп журнала событий
(wevtutil qe System /rd:true /f:text 2>nul) > "./Журналы_событий.txt"

echo Сертификаты
(certutil -store my 2>nul) > "./Сертификаты.txt"

echo Настройки брандмауэра
(netsh advfirewall show allprofiles 2>nul) > "./Брандмауэр.txt"

echo Информация о WMI
(wmic qfe 2>nul) > "./WMI.txt"

echo Информация о настройках групповой политики
(gpresult /r 2>nul) > "./Групповая_политика.txt"

echo Запланированные задачи
(schtasks /query /fo LIST /v 2>nul) > "./Запланированные_задачи.txt"

echo Подключённые устройства
(wmic path Win32_PnPEntity where "ConfigManagerErrorCode = 0" 2>nul) > "./Устройства.txt"

echo Поиск антивируса
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get * > "./Антивирус.txt"
(wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more) >> "./Антивирус.txt"

echo Управление питанием
(powercfg -list 2>nul) > "./Управление_питанием.txt"

echo Настройки Брандмауэра (права)
netsh advfirewall export "%CD%\Брандмауэр_настройки.txt" 2>nul

echo Настройки Брандмауэра (без прав)
(netsh firewall show config 2>nul) > "./Брандмауэр_настройки_2.txt"

echo Состояние Брандмауэра
(netsh firewall show state 2>nul) > "./Брандмауэр_состояние.txt"

echo ===============================
echo.
echo Подготовка ко второму этапу (3 сек.)
timeout /t 3 >nul
cd .. 
md registry
cd registry
cls

echo Имя:    [%folder%] 
echo Начало: [%starttime%]
echo Статус: [2\4]
echo Работа: [Чтение реестра]
echo ===============================


echo Проверка основных прав
echo.
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion" >nul 2>&1
if %errorlevel% == 0 (
  echo [+] Чтение
  echo Чтение - ДА > "ДОСТУП.txt"
) else (
  echo [-] Чтение
  echo Чтение - НЕТ > "ДОСТУП.txt"
  goto skip_reg
)

reg add "HKCU\Software\TestKey" /v "TestValue" /t REG_SZ /d "TestString" /f >nul 2>&1 
if %errorlevel% == 0 (
  echo [+] Изменение
  echo Изменение - ДА >> "ДОСТУП.txt"
  reg delete "HKCU\Software\TestKey" /f >nul 2>&1 
) else (
  echo [-] Изменение
  echo Изменение - НЕТ >> "ДОСТУП.txt"
)

echo.
echo проверка чтения основных путей
echo.

for %%i in (
	HKCU\Software\Microsoft\Windows\CurrentVersion
	HKCU\Software\Microsoft\Windows\
	HKCU\Software\Microsoft\
) do (
	reg query "%%i" 2>nul | find /i "ERROR" >nul
	if !errorlevel! == 0 (
		echo [-] %%i
	) else (
    	echo [+] %%i
	)
)

echo.
echo проверка доступа в критические точки
echo.

for %%K in (
	HKLM\SYSTEM\CurrentControlSet\Services
	HKCU\Software\Microsoft\Windows
	HKCU\Software\Microsoft
	HKCU\Software\Microsoft\Windows\CurrentVersion
	HKLM\Software\Microsoft\Windows\CurrentVersion
	HKLM\SYSTEM\CurrentControlSet
	HKLM\SOFTWARE\Policies
	HKLM\Software\Microsoft\Windows\CurrentVersion\Run
	HKCU\Software\Microsoft\Windows\CurrentVersion\Run
	HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
	HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
) do (
		echo [i] Testing %%K
    reg add "%%K\Test" /v "TestKey" /t REG_SZ /d "TestData" /f >nul 2>&1
    if !errorlevel!==0 (
        echo [+] Write:  %%K
        reg delete "%%K\Test" /f >nul 2>&1
        echo [+] Delete: %%K
		echo %%K >> "./Доступ_список.txt"
    ) else (
        echo [-] Write:  %%K
    )
	echo.
)

echo Проверяем доступные сервисы
echo.

for /f %%a in ('reg query hklm\system\currentcontrolset\services') do (
  if not "%%a"=="" (  
    for /f "delims=" %%a in ('reg add "%%a" /v TestKey /t REG_SZ /d "TestValue" /f 2^>^&1') do (
		set "output=%%a"
	)
	echo !output!| findstr /i "ERROR" >nul
	if !errorlevel! == 0 (
		title [SearchEngine]
	) else (
		echo [+] %%a
		echo %%a >> "./Доступ_сервисы.txt"
		reg delete "%%a" /v TestKey /f >nul 2>&1
	)  
    ) else (
      echo [X] %%a 
    )
  )
  echo.
)

echo Настройки аудита 
(reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /s 2>nul) > "./Аудит_Настройка.txt"

echo События аудита
(reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" /s 2>nul) > "./Аудит_События.txt"

echo Политика AdmPwd LAPS (Local Administrator Password Solution)
(reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd" /s 2>nul) > "./AdmPwd.txt"

echo Расположение резервной копии LAPS
(reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Policies\LAPS" /v BackupDirectory 2>nul) > "./BackupDirectory.txt"
(reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS" /v BackupDirectory 2>nul) >> "./BackupDirectory.txt"

echo LSA (Local Security Authority)
(reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /s 2>nul) > "./ LSA.txt"

echo Гостевой вхож
(reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "ForceGuest" 2>nul) > "./Гость.txt"

echo Защита LSA
(reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL 2>nul) > "./Защита_LSA.txt"

echo Состояние Credential Guard
(reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" /v LsaCfgFlags 2>nul) > "./ Credential_Guard.txt"

echo Состояние WDigest
(reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential" 2>nul) > "./WDigest.txt"

echo Winlogon
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul) > "./ Winlogon_Full.txt"

echo Количество кэшированных учетных данных
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CACHEDLOGONSCOUNT 2>nul) > "./ Winlogon_count.txt"

echo UAC (User Account Control)
(reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul) > "./UAC.txt"

echo Настройки UAC 
(reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul) > "./UAC_настройки.txt"

echo Данные PowerShell
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /s 2>nul) > "./PowerShell_данные.txt"
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine" /s 2>nul) >> "./PowerShell_данные.txt"

echo Настройки PowerShell
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /s 2>nul) > "./PowerShell_настройки.txt"
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /s 2>nul) >> "./PowerShell_настройки.txt"
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /s 2>nul) >> "./PowerShell_настройки.txt"

echo Поиск ПО
(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul) > "./ПО.txt"
(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s 2>nul) >> "./ПО.txt"

echo Настройки WSUS (Windows Server Update Services) 
(reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" /s 2>nul) > "./WSUS.txt"

echo Автозагрузка
(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s 2>nul) > "./Автозагрузка.txt"
(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /s 2>nul) >> "./Автозагрузка.txt"
(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce " /s 2>nul) > "./Автозагрузка_ONCE.txt"
(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce " /s 2>nul) >> "./Автозагрузка_ONCE.txt"

echo Привелегии msi
(reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2> nul) > "./MSI.txt"
(reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2> nul) >> "./MSI.txt"
(reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated" /s 2> nul) >> "./MSI.txt"
(reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated" /s 2> nul) >> "./MSI.txt"

echo Поиск захардваренных паролей
(reg query "HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4" /v password 2>nul) >> "./Креды.txt"
(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername") >> "./Креды.txt"
(reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s 2>nul) >> "./Креды.txt"
(reg query "HKCU\Software\TightVNC\Server" 2>nul) >> "./Креды.txt"
(reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul) >> "./Креды.txt"
(reg query "HKCU\Software\OpenSSH\Agent\Keys" /s 2>nul) >> "./Креды.txt"

echo Данные об оболочке
(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /s 2> nul) >> "./Оболочка.txt"

echo Предопределения dll
(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s 2> nul) >> "./dll.txt"


:skip_reg

echo ===============================
echo.
echo Подготовка к третьему этапу (3 сек.)
timeout /t 3 >nul
cd .. 
md security
cd security 
set "home=%CD%"
cls

echo Имя:    [%folder%] 
echo Начало: [%starttime%]
echo Статус: [3\4]
echo Работа: [Дополнительная информация]
echo ===============================

echo Отсутствие хотфиксов

for %%i in (
KB977165:"MS10-015; 2K, XP, 2K3, 2K8, Vista, 7 - User Mode to Ring"
KB941693:"MS08-025; 2K/SP4, XP/SP2, 2K3/SP1/2, 2K8/SP0, Vista/SP0/1 - win32k.sys"
KB920958:"MS06-049; 2K/SP4 - ZwQuerySysInfo"
KB914389:"MS06-030; 2K,XP/SP2 - Mrxsmb.sys"
KB908523:"MS05-055; 2K/SP4 - APC Data-Free"
KB890859:"MS05-018; 2K/SP3/4, XP/SP1/2 - CSRSS"
KB842526:"MS04-019; 2K/SP2/3/4 - Utility Manager"
KB835732:"MS04-011; 2K/SP2/3/4, XP/SP0/1 - LSASS service BoF"
KB841872:"MS04-020; 2K/SP4 - POSIX"
KB982799:"MS10-059; 2K8, Vista, 7/SP0 - Chimichurri"
KB979683:"MS10-021; 2K/SP4, XP/SP2/3, 2K3/SP2, 2K8/SP2, Vista/SP0/1/2, 7/SP0 - Win Kernel"
KB981957:"MS10-073; XP/SP2/3, 2K3/SP2/2K8/SP2, Vista/SP1/2, 7/SP0 - Keyboard Layout"
KB2592799:"MS11-080; XP/SP3, 2K3/SP3 - afd.sys"
KB3143141:"MS16-032; 2K8/SP1/2, Vista/SP2, 7/SP1 - secondary logon"
KB2393802:"MS11-011; XP/SP2/3, 2K3/SP2, 2K8/SP2, Vista/SP1/2, 7/SP0 - WmiTraceMessageVa"
KB2305420:"MS10-092; 2K8/SP0/1/2, Vista/SP1/2, 7/SP0 - Task Sched"
KB4013081:"MS17-017; 2K8/SP2, Vista/SP2, 7/SP1 - Registry Hive Loading"
KB2975684:"MS14-040; 2K3/SP2, 2K8/SP2, Vista/SP2, 7/SP1 - afd.sys Dangling Pointer"
KB3136041:"MS16-016; 2K8/SP1/2, Vista/SP2, 7/SP1 - WebDAV to Addres"
KB3057191:"MS15-051; 2K3/SP2, 2K8/SP2, Vista/SP2, 7/SP1 - win32k.sys"
KB2989935:"MS14-070; 2K3/SP2 - TCP/IP"
KB2850851:"7SP0/SP1_x86 - schlamperei"
KB2870008:"7SP0/SP1_x86 - track_popup_menu"
KB2778930:"Vista, 7, 8, 2008, 2008R2, 2012, RT - hwnd_broadcast"
) do (
  for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
    
	wmic qfe get HotFixID | findstr /C:"%%a" 1>nul
	if !errorlevel! equ 0 (
		echo [-] %%a
	) else (
		echo [+] %%a - %%b
		echo %%a - %%b >> "./Отсутствие_исправлений.txt"
	)
  )
)

echo Проверка прав доступа к файлам процессов
for /f "tokens=2 delims==" %%x in ('wmic process list full ^| find /i "executablepath" ^| find /i /v "system32" ^| find ":"') do (
    for /f eol^=^"^ delims^=^" %%z in ('echo.%%x') do (
        (icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%") >> "./Процессы_подр".txt
        if %ERRORLEVEL% EQU 0 echo. %%z >> "./Процессы_кратк".txt 
    )
)
for /f "tokens=2 delims==" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
    for /f "tokens=* delims=" %%y in ('echo.%%x') do (
        icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" >> "./Процессы2_подр".txt
        if %errorlevel% EQU 0  echo %%~dpy >> "./Процессы2_кратк".txt 
    )
)

echo Права доступа к файлам служб
for /f "tokens=2 delims='='" %%a in ('cmd.exe /c wmic service list full ^| findstr /i "pathname" ^|findstr /i /v "system32"') do (
    for /f eol^=^"^ delims^=^" %%b in ("%%a") do (
	(icacls "%%b" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos usuarios %username%" 2>nul) >> "./Файлы_служб.txt"
	)
)

echo Поиск служб с неквотированными путями к исполняемым файлам
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
		ECHO.%%~s ^| findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 
		(ECHO.%%n && ECHO.%%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") >> "./Службы_неквота.txt"
	)
)

echo Проверка прав доступа к файлам в переменной среды PATH
for %%A in ("%path:;=";"%") do ( 
(cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") >> "./Права_Path.txt"
)

echo ===============================
echo.
echo Подготовка к четвёртому этапу (3 сек.)
timeout /t 3 >nul
cd .. 
md files
cd files
cls 
set "home=%CD%" 
rem > "%home%\\test.txt"

echo Имя:    [%folder%] 
echo Начало: [%starttime%]
echo Статус: [4\4]
echo Работа: [Чувствительные данные]
echo ===============================

echo Проверяем Credentials в аппдате
dir /b/a %appdata%\Microsoft\Credentials\ > "./Credentials_Appdata.txt"
dir /b/a %localappdata%\Microsoft\Credentials\ >> "./Credentials_Appdata.txt"

echo Изучаем файлы интереса
for %%i in (
%SystemRoot%\System32\drivers\etc\hosts@hosts.txt
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt@ConsoleHost_history.txt
) do (
  for /f "tokens=1,2 delims=@" %%a in ("%%i") do (
  if exist "%%a" (
    echo Читаем %%a
    echo %%a  > "%home%\%%b"
  ) else (
    echo Не нашли %%a
  )
  )
)



echo Сортируем Program Files
(dir /b "C:\Program Files" "C:\Program Files (x86)" | sort) > "%home%\\Program_Files.txt"

echo Истррия транскриптов
(dir %SystemDrive%\transcripts\ 2>nul) > "./transcripts.txt"


echo Проверяем SystemDrive
cd "%SystemDrive%\Microsoft\Group Policy\history"
for %%i in (
Groups.xml:SD_Groups_xml.txt
Services.xml:SD_Services_xml.txt
Scheduledtasks.xml:SD_Scheduledtasks_xml.txt
DataSources.xml:SD_DataSources_xml.txt
Printers.xml:SD_Printers_xml.txt
Drives.xml:SD_Drives.txt
) do (
	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b "*%%a" 2>nul) > "%home%\%%b"
  )
)

echo Групповые политики
cd "%windir%\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
for %%i in (
Groups.xml:GP_Groups_xml.txt
Services.xml:GP_Services_xml.txt
Scheduledtasks.xml:GP_Scheduledtasks_xml.txt
DataSources.xml:GP_DataSources_xml.txt
Printers.xml:GP_Printers_xml.txt
Drives.xml:GP_Drives.txt
) do (
	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b "*%%a" 2>nul) > "%home%\%%b"
  )
)

echo Креды в юзерах
cd "%SystemDrive%\Users"
for %%i in (
.aws:USR_aws.txt
credentials:USR_credentials.txt
gcloud:USR_gcloud.txt
credentials.db:USR_credentials.db.txt
legacy_credentials:USR_legacy_credentials.txt
access_tokens.db:USR_access_tokens.db.txt
.azure:USR_azure.txt
accessTokens.json:USR_accessTokens_json.txt
azureProfile.json:USR_azureProfile_json.txt
) do (
	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b "*%%a" 2>nul) > "%home%\%%b"
  )
)

echo Креды в корне документов
cd "%windir%\..\Documents and Settings"
for %%i in (
.aws:DaS_aws.txt
credentials:DaS_credentials.txt
gcloud:DaS_gcloud.txt
credentials.db:DaS_credentials.db.txt
legacy_credentials:DaS_legacy_credentials.txt
access_tokens.db:DaS_access_tokens.db.txt
.azure:DaS_azure.txt
accessTokens.json:DaS_accessTokens_json.txt
azureProfile.json:DaS_azureProfile_json.txt
) do (
	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b "*%%a" 2>nul) > "%home%\%%b"
  )
)

cd \
echo Поиск по имени файла
for %%i in (
RDCMan.settings:RDCMan.txt
SCClient.exe:SCClient.txt
.sudo_as_admin_successful:sudo_as_admin_successful.txt
.profile:profile.txt
httpd.conf:httpd_conf.txt
.htpasswd:htpasswd.txt
.git-credentials:git_credentials.txt
hosts.equiv:hosts_equiv.txt
Dockerfile:Dockerfile.txt
docker-compose.yml:docker_compose.txt
appcmd.exe:appcmd.txt
TypedURLs:TypedURLs.txt
TypedURLsTime:TypedURLsTime.txt
History:History.txt
Bookmarks:Bookmarks.txt
Cookies:Cookies.txt
"Login Data":Login_Data.txt
places.sqlite:places.txt
key3.db:key3.txt
key4.db:key4.txt
credentials:credentials.txt
credentials.db:credentials_db.txt
access_tokens.db:access_tokens.txt
accessTokens.json:accessTokens.txt
legacy_credentials:legacy_credentials.txt
azureProfile.json:azureProfile.txt
unattend.txt:unattend.txt
access.log:access_log.txt
error.log:error_log.txt
known_hosts:known_hosts.txt
id_rsa:id_rsa.txt
id_dsa:id_dsa.txt
anaconda-ks.cfg:anaconda_ks.txt
hostapd.conf:hostapd.txt
rsyncd.conf:rsyncd.txt
cesi.conf:cesi.txt
supervisord.conf:supervisord.txt
tomcat-users.xml:tomcat_users.txt
KeePass.config:KeePass.txt
Ntds.dit:Ntds.txt
SAM:SAM.txt
SYSTEM:SYSTEM.txt
FreeSSHDservice.ini:FreeSSHDservice.txt
sysprep.inf:sysprep_inf.txt
sysprep.xml:sysprep_xml.txt
unattend.xml:unattend_xml.txt
unattended.xml:unattended_xml.txt
groups.xml:groups.txt
services.xml:services.txt
scheduledtasks.xml:scheduledtasks.txt
printers.xml:printers.txt
drives.xml:drives.txt
datasources.xml:datasources.txt
php.ini:php.txt
https.conf:https_conf.txt
https-xampp.conf:https_xampp_conf.txt
httpd.conf:httpd_conf2.txt
my.ini:my_ini.txt
my.cnf:my_cnf.txt
access.log:access_log2.txt
error.log:error_log2.txt
server.xml:server.txt
SiteList.xml:SiteList.txt
ConsoleHost_history.txt:ConsoleHost_history.txt
setupinfo:setupinfo.txt
setupinfo.bak:setupinfo_bak.txt
web.config:web_config.txt
) do (

	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b /A:-D %%a 2>nul) > "%home%\%%b"
  )
)

echo Поиск по расширениям
for %%i in (
.rdg:rdg_files.txt
_history:history_files.txt
bashrc:bashrc_files.txt
.plan:plan_files.txt
.rhosts:rhosts_files.txt
.ovpn:ovpn_files.txt
.kdbx:kdbx_files.txt
.p12:p12_files.txt
.der:der_files.txt
.csr:csr_files.txt
.cer:cer_files.txt
.gpg:gpg_files.txt
.pgp:pgp_files.txt
.config:config_files.txt
.cfg:cfg_files.txt
.log:log_files.txt
.bak:bak_files.txt
.db:db_files.txt
) do (
	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b /A:-D "*%%a" 2>nul) > "%home%\%%b"
  )
)


echo Поиск по вхождениям
for %%i in (
pass:pass_infiles.txt
cred:cred_infiles.txt
vnc:vnc_infiles.txt
password:password_infiles.txt
credential:credential_infiles.txt
config:config_infiles.txt
ssh:ssh_infiles.txt
elasticsearch:elasticsearch_infiles.txt
) do (
	for /f "tokens=1,2 delims=:" %%a in ("%%i") do (
	echo Ищем %%a
	(dir /s /b /A:-D "*%%a*" 2>nul) > "%home%\%%b"
  )
)

rem Я б с радостью сделал список, но оно не работает с символами типа *. Мб потом разделю, посмотрим
(dir /s /b /A:-D *vnc*.ini 2>nul) > "%home%\vnc_ini.txt"
(dir /s /b /A:-D *vnc*.c*nf* 2>nul) > "%home%\vnc_configs.txt"
(dir /s /b /A:-D *vnc*.txt 2>nul) > "%home%\vnc_txt.txt"
(dir /s /b /A:-D *vnc*.xml 2>nul) > "%home%\vnc_xml.txt"
(dir /s /b /A:-D *config*.php 2>nul) > "%home%\config_php.txt"
(dir /s /b /A:-D elasticsearch.y*ml 2>nul) > "%home%\elasticsearch.y_ml.txt"
(dir /s /b /A:-D kibana.y*ml 2>nul) > "%home%\kibana_yml.txt"


echo Файлы интереса
for %%K in (
%WINDIR%\sysprep\sysprep.xml
%WINDIR%\sysprep\sysprep.inf
%WINDIR%\sysprep.inf
%WINDIR%\Panther\Unattended.xml
%WINDIR%\Panther\Unattend.xml
%WINDIR%\Panther\Unattend\Unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\System32\Sysprep\unattend.xml
%WINDIR%\System32\Sysprep\unattended.xml
%WINDIR%..\unattend.txt
%WINDIR%..\unattend.inf
%WINDIR%\repair\SAM
%WINDIR%\System32\config\RegBack\SAM
%WINDIR%\System32\config\SAM
%WINDIR%\repair\SYSTEM
%WINDIR%\System32\config\SYSTEM
%WINDIR%\System32\config\RegBack\SYSTEM
%WINDIR%\Windows\appcompat\appcompat.txt
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\boot.ini
) do (
  if exist "%%K" (
    echo [+] %%K
	echo %%K >> "./Файлы_интереса.txt"
  ) else (
    echo [-] %%K
  )
)

echo Файлы интереса
for %%K in (
"C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
"C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
"%programdata%\Microsoft\Windows\Start Menu\Programs\Startup"
"%appdata%\Microsoft\Windows\Start Menu\Programs\Startup"
"%SystemDrive%\transcripts\"
) do (
  if exist "%%K" (
    echo [+] %%K
	dir /A %%K >> "./Папки_интереса.txt"
  ) else (
    echo [-] %%K
  )
)

cd %home%\..
cls
echo Имя:    [%folder%] 
echo Начало: [%starttime%]
echo Конец:  [%time%]
echo Статус: [Очистка]
echo ==============================
for /f "delims=" %%i in ('2^>nul dir/ad/b') do (
 for /f "delims=" %%j in ('2^>nul dir/a-d/b/s "%%i"') do (
  if %%~zj equ 0 del/a/f "%%j"&& set f=%%j&& (
   cmd/v/c echo [-] !f:*%CD%\=!
   cmd/v/c echo !f:*%CD%\=! >> "./Error_log.txt"
  )
 )
)
timeout /t 4 >nul

cls
echo Имя:    [%folder%] 
echo Начало: [%starttime%]
echo Конец:  [%time%]
echo Статус: [Готово]
pause

endlocal