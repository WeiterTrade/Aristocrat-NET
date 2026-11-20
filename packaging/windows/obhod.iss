; Установщик Aristocrat NET для Windows 7, 8, 8.1, 10, 11 (x86 и x64) — Inno Setup 6.2.
; Сборка: ISCC.exe /DVERSION=1.0.0 /DVIVERSION=1.0.0.0 /DSRC=<папка со сборкой> obhod.iss
;   SRC\Obhod.exe, SRC\README.txt, SRC\obhod.ico
;   SRC\tor-legacy\  — Tor 13.5.x (последний с поддержкой Windows 7/8)
;   SRC\tor-modern\  — актуальный Tor (Windows 10+); файл ARCH_x64 — если сборка только 64-битная
; Inno Setup 6.2.2 — последняя версия, установщик которой работает на Windows 7.

#ifndef VERSION
  #define VERSION "0.0.0"
#endif
#ifndef VIVERSION
  #define VIVERSION "0.0.0.0"
#endif
#ifndef SRC
  #define SRC "..\..\build\win"
#endif
#define ASSETS "..\..\assets"
; /DDEV=1 — установщик сборки разработчика (раздача интернета); ставится только на компьютер разработчика.
; /DEDWARD=1 — установщик Edward Version (с маршрутом «Ебаная Чукотка»).
#ifdef DEV
  #define SETUPNAME "AristocratNET-Dev-Setup"
  #define VERNAME "Aristocrat NET " + VERSION + " (разработчик)"
#elif defined(EDWARD)
  #define SETUPNAME "AristocratNET-Edward-Setup"
  #define VERNAME "Aristocrat NET " + VERSION + " Edward Version"
#else
  #define SETUPNAME "AristocratNET-Setup"
  #define VERNAME "Aristocrat NET " + VERSION
#endif

[Setup]
AppId=AristocratNET
AppName=Aristocrat NET
AppVersion={#VERSION}
AppVerName={#VERNAME}
AppPublisher=Aristocrat NET
AppCopyright=Aristocrat (в своём кругу — Старый)
VersionInfoVersion={#VIVERSION}
VersionInfoProductName=Aristocrat NET
VersionInfoDescription=Установка Aristocrat NET
DefaultDirName={autopf}\Obhod
DefaultGroupName=Aristocrat NET
DisableProgramGroupPage=yes
DisableDirPage=auto
DisableWelcomePage=yes
PrivilegesRequired=admin
MinVersion=6.1sp1
OutputDir=.
OutputBaseFilename={#SETUPNAME}-{#VERSION}
SetupIconFile={#SRC}\obhod.ico
UninstallDisplayIcon={app}\obhod.ico
UninstallDisplayName=Aristocrat NET
WizardStyle=modern
WizardSmallImageFile={#ASSETS}\wizard-small-55.bmp,{#ASSETS}\wizard-small-64.bmp,{#ASSETS}\wizard-small-69.bmp,{#ASSETS}\wizard-small-83.bmp,{#ASSETS}\wizard-small-92.bmp,{#ASSETS}\wizard-small-110.bmp,{#ASSETS}\wizard-small-138.bmp
WizardImageFile={#ASSETS}\wizard-164.bmp,{#ASSETS}\wizard-192.bmp,{#ASSETS}\wizard-246.bmp,{#ASSETS}\wizard-328.bmp
Compression=lzma2/max
SolidCompression=yes
CloseApplications=no

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "startmenu"; Description: "Добавить ярлык в меню «Пуск»"; GroupDescription: "Ярлыки:"
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Ярлыки:"

[Files]
Source: "{#SRC}\Obhod.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SRC}\README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SRC}\obhod.ico"; DestDir: "{app}"; Flags: ignoreversion
; Tor: на Windows 10+ — актуальный, на 7/8/8.1 — ветка 13.5 (новые сборки там не запускаются).
Source: "{#SRC}\tor-modern\*"; DestDir: "{app}\tor"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: UseModernTor
Source: "{#SRC}\tor-legacy\*"; DestDir: "{app}\tor"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: not UseModernTor

[InstallDelete]
Type: filesandordirs; Name: "{app}\tor"

[Icons]
Name: "{autoprograms}\Aristocrat NET"; Filename: "{app}\Obhod.exe"; IconFilename: "{app}\obhod.ico"; Tasks: startmenu
Name: "{autodesktop}\Aristocrat NET"; Filename: "{app}\Obhod.exe"; IconFilename: "{app}\obhod.ico"; Tasks: desktopicon

[Run]
; Входящие подключения к программе — разрешить в брандмауэре: раздача интернета устройствам сети
; (порт 8282), а в сборке разработчика — и раздача «Ебаная Чукотка» (белый IP).
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Aristocrat NET (раздача)"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Aristocrat NET (раздача)"" dir=in action=allow program=""{app}\Obhod.exe"" enable=yes profile=any"; Flags: runhidden
Filename: "{app}\Obhod.exe"; Description: "Запустить Aristocrat NET"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM Obhod.exe"; Flags: runhidden; RunOnceId: "KillObhod"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Aristocrat NET (раздача)"""; Flags: runhidden; RunOnceId: "DelFirewall"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\tor"

[Code]
function UseModernTor: Boolean;
begin
  Result := GetWindowsVersion >= $0A000000;
#ifexist SRC + "\tor-modern\ARCH_x64"
  Result := Result and IsWin64;
#endif
end;

procedure KillRunning;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Obhod.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(500);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  KillRunning;
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Прежний установщик (NSIS): его запись в «Программах и компонентах», деинсталлятор и ярлыки.
    RegDeleteKeyIncludingSubkeys(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Obhod');
    RegDeleteKeyIncludingSubkeys(HKLM, 'Software\Obhod');
    DeleteFile(ExpandConstant('{app}\uninstall.exe'));
    DelTree(ExpandConstant('{commonprograms}\Aristocrat NET'), True, True, True);
    DelTree(ExpandConstant('{commonprograms}\Обход'), True, True, True);
    DeleteFile(ExpandConstant('{commondesktop}\Обход.lnk'));
    if not WizardIsTaskSelected('desktopicon') then
      DeleteFile(ExpandConstant('{commondesktop}\Aristocrat NET.lnk'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Proxy: String;
begin
  // Выключить системный прокси, если он остался указывать на программу.
  if CurUninstallStep = usUninstall then
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyServer', Proxy) then
      if Proxy = '127.0.0.1:8881' then
        RegWriteDWordValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Internet Settings', 'ProxyEnable', 0);
end;
