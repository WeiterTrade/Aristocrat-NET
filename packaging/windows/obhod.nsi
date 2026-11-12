; Установщик «Обход» для Windows 7, 8, 8.1, 10, 11 (x86 и x64).
; Сборка: makensis -DVERSION=1.0.0 -DVIVERSION=1.0.0.0 -DSRC=<папка со сборкой> obhod.nsi
;   SRC/Obhod.exe, SRC/README.txt, SRC/obhod.ico
;   SRC/tor-legacy/  — Tor 13.5.x (последний с поддержкой Windows 7/8)
;   SRC/tor-modern/  — актуальный Tor (Windows 10+); файл ARCH_x64 — если сборка только 64-битная
Unicode true
SetCompressor /SOLID lzma

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef VIVERSION
  !define VIVERSION "0.0.0.0"
!endif
!ifndef SRC
  !define SRC "build"
!endif

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinVer.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

Name "Обход ${VERSION}"
OutFile "Obhod-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES\Obhod"
InstallDirRegKey HKLM "Software\Obhod" "InstallDir"
RequestExecutionLevel admin
BrandingText "Обход ${VERSION}"

!define MUI_ICON "${SRC}/obhod.ico"
!define MUI_UNICON "${SRC}/obhod.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\Obhod.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить «Обход»"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

VIProductVersion "${VIVERSION}"
VIAddVersionKey /LANG=${LANG_RUSSIAN} "ProductName" "Обход"
VIAddVersionKey /LANG=${LANG_RUSSIAN} "FileDescription" "Обход блокировок: DPI + Tor"
VIAddVersionKey /LANG=${LANG_RUSSIAN} "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_RUSSIAN} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_RUSSIAN} "LegalCopyright" "MIT"

Var ModernArch

Function .onInit
  ${IfNot} ${AtLeastWin7}
    MessageBox MB_ICONSTOP "Нужна Windows 7 или новее."
    Abort
  ${EndIf}
FunctionEnd

Section "Обход" SecMain
  SectionIn RO
  ; Остановить запущенную копию, чтобы заменить файлы.
  nsExec::Exec 'taskkill /F /IM Obhod.exe'
  Pop $0
  Sleep 500
  SetShellVarContext all

  SetOutPath "$INSTDIR"
  File "${SRC}/Obhod.exe"
  File "${SRC}/README.txt"
  File "${SRC}/obhod.ico"

  ; Tor: на Windows 10+ — актуальный, на 7/8/8.1 — ветка 13.5 (новые сборки там не запускаются).
  RMDir /r "$INSTDIR\tor"
  SetOutPath "$INSTDIR\tor"
  StrCpy $ModernArch "x86"
  !if /FileExists "${SRC}/tor-modern/ARCH_x64"
    StrCpy $ModernArch "x64"
  !endif
  ${If} ${AtLeastWin10}
  ${AndIf} $ModernArch == "x86"
    File /r "${SRC}/tor-modern/*"
  ${ElseIf} ${AtLeastWin10}
  ${AndIf} ${RunningX64}
    File /r "${SRC}/tor-modern/*"
  ${Else}
    File /r "${SRC}/tor-legacy/*"
  ${EndIf}

  ; Ярлыки
  SetOutPath "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\Обход"
  CreateShortcut "$SMPROGRAMS\Обход\Обход.lnk" "$INSTDIR\Obhod.exe" "" "$INSTDIR\obhod.ico"
  CreateShortcut "$SMPROGRAMS\Обход\Удалить «Обход».lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\Обход.lnk" "$INSTDIR\Obhod.exe" "" "$INSTDIR\obhod.ico"

  ; Удаление через «Программы и компоненты»
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Obhod" "InstallDir" "$INSTDIR"
  !define UNKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Obhod"
  WriteRegStr HKLM "${UNKEY}" "DisplayName" "Обход"
  WriteRegStr HKLM "${UNKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNKEY}" "Publisher" "Obhod"
  WriteRegStr HKLM "${UNKEY}" "DisplayIcon" "$INSTDIR\obhod.ico"
  WriteRegStr HKLM "${UNKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNKEY}" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "${UNKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNKEY}" "EstimatedSize" "$0"
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /F /IM Obhod.exe'
  Pop $0
  Sleep 500
  SetShellVarContext all
  ; Выключить системный прокси, если он остался указывать на «Обход».
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
  ${If} $0 == "127.0.0.1:8881"
    WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
  ${EndIf}
  Delete "$DESKTOP\Обход.lnk"
  RMDir /r "$SMPROGRAMS\Обход"
  RMDir /r "$INSTDIR\tor"
  Delete "$INSTDIR\Obhod.exe"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\obhod.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Obhod"
  DeleteRegKey HKLM "Software\Obhod"
SectionEnd
