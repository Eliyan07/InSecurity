!macro NSIS_HOOK_PREUNINSTALL
  ; The app auto-generates YARA signature sidecar files next to bundled rules
  ; on first run, so remove those before the default NSIS uninstall cleanup.
  Delete "$INSTDIR\resources\yara_rules\heuristic\*.yar.sig"
  Delete "$INSTDIR\resources\yara_rules\strict\*.yar.sig"

  ; Remove legacy Python bundle layouts from older installs. New builds no
  ; longer ship a Python runtime, but these directories may still exist after
  ; upgrading from previous versions.
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\resources\python"
  RMDir /r "$INSTDIR\resources\python_runtime"
!macroend
