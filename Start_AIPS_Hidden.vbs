Set FSO = CreateObject("Scripting.FileSystemObject")
strPath = FSO.GetParentFolderName(WScript.ScriptFullName)

Set objShell = CreateObject("Shell.Application")
' 0 means hidden window
objShell.ShellExecute "cmd.exe", "/c """ & strPath & "\run_hidden.bat""", "", "runas", 0
