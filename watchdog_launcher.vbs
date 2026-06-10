Option Explicit

Dim WshShell
Dim FileSystem
Dim ScriptDir

Set WshShell = CreateObject("WScript.Shell")
Set FileSystem = CreateObject("Scripting.FileSystemObject")

ScriptDir = FileSystem.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = ScriptDir
WshShell.Run """" & ScriptDir & "\start_watchdog.bat" & """", 0, False
