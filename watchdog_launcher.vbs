Option Explicit

Dim WshShell
Dim FileSystem
Dim ScriptDir
Dim EnvPath
Dim DashboardPort
Dim ShouldOpenDashboard

Set WshShell = CreateObject("WScript.Shell")
Set FileSystem = CreateObject("Scripting.FileSystemObject")

ScriptDir = FileSystem.GetParentFolderName(WScript.ScriptFullName)
EnvPath = ScriptDir & "\.env"
DashboardPort = ReadEnvValue(EnvPath, "YUBIWATCH_DASHBOARD_PORT", "8765")
ShouldOpenDashboard = EnvBool(ReadEnvValue(EnvPath, "YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP", "false"))

If ShouldOpenDashboard Then
    WshShell.Environment("PROCESS")("YUBIWATCH_STARTUP_BROWSER_HANDLED") = "1"
End If

WshShell.Run """" & ScriptDir & "\start_watchdog.bat" & """", 0, False

If ShouldOpenDashboard Then
    WScript.Sleep 3000
    WshShell.Run "http://127.0.0.1:" & DashboardPort & "/", 1, False
End If

Function ReadEnvValue(Path, Key, DefaultValue)
    Dim FileHandle
    Dim Line
    Dim Position
    Dim Name
    Dim Value

    ReadEnvValue = DefaultValue
    If Not FileSystem.FileExists(Path) Then
        Exit Function
    End If

    Set FileHandle = FileSystem.OpenTextFile(Path, 1, False)
    Do Until FileHandle.AtEndOfStream
        Line = Trim(FileHandle.ReadLine)
        If Len(Line) > 0 And Left(Line, 1) <> "#" Then
            Position = InStr(Line, "=")
            If Position > 1 Then
                Name = Trim(Left(Line, Position - 1))
                Value = Trim(Mid(Line, Position + 1))
                If UCase(Name) = UCase(Key) Then
                    ReadEnvValue = StripQuotes(Value)
                    FileHandle.Close
                    Exit Function
                End If
            End If
        End If
    Loop
    FileHandle.Close
End Function

Function StripQuotes(Value)
    Value = Trim(Value)
    If Len(Value) >= 2 Then
        If (Left(Value, 1) = """" And Right(Value, 1) = """") _
            Or (Left(Value, 1) = "'" And Right(Value, 1) = "'") Then
            StripQuotes = Mid(Value, 2, Len(Value) - 2)
            Exit Function
        End If
    End If
    StripQuotes = Value
End Function

Function EnvBool(Value)
    Select Case LCase(Trim(Value))
        Case "1", "true", "yes", "y", "on"
            EnvBool = True
        Case Else
            EnvBool = False
    End Select
End Function
