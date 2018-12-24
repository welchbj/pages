---
title: windows basics
description: windows utilities and internals
published_at: 2018-12-23
last_modified_at: 2018-12-23
---

# Windows Commands, Scripting, and (Very) Basic Internals

Kahoot ***is not*** a game.

## `cmd.exe` / batch scripting basics

### Redirection operators

* `>` - redirect STDOUT by creating / overwriting its destination
* `>>` - redirect STDOUT by creating / appending to its destination
* `|` - pipe output of one command to another

### Conditional processing

* `&` and `;` - execute second command regardless of success/failure of first
* `&&` - execute second command *only if* the first is successful (i.e., zero exit code)
* `||` - execute second command *only if* the first fails (i.e., non-zero exit code)

### Nesting commands

* `(` and `)` - nest commands for complex arrangement

### Argument expansion

Note that these can be combined (i.e., `%~dp1` expands to a drive letter and path only).

| Variable | Expansion |
| -------- | --------- |
| `%*` | all arguments (`%1`, `%2`, etc.) |
| `%~1` | remove any surrounding quotes |
| `%~f1` | fully qualified path name |
| `%~d1` | drive letter only |
| `%~p1` | path only |
| `%~n1` | file name only |
| `%~x1` | file extensions only |
| `%~s1` | expanded path contains short names only |
| `%~a1` | file attributes |
| `%~t1` | date/time of the file |
| `%~z1` | size of the file |
| `%~$PATH:1` | searches the directories listed in the `PATH` environment variable and expands `%1` to the fully qualified name of the first one found |

### Environment variable subsitution

Batch has support for expansion of variables to include subsitution and sub-string operations.

```bat
:: expand PATH with all instances of str1 replaced with str2
%PATH:str1=str2%

:: expand PATH with all instances of str1 removed
%PATH:str1=%

:: extract the 5 characters that begin at the 11th (offset 10) character of
:: PATH
%PATH:~10,5%

:: extract the last 10 characters of PATH
%PATH:~-10%

:: extract all but the last 2 characters of PATH
%PATH:~0,-2%
```


## Internal `cmd.exe` commands

These commands are native to the `cmd.exe` program. In other words, there is no executable on the system that corresponds to the command. They are interpreted by your shell session and executed as subroutines defined with `cmd.exe`. For more information, use `cmd.exe /?` and checkout the [fantastic SS64 reference](https://ss64.com/nt/syntax-internal.html).

### `assoc`

Display and modify file extension associations. It is important to note that a `cmd.exe` shell can be started without Command Extensions enabled (via either the `/E:OFF` or `/Y` options), in which case `assoc` will not function.

```bat
:: view all file associations
assoc

:: simple example of viewing .doc extension associations
$ assoc .doc
.doc=Word.Document.8

:: add a file association; this example is already the default for .txt files
assoc .txt=txtfile

:: delete a file association (please don't actually run the below command on a
:: system you care about)
assoc .txt=
```

### `break`

An old DOS utility for for setting or clearing CTRL+C checking. Has no effect on Windows.

### `call`

Call one batch program from another. Also accepts labels for calling subroutines defined within the same batch file. This will result in a new batch context being created with the specified arguments being passed to the new context. The parent batch program pauses during the execution of the called program. See the [SS64 call reference](https://ss64.com/nt/call.html) for more advanced usage examples and features.

Notes:

* You should always end subroutines with `exit /b` or `goto :eof` (which accomplish the same thing) in order to return to the original `call` position
* The `&`, `|`, and `<>` operators are quite buggy when used in conjunction with `call`
* Avoid variable namespacing conflicts with the `setlocal` and `endlocal` commands

```bat
:: example of calling a separate batch program
@echo off
call my_other_function_that_accepts_an_argument.bat 10
echo Came back from the call

:: example of a subroutine-calling batch script
@echo off
call :echoer_subroutine hello
call :echoer_subroutine goodbye
echo Did you see my message?
goto :eof

:echoer_subroutine
echo You wanted to print %1
exit /b
```

### `cd` / `chdir`

Display the name or change the current directory.

```bat
:: print the current directory
cd

:: change directories within the current drive
cd \Users\brian

:: change directories across drives
cd /D Z:\mypath
```

### `cls`

Clears the screen.

### `color`

Set the default console foreground and background colors. The syntax of this command is `color <bg><fg>`, based on the codes in the below table.

| Code | Color |
| ---- | ----- |
| 0 | black |
| 1 | blue |
| 2 | green |
| 3 | aqua |
| 4 | red |
| 5 | purple |
| 6 | yellow |
| 7 | white |
| 8 | gray |
| 9 | light blue |
| a | light green |
| b | light aqua |
| c | light red |
| d | light purple |
| e | light yellow |
| f | bright white |

```bat
:: set the console colors to light red on bright white
color fc

:: restore colors to their state from cmd.exe start
color

:: set ERRORLEVEL to 1 by using the same fg and bg color
color 11
```

### `copy`

Copies one or more files to another location. Supports copying across drives. Important to note that this will copy in ASCII mode by default; use the `/B` option to perform a binary file copy that will include extended characters.

```bat
:: basic copying of files in the current directory
copy source.txt dest.txt

:: combine files into a destination
copy src1.txt + src2.txt + src3.txt dest.txt

:: specify the source only, which will copy into the current directory
copy "C:\my stuff\*.txt"

:: suppress prompting of overwriting a destination file
copy /y source.txt destthatexistsandimabouttooverwrite.txt

:: suppress feedback from the operation
copy source.txt dest.txt >nul
```

### `date`

Display or set the date.

```bat
:: display the date
date /t

:: set the date interactively
date

:: set the date to something very important
date 03/19/1996
```

### `del` / `erase`

Delete one or more files.

```bat
:: delete with a prompt before each file
del /p *.txt

:: force deletion of read-only files
del /f *.txt

:: recursive deletion with suppressed prompting
del /q /s mydir

:: delete based on file attributes; this example deletes hidden files
del /a:h *.txt
```

### `dpath`

An undocumented internal utility that allows the `type` command to read data files in specified directories as if they were in the current directory. The list of directories is held in the `DPATH` directory, which this command modifies.

```bat
:: a simple example of adding all PATH directories to the DPATH
$ type boot.ini
The system cannot find the file specified.
$ dpath %PATH%
$ type boot.ini
...
```

### `echo`

Print text, usually to the active console session.

```bat
:: show if echo is on or off
echo

:: print a string to stdout
echo Hey there, stdout

:: print a string to stderr
echo Hey there, stderr >&2

:: print a blank line
echo.

:: in a batch script file, display printing the echo command in the prompt
@echo off

:: show an environment variable (in this case, using a built-in variable)
echo %COMPUTERNAME%
```

### `exit`

Quit the `cmd.exe` program or the current batch script. Use the `/b` switch to exit the current batch script. The exit code can also be specified.

### `for`

Conditionally perform a command multiple times. Reference loop variables with `%%` in batch scripts and `%` from the command prompt. Note that loops will default to taking the first token from each line, which are separated via the `delims` keyword argument.

```bat
:: loop over files
for %g in (*.txt) do echo %g

:: loop over file contents
for /f %g in (*.txt) do echo %g

:: loop over numbers
$ for /l %g in (0,1,3) do echo %g
0
1
2
3

:: loop over command results line-by-line
for /f "tokens=*" %g in ('dir') do echo %g
```

### `ftype`

Used in conjunction with the `assoc` command to display or modify file types used in file extension associations. The `PATHEXT` environment variable allows for implicit extension identification.

```bat
:: configure execution of Perl scripts without specifying the perl.exe program
assoc .pl=PerlScript
ftype PerlScript=perl.exe %1 %*

:: we can now execute Perl scripts like this
script.pl 1 2 3
```

### `goto`

Direct `cmd.exe` execution flow to a labeled line in a batch program. The `:eof` label is an implicit reference to the end of the file.

### `if`

Conditional processing in batch programs.

Comparison operators:

| Operator | Meaning |
| -------- | ------- |
| `EQU` | equal |
| `NEQ` | not equal |
| `LSS` | less than |
| `LEQ` | less than or equal to |
| `GTR` | greater than |
| `GEQ` | greater than or equal to |

```bat
:: checking the error level; the below statements are equivalent
if ERRORLEVEL 1 An error was found
if %ERRORLEVEL% geq 1 An error was found
if %ERRORLEVEL% gtr 0 An error was found

:: case-sensitive string comparison
if Brian==Brian echo These strings are equal

:: case-insensitive string comparison
if /i brian==BRIAN echo These strings are equal

:: testing for an empty variable
if [%1] eq [] echo No argument present

:: testing for an undefined variable
if not defined MY_VAR echo The variable is not defined

:: if-else construct
if exist file.txt (
    echo Found the file
) else (
    echo Couldn't find the file
)
```

### `keys`

Enables or disables command-line editing on DOS systems and has no effect on Windows systems.

### `md` / `mkdir`

Creates a directory. When Command Extensions are enabled, these commands will also create intermediate directories in the specified path if they do not already exist.

```bat
:: this
mkdir \a\b\c\d

:: is the same as
mkdir \a
chdir \a
mkdir b
chdir b
mkdir c
chdir c
mkdir d
```

### `mklink`

Create a symbolic link. Defaults to creating a file symbolic link, use the `/d` option to create a directory symbolic link. See [the SS64 reference](https://ss64.com/nt/mklink.html) for information on the difference between shortcuts, hard links, soft links, and symbolic links.

```bat
:: a simple example of linking to an executable
mklink brian.exe \Windows\System32\notepad.exe
```

### `move`

Move and rename files and directories. Note that the source field may contain wildcards, but the destination cannot.

```bat
:: simple move within the same folder
move old.txt new.txt

:: suppress prompting to confirm you want to overwrite an existing file
move /y old.txt new.txt

:: moving across drives
move g:\old.txt c:\new.txt
```

### `path`

Modify or display the `PATH` environment variable.

```bat
:: display the current PATH variable
path

:: clear the current PATH configuration, which means only the current directory
:: will be searched
path ;

:: add a new drive to the PATH variable
path Z:;%PATH%
```

### `pause`

Pause the execution of a batch file by displaying the message `Press any key to continue...`.

```bat
:: display a custom message
echo Do you want to continue? Then press any key...
pause >nul
```

### `prompt`

Changes the `cmd.exe` prompt string to the specified text. See the [SS64 prompt page](https://ss64.com/nt/prompt.html) for a list of the available special codes.

### `pushd` / `popd`

Modify the "directory stack".

```bat
:: a simple example
C:\demo> pushd \work
C:\work> popd
C:\demo> pushd "F:\monthly reports"
F:\monthly reports> popd
C:\demo>
```

### `rem`

Mark a line as a comment or remark. Also of note that while `::` is commonly used as a comment, it is in fact a specially-treated blank label

```bat
:: comments can also be included inline and "jumped" around
goto :start

What we write here will not be executed or validated as batch syntax!

:start
rem The real program starts here
```

### `rd` / `rmdir`

Remove (i.e., delete) a directory.

```bat
:: quietly delete an entire directory tree
rmdir /s /q mydirectory
```

### `set`

Display, set, or remove `cmd.exe` environment variables. This can also be used to compute arithmetic/logical results via the following operators:

* Grouping - `(` and `)`
* Unary - `!`, `~`, and `-`
* Arithmetic - `*`, `/`, `%`, `+`, and `-`
* Bitwise - `>>`, `<<`, `&`, `^`, and `|`
* Assignment - `=`, `*=`, `/=`, `%=`, `+=`, `-=`, `&=`, `^=`, `|=`, `>>=`, and `<<=`

The following environment variables *will not* be displayed by `set` (although they still exist and are accessible by the user):

* `%CD%` - expands to the current directory string
* `%DATE%` - expands to current date using same format as DATE command
* `%TIME%` - expands to current time using same format as TIME command
* `%RANDOM%` - expands to a random decimal number between 0 and 32767
* `%ERRORLEVEL%` - expands to the current ERRORLEVEL value
* `%CMDEXTVERSION%` - expands to the current Command Processor Extensions version number
* `%CMDCMDLINE%` - expands to the original command line that invoked the Command Processor
* `%HIGHESTNUMANODENUMBER%` - expands to the highest NUMA node number on this machine

```bat
:: show all environment variables
set

:: show all environment variables beginning with A
set A

:: define a new variable
set MY_VAR=100

:: building a list via delayed expansion
set LIST=
for %i in (*) do set LIST=!LIST! %i

:: prompt the user for a variable definition
set /p PROMPT_VAR=Enter your variable...
```

### `setlocal` / `endlocal`

Begin / end localization of environment variables within a batch file. In other words, environment changes made after `setlocal` has been issued will be local to the batch file and not have an effect on the calling batch script's environment. There is an implicit `endlocal` at the end of every batch script.

The `setlocal` command can also be used to enable or disable delayed expansion of environment variables via `setlocal ENABLEDELAYEDEXPANSION` and `setlocal DISABLEDELAYEDEXPANSION`.

### `shift`

Change the position of replaceable parameters in a batch file.

```bat
:: shift %1 to %0, %2 to %1, etc.
shift

:: shift %3 to %2, %4 to %3, etc., but leave %0 and %1 unaffected
shift /2
```

### `start`

Start a separate window to run a specified program or command. Accepts the the title of window as the first positional argument. Other important options include:

* `/d` - specify the starting directory of the window
* `/i` - use the environment with which the current `cmd.exe` instance was started (i.e., not including any modifications that occured to the current environment since it started)
* `/b` - start the application without creating a new window
* `/wait` - wait for the started application to terminate before control returns to the calling `cmd.exe` instance

### `time`

Display or set the system time.

```bat
:: output the current time
time /t

:: set the current time (make a wish)
time 11:11 AM
```

### `title`

Set the window title for the current command prompt.

### `type`

Display the contents of a text file.

```bat
:: create a new file with empty contents
type nul >file.txt
```

### `ver`

Displays the Windows version.

### `verify`

Tell `cmd.exe` whether to verify that your files are written correctly to a disk. Accepts one positional argument: either `ON` or `OFF`. Omitting this parameter will tell you the current setting.

### `vol`

Display the disk volume label and serial number, if they exist.


## External `cmd.exe` commands

These commands come from places like `C:\Windows`, `C:\Windows\System`, `C:\Windows\System32`, and `C:\Windows\SysWOW64` (only on 64-bit systems). Loading these commands depends on proper configuration of the `PATH` environment variable.

### `auditpol`

Display information about and perform functions to manipulate audit policies.

```bat
:: get audit policy for all categories
auditpol /get /category:*

:: view global SACLs for different resource types
auditpol /resourceSACL /type:File /view
auditpol /resourceSACL /type:Key /view
```

### `eventvwr`

GUI for viewing event logs.

### `findstr`

Search for a text string in a file.

```bat
:: case-insensitive search
findstr /i brian file.txt

:: match patterns at the beginning of the line
findstr /b /i beginningpattern file.txt

:: regular expression search
findstr /i /r /c:"hello.*goodbye" file.txt

:: search in subfolders for txt and ini files
findstr /si searchstr *.txt *.ini
```

### `hostname`

Display the host name portion of the full computer name of the computer.

```bat
:: the two below commands are essentially equivalent
hostname
echo %COMPUTERNAME%
```

### `icacls`

Display or modify Access Control Lists (ACLs) for files and folders.

```bat
$ icacls C:\Windows
C:\Windows NT SERVICE\TrustedInstaller:(F)
           NT SERVICE\TrustedInstaller:(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(M)
           NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
           BUILTIN\Administrators:(M)
           BUILTIN\Administrators:(OI)(CI)(IO)(F)
           BUILTIN\Users:(RX)
           BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
           CREATOR OWNER:(OI)(CI)(IO)(F)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
           APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

### `net`

Manage network resources. The following subcommands are available within this tool (see [the SS64 reference](https://ss64.com/nt/net.html) for more information):

* `net accounts`, `net user`, `net group`, `net localgroup` - logins and security
* `net computer`, `net config workstation`, `net config server` - network workstation/server configuration
* `net file`, `net sessions` - open files and user sessions
* `net help`, `net helpmsg` - help
* `net print` - network print jobs
* `net time` - network time
* `net start`, `net stop`, `net pause`, `net continue` - manage services
* `net share` - create file and printer shares
* `net use` - connect to a file/print Share (Drive Map)
* `net view` - view file and printer shares

```bat
:: temporarily map the local t: drive
net use t:\\computername\c$ /persistent:no

:: map the first available drive to mount sysinternals tools
net use * https://live.sysinternals.com

:: remove a drive map
net use t: /delete

:: view all local users
net user

:: view all local groups
net localgroup

:: create a new user
net user brian mypassword /add

:: add a user to a group
net localgroup Administrators brian /add
```

### `netsh advfirewall`

Interact with firewall configurations.

```bat
:: query basic firewall information
netsh firewall show state
netsh firewall show config

:: disable the firewall on newer Windows versions
netsh advfirewall set allprofiles state off

:: disable the firewall on older Windows versions
netsh firewall set opmode disable
```

### `reg`

Command-line tool for interacting with the registry.

```bat
:: search registry for keyword "password"
reg query HKLM /f password /t REG_SZ /s

:: search registry for AlwaysInstallElevated value
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### `regedit`

GUI program for viewing and editing the registry.

### `sfc`

Scan the integrity of all protected system files and replaces incorrect versions with correct Microsoft versions.

```bat
:: verify a single file
sfc /verifyfile=c:\windows\system32\winhttp.dll

:: verify all system files; if any are malformed then they will be replaced
sfc /scannow
```

### `where`

Find executables in the `PATH` environment variable.

```bat
:: a simple example
$ where findstr
C:\Windows\System32\findstr

:: recursive search in C:\Windows for executable-ish files
where /r C:\windows *.exe *.dll *.bat

:: return only the exit code without printing output (useful for scripting)
$ where /q notarealprogram || echo Couldn't find it
Couldn't find it
```

### `wmic`

Windows Management Instrumentation Command: retrieve a huge range of information about local or remote computers. See the [SS64 wmic reference](https://ss64.com/nt/wmic.html) for a full overview of functionality.

```bat
:: show all users on the local machine
$ wmic useraccount list brief
AccountType  Caption                     Domain   FullName        Name                SID
512          BrianJr\Administrator       BrianJr                  Administrator       <sid>
512          BrianJr\Brian               BrianJr  Brian Welch     Brian               <sid>
...

:: NIC information
wmic nicconfig list brief

:: list event logs
$ wmic nteventlog list brief
FileSize  LogfileName                        Name                                                                     NumberOfRecords
18944000  Application                        C:\WINDOWS\System32\Winevt\Logs\Application.evtx                         24994
69632     HardwareEvents                     C:\WINDOWS\System32\Winevt\Logs\HardwareEvents.evtx                      0
69632     Internet Explorer                  C:\WINDOWS\System32\Winevt\Logs\Internet Explorer.evtx                   0
...

:: show locally running processes
$ wmic process list brief
HandleCount  Name                                                    Priority  ProcessId  ThreadCount  WorkingSetSize
0            System Idle Process                                     0         0          4            8192
5619         System                                                  8         4          184          13910016
0            Registry                                                8         96         3            1556480
...

:: show locally running services
$ wmic service list brief
ExitCode  Name                                                    ProcessId  StartMode  State    Status
0         AdobeARMservice                                         4620       Auto       Running  OK
0         AdobeFlashPlayerUpdateSvc                               0          Manual     Stopped  OK
1077      AJRouter                                                0          Manual     Stopped  OK
...
```

### `wf` / `wf.msc`

Windows Defender Firewall GUI.

### `wevtutil`

The Windows Events Command Line Utility. Retrieve information about event logs and publishers, install and uninstall event manifests, run queries, and export, archive, and clear logs.

```bat
:: show all logs
wevtutil el

:: get security log info
wevtutil gli security

:: get last three events from the security log
wevtutil qe security /c:3
```


## PowerShell

### PowerShell versions

| Version | Release Date | Windows Version |
| ------- | ------------ | --------------- |
| 1.0     | Nov 2006     | Win XP          |
| 2.0     | Oct 2009     | Win 7           |
| 3.0     | Sep 2012     | Win 8           |
| 4.0     | Oct 2013     | Win 8.1         |
| 5.0     | Apr 2014     | Win 10          |

### Execution policy

[Execution policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6) are designed to protect users, but they really just get in the way.

There are several different policies:

* `Restricted` - permits individual commands, but will not run scripts
* `AllSigned` - scripts can run, but all (remote and locally-written) scripts must be signed by a trust publisher
* `RemoteSigned` - scripts can run, but requires digital signatures on scripts downloaded from the internet (but not locally-written scripts)
* `Unrestricted` - unsigned scripts can run, but warns the user before running scripts downloaded from the internet
* `Bypass` - nothing is blocked and there are no warnings or prompts
* `Undefined` - there is no execution policy set in the current scope

Here's how to bypass them:

```posh
# pipe your script to a PowerShell process
Write-Host "<script contents>" | powershell.exe -noprofile -

# pipe your script from a file
Get-Content script.ps1 | powershell.exe -noprofile -
type script.ps1 | powershell.exe -noprofile -

# piping to Invoke-Expression
Get-Content script.ps1 | Invoke-Expression

# download and run via IEX
IEX(New-Object Net.WebClient).DownloadString('https://bit.ly/myscript')

# execute via -Command switch
powershell.exe -Command "Write-Host 'Executing some PowerShell"

# run via Invoke-Command
Invoke-Command -ScriptBlock {Write-Host "Executing some more PowerShell"}

# use the bypass execution policy
powershell.exe -ExecutionPolicy Bypass -File script.ps1

# set the execution policy for the process scope
Set-ExecutionPolicy Bypass -Scope Process

# disable ExecutionPolicy by swapping out the AuthorizationManager
function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue($executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}
Disable-ExecutionPolicy script.ps1
```

### Multi-threading

Multi-threading can be achieved via the `Start-Job`, `Get-Job`, `Receive-Job`, and `Remove-Job` cmdlets.

```posh
# print a couple of strings via concurrent jobs
"Hello", "Good-bye" | %{
    $ThreadScript = {
        param($word)
        Write-Host "You wanted me to say $word"
        Start-Sleep 5
    }

    Write-Host "Beginning job for $_..."
    Start-Job $ThreadScript -ArgumentList $_
}

# block until job execution completes
While (Get-Job -State "Running") { Start-Sleep 1 }

# display output from all jobs
Get-Job | Receive-Job

# clean up
Remove-Job *
```

### `Get-Process`

Get the processes running on the local computer.

```posh
PS C:\> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    225      18     3552       9692       8.58   4612   0 AppleMobileDeviceService
    395      23    14268      25032       0.77  11520   6 ApplicationFrameHost
    322      16     2980      13028       0.22   4620   0 armsvc
...
```

### `Get-Service`

Get the services running on the local computer.

```posh
PS C:\> Get-Service
Status   Name               DisplayName
------   ----               -----------
Running  AdobeARMservice    Adobe Acrobat Update Service
Stopped  AdobeFlashPlaye... Adobe Flash Player Update Service
Stopped  AJRouter           AllJoyn Router Service
...
```

### `Get-Help`

Display information about Windows PowerShell commands and concepts.

```posh
# Get-Help about Get-Help (mind = blown)
Get-Help Get-Help

# include examples
Get-Help Get-Process -Examples
```

### `Get-Alias`

Get aliases for the current session.

```posh
# get all aliases for the current session
Get-Alias

# look up aliases mapped to a specific command
PS C:\> Get-Alias -Definition Get-ChildItem

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           dir -> Get-ChildItem
Alias           gci -> Get-ChildItem
Alias           ls -> Get-ChildItem
```

### `Get-Member`

Gets the properties and methods of objects.

```posh
PS C:\>Get-Service | Get-Member
    TypeName: System.ServiceProcess.ServiceController
    Name                      MemberType    Definition
    ----                      ----------    ----------
    Name                      AliasProperty Name = ServiceName
    Close                     Method        System.Void Close()
    Continue                  Method        System.Void Continue()
...
```

### `Get-CimInstance`

Gets the CIM instances of a class from a CIM server. [CIM (Common Information Model)](https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/common-information-model) is like WMI but intended to be cross-platform.

```posh
# get running processes
Get-CimInstance -ClassName Win32_Process

# get running processes with an applied filter
Get-CimInstance -ClassName Win32_Process -Filter "Name like 'p%'"

# get a property from two remote computes named Server01 and Server02
$s = New-CimSession –ComputerName Server01,Server02
Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $s
```

### `Get-Item`

Get files and folders.

```posh
# get all of the streams from a specific file
Get-Item file.txt -Stream *

# get all items in the current directory
Get-Item .

# deterimine the last access time of a directory
(Get-Item C:\Windows).LastAccessTime

# filter out matches
Get-Item C:\Windows\*.exe -Exclude w*
```

### `Get-ItemProperty`

Get the properties of a specified item (shocker).

```posh
# get the properties of a directory
Get-ItemProperty C:\Windows

# display the value name and data of each of the registry entries contained in
# the CurrentVersion registry subkey
PS C:\> Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion
ProgramFilesDir          : C:\Program Files
CommonFilesDir           : C:\Program Files\Common Files
ProgramFilesDir (x86)    : C:\Program Files (x86)
...

# gets the value name and data of the ProgramFilesDir registry entry in the
# CurrentVersion registry subkey
PS C:\> Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -name "ProgramFilesDir"
ProgramFilesDir : C:\Program Files
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
PSChildName     : CurrentVersion
PSDrive         : HKLM
PSProvider      : Microsoft.PowerShell.Core\Registry
```

### `Get-NetFirewallRule`

Retrieve firewall rules from the target computer.

```posh
# retrieve all of the firewall rules in the active store (i.e., those that
# apply to the computer)
Get-NetFirewallRule -PolicyStore ActiveStore

# retrieve all of the firewall rules scoped to the public profile
Get-NetFirewallProfile -Name Public | Get-NetFirewallRule
```

### `Get-Acl`

Get the security descriptor for a resource, such as a file or registry key.

```posh
# get security access information about the C:\Windows directory
Get-Acl C:\Windows

# view access controls of a registry key
Get-Acl -Path "HKLM:\System\CurrentControlSet\Control" | Format-List
```

### `Get-Eventlog`

Get the events in an event log, or a list of the event logs, on the local or remote computers.

```posh
# get all event logs on a computer
Get-EventLog -List

# get the five most recent entries in the Application event log
Get-EventLog -Newest 5 -LogName "Application"

# query event logs on remote computers
Get-EventLog -LogName "Windows PowerShell" -ComputerName "localhost", "Server01", "Server02"

# search for log messages that match a pattern
Get-EventLog -LogName "Windows PowerShell" -Message "*failed*"
```


## Third-party / sysinternals

### `accesschk`

Report effective permissions for securable objects.

```bat
:: check the permissions of a folder
$ accesschk.exe C:\Windows

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Windows\.erlang.cookie
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  BUILTIN\Users
  R  APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
  R  APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES
...
```

### `autoruns`

GUI tool that will show you what programs are configured to run during system bootup or login, and when you start various built-in Windows applications like Internet Explorer, Explorer and media players.

### `handle`

Handle viewer to search for open file references.

```bat
:: dump all handles
handle -a
```

### `procexp`

AKA: Process Explorer. A GUI tool for examining running processes, considered to be a more advanced form of the Windows Task Manager.

### `procmon`

AKA: Process Monitor. A GUI tool for displaying information regarding the file system, registry, and the processes running on the system as they are occurring.

### `psinfo`

Gathers key information about the local or remote system, including the type of installation, kernel build, registered organization and owner, number of processors and their type, amount of physical memory, the install date of the system, and if it's a trial version, the expiration date.

```bat
$ psinfo

PsInfo v1.78 - Local and remote system information viewer
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

System information for \\BRIANJR:
Uptime:                    3 days 17 hours 59 minutes 31 seconds
Kernel version:            Windows 10 Enterprise, Multiprocessor Free
...
```

### `pslist`

Show running process statistics.

```bat
$ pslist

PsList v1.4 - Process information lister
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Process information for BRIANJR:

Name                Pid Pri Thd  Hnd   Priv        CPU Time    Elapsed Time
Idle                  0   0   4    0     52    65:17:57.812    90:00:08.176
System                4   8 191 5839    228     0:25:56.375    90:00:08.176
Registry             96   8   3    0   2240     0:00:02.437    90:00:09.431
smss                440  11   2   52    488     0:00:00.281    90:00:08.170
...
```

### `psloggedon`

Display both the locally logged on users and users logged on via resources for either the local computer, or a remote one. If you specify a user name instead of a computer, `psloggedon` searches the computers in the network neighborhood and tells you if the user is currently logged on.

```bat
$ psloggedon

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     11/18/2018 5:32:55 AM      BRIANJR\Brian
     <unknown time>             BrianJr\postgres

No one is logged on via resource shares.
```

### `logonsessions`

List the currently active logon sessions and, if you specify the `-p` option, the processes running in each session.

```bat
$ logonsessions

LogonSessions v1.4 - Lists logon session information
Copyright (C) 2004-2016 Mark Russinovich
Sysinternals - www.sysinternals.com


[0] Logon session 00000000:000003e7:
    User name:    WORKGROUP\BRIANJR$
    Auth package: NTLM
    Logon type:   (none)
    Session:      0
    Sid:          S-1-5-18
    Logon time:   11/14/2018 4:14:14 PM
    Logon server:
    DNS Domain:
    UPN:
...
```

### `tcpview`

GUI tool to show you detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and state of TCP connections,

### `psexec`

A light-weight telnet-replacement that lets you execute processes on other systems, complete with full interactivity for console applications, without having to manually install client software.

Input is only passed to the remote system when you press the Enter key. Typing Ctrl-C terminates the remote process.

```bat
:: execute a command on Mark's laptop
psexec \\marklap "c:\long name app.exe"
```

### `psgetsid`

Translate SIDs to their display name and vice versa.

```bat
:: get the SID for a user
psgetsid brian
```

### `sigcheck`

Show file version number, timestamp information, and digital signature details, including certificate chains. Also includes an option to check a file's status on [VirusTotal](https://www.virustotal.com).

```bat
:: check for unsigned files in C:\Windows\System32
sigcheck -u -e c:\Windows\System32
```


## Process states

### New / created

Newly created process follows this flow:

* Open executable file
* Create initial thread
* Pass to `kernel32.dll` to check permissions
* Pass to `csrss`, build structure, spawn first sub-thread, inserts into Windows subsystem-wide process list
* Starts execution of initial thread
* For real-time systems, processes may be held in "New State" to avoid contention, otherwise moved to "Ready State".

### Ready

Process ready to execute when given the opportunity (CPU Time).

### Running

Process currently being executed (one or more threads executing).

### Waiting

Process can’t execute until some event occurs (i.e., I/O Read).

### Terminated / exit

Termination of a process due to a halt or abort.


## Thread states

### Initialized

Threads are placed in the Initialized state whilst they are being created.

### Running

A Running thread is the thread that is currently executing on a processor.

### Ready

Threads that are not Ready to run are given state determined by the reason they cannot run.

### Deferred ready

Global state that indicates the thread is ready to run on any processor. This can be used for one CPU to schedule a high priority thread on another CPU, for example.

### Waiting

Waiting on some event, such as synchronization or I/O completion, or can be forced to wait if they access memory that is paged to disk, for example.  Once the event has been signalled, or the timeout has elapsed, the thread will be eligible to run again.

### Transition

Threads placed in this state when their kernel stack has been paged out. These threads will not be ready to run until their kernel stack is available again.

### Standby

The Standby thread is the Ready thread that is currently selected to be swapped into the Running state next on that processor. However, this may change if a higher priority thread becomes ready before the change is made.

### Terminated

For threads that have exited. They will remain here until the system has cleaned up.


## Registry

Primary hive (root) keys:

* `HKCU` / `CURRENT USER` - individual user settings (equivalent to `HKU\<SID OF CURRENT USER>`)
* `HKU` / `USERS` - all accounts on machine, the root key containing the ntuser.dat hives for ALL users
* `HKCR` / `CLASSES ROOT` - file association and COM objects, backward compatibility, and file extension information (merged view of `HKLM\Software\Classes` and `HKCU\Software\Classes`)
* `HKLM` / `LOCAL MACHINE` - system related information, SAM, Critical boot/kernel functions, 3rd party software, hardware, BCD.dat
* `HKCC` / `CURRENT CONFIG` - current hardware profile, information that is gathered at runtime (can be located with value `HKLM\SYSTEM\Select\Current`)

Only `HKU` and `HKLM` are available via remote tools.

To query the hivelist:
```bat
reg query hklm\system\currentcontrolset\control\hivelist
```

Registry contains keys and values:

* Keys: contain other keys (AKA Sub-keys) and/or a collection of property/value pairs; container objects, like folders
* Values: store data; non-container objects like files

[Registry data types](https://msdn.microsoft.com/en-us/library/windows/desktop/bb773476(v=vs.85).aspx):

| Type | Description |
| ---- | ----------- |
| `REG_BINARY` | Binary data in any form |
| `REG_DWORD` | 32-bit number |
| `REG_QWORD` | 64-bit number |
| `REG_DWORD_LITTLE_ENDIAN` | 32-bit number in little-endian format, equivalent to `REG_DWORD` |
| `REG_QWORD_LITTLE_ENDIAN` | A 64-bit number in little-endian format, equivalent to `REG_QWORD` |
| `REG_DWORD_BIG_ENDIAN` | 32-bit number in big-endian format |
| `REG_EXPAND_SZ` | Null-terminated string that contains unexpanded references to environment variables (for example, `"%PATH%"`) |
| `REG_LINK` | Unicode symbolic link |
| `REG_MULTI_SZ` | Array of null-terminated strings that are terminated by two null characters |
| `REG_NONE` | No defined value type |
| `REG_RESOURCE_LIST` | Device-driver resource list |
| `REG_SZ` | Null-terminated string |


## Logging Sequence

* On startup, `LSASS` sends the system audit policy to the Security Reference Manager (`SRM`)
* When an object is access, `SRM` generates auditing messages and sends them to `LSASS`
* `LSASS` sends the event log messages to the Event Logger


## Windows Resource Protection (WRP)

Previously known as Windows File Protection (WPF) in Windows XP, which did the following:

* Watch for system file overwrite attempts
* Check file signature against known correct ones
* If bad, replace overwritten system file with a copy from `C:\Windows\System32\dllcache` folder (which is now the `C:\Windows\winsxs\Backup` folder in WRP)

WRP adds the following functionality:

* Keep protected files from being overwritten in the first place
* Protected resources can only be modified by the Windows Module Installer service (`TrustedInstaller.exe`)
* Protects system registry keys

The following are still blue team concerns with regard to WRP:

* Attackers can still mount a drive into another OS and overwrite protected files
* Attackers can still gain elevated access via compromised third-party drivers
* With Administrator privilege, attacks can alter the WRP configuration to allow for modification


## User Account Control (UAC)

Limits the privileges of user-run applications (even when run as Administrator) in order to prevent the modification of system files, resources, or settings. This mechanism causes explicit acknowledgement from the user when elevated privileges are requested.

User Interface Privilege Isolation (UIPI) is a part of UAC, where each process is given a privilege level.

* High integrity level can send messages to lower level integrity
* Lower integrity level can only read from higher
* UIPI can be bypassed by signed and trusted applications with the `UIaccess` manifest setting


## New Technology File System (NTFS)

Each file in NTFS has a security descriptor, which includes:
* Security identifiers (SIDs) for the owner
* A Discretionary Access Control List (DACL) that specifies the read/write/execute/delete  access rights allowed or denied to particular users or groups
* A System Access Control List (SACL) that specifies the types of access attempts that generate audit records for the object

Locating SIDs in the registry:
```posh
reg query HKU
reg query "hklm\software\microsoft\windows nt\currentversion\profilelist\{SID}"

wmic useraccount get name,sid,fullname
wmic useraccount where sid={sid} get name
wmic useraccount where name={name} get sid

Get-ChildItem Registry::\HKEY_USERS -ErrorAction SilentlyContinue
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'
```

Equivalent methods of checking the permission properties of `notepad.exe`:
```bat
:: via explorer.exe: right click -> properties -> security
icacls C:\Windows\System32\notepad.exe
Get-Acl C:\Windows\System32\notepad.exe | Format-List
accesschk C:\Windows\System32\notepad.exe
```


## Windows Boot Sequence

### Windows XP boot sequence

* Pre-boot - Power on Self Test (POST)
* MBR - loads boot code
* Bootcode - searches partition table for boot sectory and loads NTLDR
* NTLDR
  * Reads in `boot.ini` for OS choices, runs `NTDETECT.com` to query hardware
  * Stored data from `NTDETECT.com` in `HKLM\Hardware` registry key
  * Starts `NTOSKRNL.exe` and `HAL.dll`
* `NTOSKRNL.exe` - starts `SMSS.exe`
* `SMSS.exe` - launches `Winlogon.exe` and `CSRSS`
* `Winlogon.exe`
  * Starts `LSASS`
  * Loads `MSGINA`
  * Starts `SCM`
  * Starts `logonui.exe`
* `MSGINA.dll`
  * Graphical  Indentification and Authorization (GINA) dll
  * Activates the user shell
  * Customizable identification and authentication procedures
  * Logon dialog
* `Winlogon.exe` - receives credentials from MSGINA and passes them to LSASS
* LSASS
  * Checks creds against LSA database cache then NTLM or Kerberos if not found
  * Sends user token to Winlogon
* Winlogon - starts userinit in user context
* Userinit - loads user profile, runs startup programs, starts `explorer.exe`

### Windows 7 boot sequence

Pre-boot:

* Basic Input/Output System (BIOS)
  * Power on Self Test (POST)
  * Master boot record (MBR)
    * First 512 byte sector on hard disk
    * Reads and loads Volume Boot Record (VBR)
  * VBR - loads Bootmgr into memory
  * Bootmgr
    * Reads Boot Config Database (BCD)
    * Boot menu and memtest
    * Calls winload (on a fresh boot)
    * Calls winresume
* Unified Extensible Firmware Interface (UEFI)
  * Power on Self Test (POST)
  * Runs bootloader and BCD from NVRAM
  * Bootloader detects hardware
  * EFI boot manager gives OS boot menu
  * Winload.efi - the EFI version of winload
  * Requires EFI system partition (formatted as FAT and up to 1 GB in size)

Boot:

* `NTOSKRNL`
  * SYSTEM
  * Prepares for running native system
  * Runs `SMSS`
* `HAL.dll`
  * Hardware Abstraction Layer (HAL)
  * Interfaces driver to kernel
* `SMSS`
  * Session manager
  * Session 0 loads `Wind32k.sys` (kernel subsystem)
  * Runs `WININIT`
* `WININIT`
  * Starts Service Control Manager (SCM)
  * Starts Local Security Authority SubSystem (LSASS)
  * Starts Local Session Manager (LSM)
* `CSRSS`
  * Client-Server Runtime SubSystem
  * Client side of the Win32 subsystem process
  * Thread creation

Logon:

* Winlogon - coordinates logon and user activity and launches logonui
* Logonui - interactive logon dialog box
* Services - loads auto-start drivers and services


## Active Directory

Important features:

* Centralized data storage
* Integration with DNS
* Policy-based administration
* Replication of information
* Interoperability with directory services
* Signed and encrypted LDAP traffic

Terminology:

* Trusted - an authenticated account from one domain is not reject by another domain
* Contiguous DNS domains
  * Domains with the same root DNS name
  * For example, `a.brianwel.ch`, `b.brianwel.ch`, and `brianwel.ch` are all contiguous; `brianwel.ch` and `google.com` are not contiguous
* Domain
  * A group of computers which share a common account database
  * Since Windows 2000, Windows domains must have a corresponding DNS domain associated with it (consequently, domain controllers for the domain must have an associated DNS domain as their primary DNS suffix)
* Organizational Unit (OU)
  * Used for grouping similar accounts or machines
  * Allows for delegating authority over a group of accounts or machines to a person (the local administrator)
  * OUs can contain other OUs to a depth of 63
* Tree
  * A group of one or more trusted Windows domains with contiguous DNS domains
  * Shares common global catalog servers and a common schema
  * Require no physical representation (like a domain controller), but require at least one domain to exist
  * Used for grouping Windows domains which need to share files, policy, and resources
* Forest
  * A group of one or more trusted Windows trees
  * These trees *do not* need to have contiguous DNS names
  * Shares a schema and global catalog servers
* Site
  * Groupings of subnets
  * Objects in a site share the same global catalog servers and can have a common set of group policies applied to them
* Schema
  * Defines what attributes, objects, classes and rules are available in the Active Directory
  * The schema is shared by AD forest-wide and is replicated between all domains
  * Only special administrators known as Schema Administrators have the right to make modifications
  * Schema modifications are fairly rare
* Global catalog server
  * Processes directory searches for the entire forest
  * Contains a subset of the searchable attributes for all objects in the AD, regardless of the object’s parent domain
  * A global catalog server must be a domain controller
* Top-level / forest root domain - the first domain installed in a forest
* Group policy
  * Windows term for common configuration settings
  * Can set certain computer settings such as who can login to the computer or user settings such whether the user can run control panel applets
  * A GPO, or group policy object, is a set of settings applied to a site, domain or OU container
* Group policy loopback
  * Gives the administrator the ability to apply Group Policy, based upon the computer that the user is logging onto

Logical AD structure:

* Domains
* Organizational units
* Trees and forests

Physical AD structure:

* Sites
* Domain controllers
* Member servers

Interating with active directory:

* `dsadd` - add specific types of objects to the directory
* `dsget` - display the selected properties of a specific object in the directory
* `dsmod` - modify existing objects in the directory
* `dsquery` - query the directory according to specific criteria
* PowerShell's `Get-ADComputer`, `Get-ADDomain`, `Get-ADDomainController`, `Get-ADUser`, and [many others](https://docs.microsoft.com/en-us/powershell/module/addsadministration/?view=win10-ps)


## General Concepts

### Paging

Paging is a memory management scheme by which a computer stores and retrieves data from secondary storage for use in main memory.

### [User mode and kernel mode](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)

In addition to being private, the virtual address space of a user-mode application is limited. A processor running in user mode cannot access virtual addresses that are reserved for the operating system. Limiting the virtual address space of a user-mode application prevents the application from altering, and possibly damaging, critical operating system data.

All code that runs in kernel mode shares a single virtual address space. This means that a kernel-mode driver is not isolated from other drivers and the operating system itself. If a kernel-mode driver accidentally writes to the wrong virtual address, data that belongs to the operating system or another driver could be compromised. If a kernel-mode driver crashes, the entire operating system crashes.


## Tactical Survey

### Incident Response

Six phases of incident response (P.I.C.I.E.R.):

* Preparation
  * Packing list
  * Update tools
  * SOPs / policies and procedures
  * Network diagrams
* Identification - determine if working with an adverse event or an incident
  * Adverse event - event with a negative consequence
    * Unauthorized use of system privileges
    * Execution of malware that destroys data
  * Incident - event that violates an organization's security or privacy policies
    * Unknown connections
    * Unknown user accounts
    * External devices
* Containment - limit damage caused to systems and prevent any further damage from occuring
  * Cordon and clear (VLANs)
  * Patch / hotfix
* Investigation - determine the priority, scope, and root cause of an incident
  * Indicators of compromise (IOCs)
  * Vulnerability assessment
  * Forensic analysis - static or dynamic analysis
* Eradication - remove the infection
  * Re-image
  * Key rotation
* Recovery
  * Remove VLANs
  * Return network to normal

Order of volatility:

* Registers, cache
* Routing table, arp cache, process table, kernel statistics, memory
* Temporary file systems
* Disk and other storage media
* Remote logging and monitoring data that is relevant to the system in question
* Physical configuration, network topology
* Archival media

### Enumeration

What to consider when baselining:

* Local user accounts
* Running processes
* Services (installed and autostart)
* Autorun locations
* Scheduled tasks
* Drivers and system files (via hashing of file contents)
* Network communications
* Loaded modules (DLLs)
* Installed applications and user context
* Group policy objects