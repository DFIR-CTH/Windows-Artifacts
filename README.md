# Windows-Artifacts

This document provides a detailed overview of artifacts and forensic evidence used to detect compromised endpoints even when no active malware is present. The focus is on Windows operating system artifacts that capture program execution and user activity, which can aid in incident response and threat hunting

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Core Concepts and Artifacts**


**Program Execution Artifacts**
-------------------------------

**(1) Prefetch Files**
----------------------


- Purpose: Prefetcher was introduced in Windows XP to optimize application launch times by caching necessary files during the first **10 seconds** of an application’s execution.

- Location: C:\Windows\Prefetch

- File Extensions: Mainly .pf but can include .ebd, .mkd, and others.

- Example Filename: CMD.EXE-4A818364.pf (where the suffix is a hash value)

- Hash Generation Process:
  
  - Determine the full file path (e.g., C:\Windows\NOTEPAD.EXE)
  - Convert the path to a Unicode string
  - Convert to device path format (e.g., \DEVICE\HARDDISKVOLUMEx\WINDOWS\NOTEPAD.EXE)
  - Apply a hashing function to generate the filename hash

- Special Cases: For executables like dllhost.exe, mmc.exe, and rundll32.exe, command-line parameters are included in the hash calculation. Variations in case and spacing in parameters affect the hash outcome.
  
- Binary Locations:

  - 64-bit Windows: C:\Windows\System32
  - 32-bit Windows: C:\Windows\SysWOW64

- Important Considerations:

  - Prefetch files are referenced and updated on each program run to improve performance.
  - These files rarely appear in unallocated disk space because they are actively maintained by the OS.
  - Prefetch is enabled only on Windows workstations by default, not on servers.
  - Limits on Prefetch Files:
  - Windows XP, Vista, 7: limit of 128 files
  - Windows 8 and later: limit increased to 1024 files
  - Oldest files are automatically purged first.

- Timestamps in Prefetch:

  - First run: Creation date of the file
  - Last run: Modification date of the file

- Parsing Tool: **Eric Zimmerman’s PECmd.exe** (https://download.ericzimmermanstools.com/net9/PECmd.zip) is recommended for analyzing Prefetch files.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**(2) ShimCache or AppCompatCache**
-----------------------------------


- What it does :

  - Provides compatibility for older software running in newer versions of Windows.
  - Executable file name, file path ,and timestamp are recorded.
  - Windows 7/8/8.1 had an "execution flag" that could indicate if the program ran.
  - Renanming or moving a file will cause it to be re-shimmed.
  - Last 1024 entries are retained.
  - Most tools will output data with the most recently shimmed entries at the top.
  - Stored in the SYSTEM registry hive
 
- Confusion Points :

  - Timestamp is the last modification time of the file
  - File visible in Windows Explorer or File Explorer can determine what is added to the Shimcache
 
-  Misunderstood things :
     
    - You can NOT use shimcache to prove execution in Windows 10 (like "there is no execution-flag") .
    - Only written on reboot or shutdown


- Shimcache can be used to show executable files present on, or accessed via, a given system.

- Even if we can't determine execution on a Windows 10 system,we can show that a file once existed on that system, or was browsed to via an external drive or UNC path.

- Anti-Forensics is complicated by the fact that the data resides in memory until reboot or shutdown, at which time the shimcache is commited to the Registry

- File Location: C:\Windows\System32\config\SYSTEM hive (not a standalone file)

- ShimCache (AppCompatCache) location: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache

- Tool : **Eric Zimmerman's AppCompatCacheParser** (https://download.ericzimmermanstools.com/net9/AppCompatCacheParser.zip)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**(3) AmCache**
---------------


- Purpose : Amcache.hve is a Windows registry hive file that stores metadata about program executions, including file paths, SHA-1 hashes, sizes, publishers, and timestamps for applications, drivers, and DLLs. It aids DFIR by providing evidence of run executables, even if deleted, across Windows 7/Server 2008 R2 and later.

- File Location : C:\Windows\AppCompat\Programs\Amcache.hve  , with associated transaction logs like Amcache.hve.LOG1 and .LOG2

- Data Structure : Key registry paths include Root\File (file entries with execution details) and Root\Programs (program metadata with pointers to files). Entries capture full paths, SHA1 hashes (for files <31MB), file sizes, compilation timestamps, and last write times for File Key.

- Tool : **Eric Zimmerman's AmcacheParser** (https://download.ericzimmermanstools.com/net9/AmcacheParser.zip)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  
**(4) UserAssist**
-------------------


- Purpose : UserAssist is a Windows registry artifact that tracks GUI-based application launches via Explorer, recording paths, run counts, last execution times, focus times, and counts for user activity reconstruction in DFIR.

- Registry Locations : Primary paths under each user's NTUSER.DAT/NTUSER.dat **hive: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count\[ROT13-encoded values]**

  - with GUIDs like
  {75048700-EF1F-11D0-9888-006097DEACF9} (Windows XP+),
  {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} (Vista+), and
  {F4E57C4B-2036-45F0-A9DD-CF56972AC756} for UWP apps (Win10+)

- Data Structure : Values use ROT13 encoding for app names (e.g., "C:\Windows\system32\notepad.exe" becomes obfuscated string); binary data includes 4-byte run count, 8-byte FILETIME last run timestamp, focus count/time (Vista+), and session ID.

- Versions Differences :
    
    - XP/2000: Basic path, count, last run time.
    - Vista/7: Adds focus time/count.
    - 8+: Higher focus precision.
    - 10/11: UWP app tracking.
 
- Tool : **Eric Zimmerman's RegistryExplorer** (https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**(5) SRUM (System Resource Utilization Monitor)**
------------------------------------------------


- Purpose : SRUM (System Resource Utilization Monitor) is a Windows 8+ telemetry feature that logs app resource usage (CPU, network, energy) in an ESE database for performance optimization, offering DFIR insights into app execution, network activity, and timelines even for UWP apps or deleted binaries.

- File Location : **C:\Windows\System32\sru\SRUDB.dat**, with supporting files like SRUDB.dat.LOG1, SRUDB.dat.jfm, and temp files; paired with registry at HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions listing GUIDs for tables.

- Key Tables :

    
  | Table GUID                            | Description                 | Key Data                                                                                              |
  |---------------------------------------|:---------------------------:|-------------------------------------------------------------------------------------------------------|
  |{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} | Application Resource Usage  |Foreground/Background CPU cycles, bytes read/written, context switches per app/user (1-hour buckets)   |
  |                                       |                             |                                                                                                       |
  |{973F5D5C-1D90-4944-BE8E-24B94231A174} | Network Usage               |Bytes sent/received, interface GUIDs per app                                                           | 
  |                                       |                             |                                                                                                       |
  |{DD6636C4-8929-4683-974E-22C046A43763} | Network Connections         |Connection start times, duration, interfaces                                                           | 
  |                                       |                             |                                                                                                       |
  |{5C8CF1C7-7257-4F13-B223-970EF5939312} | Execution                   |App duration, network bytes (Win10+)                                                                   |

- Tool : **SRUM-DUMP.EXE** (https://github.com/MarkBaggett/srum-dump)
  
  
  

  
