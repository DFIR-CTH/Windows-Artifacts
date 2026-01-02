# Windows-Artifacts

This document provides a detailed overview of artifacts and forensic evidence used to detect compromised endpoints even when no active malware is present. The focus is on Windows operating system artifacts that capture program execution and user activity, which can aid in incident response and threat hunting

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**Core Concepts and Artifacts**

**1. Program Execution Artifacts**

**Prefetch Files**


- Purpose: Prefetcher was introduced in Windows XP to optimize application launch times by caching necessary files during the first 10 seconds of an application’s execution.

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
  
