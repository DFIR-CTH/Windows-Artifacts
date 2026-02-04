## 📁 File Opening Artifacts
----

### [Shortcut Files (.LNK)](File%20Opening%20Artifacts.md#shortcut-files-lnk)

### [Jump Lists](File%20Opening%20Artifacts.md#jump-lists)

### [ShellBags](File%20Opening%20Artifacts.md#shellbags)

### [OpenSaveMRU](File%20Opening%20Artifacts.md#opensavemru)

### [Prefetch Files](File%20Opening%20Artifacts.md#prefetch-files)



### Shortcut Files (.LNK)

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Track files, folders, and applications accessed by users through Windows Explorer. Automatically created when users open files from supported applications or manually created as shortcuts. |
| **Key Characteristics** | • Contains metadata about target file location, timestamps (MAC times), file size<br>• Stores volume serial number and network share information<br>• May contain MAC address of host computer (via Object ID)<br>• Persists even after target file deletion<br>• Can reveal USB device usage and removable media access |
| **Locations** | **Windows 7/8/10/11:**<br>`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Recent\`<br>`C:\Users\<username>\AppData\Roaming\Microsoft\Office\Recent\` (Office-specific)<br><br>**Windows XP:**<br>`C:\Documents and Settings\<username>\Recent\` |
| **Parsing Steps** | 1. Navigate to Recent folder using forensic tool (FTK Imager, Autopsy)<br>2. Export .lnk files to examination directory<br>3. Parse LNK structure to extract:<br>   - Target file path and attributes<br>   - Creation, modification, access timestamps<br>   - Volume information and network paths<br>   - Tracker data (hostname, MAC address)<br>4. Correlate timestamps with user activity timeline<br>5. Identify external devices via network paths |
| **Tools** | • **LECmd** (Eric Zimmerman) - Command-line parser with AppID database<br>• **LnkParse3** - Python-based parser, handles malformed files<br>• **Velocir aptor** - Windows.Forensics.Lnk artifact<br>• **FTK Imager** - File extraction<br>• **Autopsy** - Automated parsing and timeline analysis |
| **Additional Info** | • LNK files are NOT generated for command-line access<br>• Primarily useful for GUI-based user actions<br>• Can reveal file access even from deleted or formatted drives<br>• Critical for USB forensics and external device tracking<br>• Malware may create malicious LNK files with embedded payloads |

---





### Jump Lists

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Provide quick access to recently/frequently used files, websites, and applications from taskbar. Track user interactions with files, folders, and websites per application with up to 2,000 entries per app. |
| **Key Characteristics** | • **AutomaticDestinations**: OLE CF format storing up to 2,000 entries with MRU ordering and timestamps<br>• **CustomDestinations**: Application-defined favorites, concatenated LNK files<br>• Named with AppID-based filenames (16 hex digits)<br>• Persist even after file deletion from system<br>• Store LNK files internally with access timestamps |
| **Locations** | **AutomaticDestinations:**<br>`C:\Users\<Profile>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`<br>Filename: `[AppID].automaticDestinations-ms`<br><br>**CustomDestinations:**<br>`C:\Users\<Profile>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`<br>Filename: `[AppID].customDestinations-ms` |
| **Parsing Steps** | 1. Extract Jump List files from AutomaticDestinations and CustomDestinations folders<br>2. Identify application using AppID (use JLECmd database or manual lookup)<br>3. Parse AutomaticDestinations (OLE format):<br>   - Extract DestList stream for MRU order<br>   - Parse embedded LNK files<br>   - Extract timestamps and access counts<br>4. Parse CustomDestinations:<br>   - Extract concatenated LNK files<br>   - Identify favorite/pinned items<br>5. Correlate with timeline and user activity |
| **Tools** | • **JumpList Explorer (JLE Cmd)** (Eric Zimmerman) - Automatic AppID matching<br>• **oledump.py** - Parse OLE structure and extract streams<br>• **Autopsy** - Automated Jump List parsing<br>• **X-Ways Forensics** - Jump List analysis<br>• **JumpListExt** - GUI tool for manual analysis |
| **Additional Info** | • Introduced in Windows 7, continued through Windows 11<br>• AutomaticDestinations more forensically valuable (MRU + timestamps)<br>• CustomDestinations useful for browser favorites, RDP connections<br>• AppID algorithm same for both Automatic and Custom<br>• Can track cloud storage access, browser history, remote desktop usage<br>• Useful for data exfiltration investigations (USB, cloud uploads) |

---





### ShellBags

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Store Windows Explorer view settings and preferences for folders (icon size, position, view mode, window size). Track folder access including local drives, network shares, removable devices, and ZIP files opened as folders. |
| **Key Characteristics** | • Records folder browsing history even for deleted folders<br>• Tracks folders on removable media and network shares<br>• Stores view preferences (list, details, tiles, icon sizes)<br>• Contains MFT entry numbers for folder identification<br>• Maintains timestamps via registry key Last Write Time<br>• Tracks ZIP files opened as folders through Windows Explorer |
| **Locations** | **Windows 7/8/10/11:**<br><br>**NTUSER.DAT:**<br>`HKCU\Software\Microsoft\Windows\Shell\BagMRU`<br>`HKCU\Software\Microsoft\Windows\Shell\Bags`<br>*Desktop and Network Locations*<br><br>**USRCLASS.DAT:**<br>`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`<br>`HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags`<br>*Local, removable, network folders, ZIP files*<br><br>**Registry Hive Paths:**<br>`%SystemDrive%:\Users\<USERNAME>\NTUSER.dat`<br>`%SystemDrive%:\Users\<USERNAME>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| **Parsing Steps** | 1. Extract NTUSER.DAT and USRCLASS.DAT registry hives using FTK Imager<br>2. Load hives into ShellBags Explorer (offline analysis)<br>3. Navigate to BagMRU and Bags keys<br>4. Parse ShellBag data structure:<br>   - Folder names and paths<br>   - MFT entry numbers<br>   - View settings<br>   - Registry key Last Write Time (folder access timestamp)<br>5. Identify renamed folders (same MFT entry number)<br>6. Track external device access via removable media paths<br>7. Correlate with user activity timeline |
| **Tools** | • **ShellBags Explorer** (Eric Zimmerman) - Load offline hives, parse entries<br>• **Registry Explorer** (Eric Zimmerman) - Manual registry analysis<br>• **Velocir aptor** - Windows.Forensics.Shellbags artifact<br>• **FTK Imager** - Extract registry hives<br>• **Autopsy** - Automated ShellBags parsing<br>• **RegRipper** - Extract ShellBag data via plugins |
| **Additional Info** | • Available since Windows XP, enhanced in Vista+<br>• UsrClass.dat contains majority of forensic data (local/network/removable)<br>• Useful for proving folder access when files deleted<br>• Can detect Control Panel access (interface-by-interface basis)<br>• Folder renaming tracked via consistent MFT entry numbers<br>• Does NOT track individual files (only folders and ZIP files)<br>• Critical for insider threat investigations and data theft cases |

---





### OpenSaveMRU

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Track files accessed through "Open" or "Save As" Windows shell dialog boxes across any application using Common Dialog libraries. Reveals downloaded files and last files accessed by users. |
| **Key Characteristics** | • Stores full path of files accessed via Open/Save dialogs<br>• Organized by file extension in subkeys<br>• "*" subkey contains last 20 files (10 in XP) of any extension<br>• MRUListEx tracks access order (most recent first)<br>• Does NOT capture Microsoft Office program files (Office uses separate tracking)<br>• Updated by web browsers, document viewers, archiving utilities, image viewers |
| **Locations** | **Windows XP:**<br>`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU`<br><br>**Windows 7/8/10/11:**<br>`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`<br><br>**Registry Hive Path:**<br>`C:\Users\<username>\NTUSER.DAT` |
| **Parsing Steps** | 1. Extract NTUSER.DAT registry hive using forensic tool<br>2. Navigate to OpenSaveMRU (XP) or OpenSavePidlMRU (7+) key<br>3. Examine "*" subkey for cross-extension recent files (last 20)<br>4. Parse extension-specific subkeys (e.g., .txt, .pdf, .jpg, .docx)<br>5. Extract MRUListEx to determine access order:<br>   - Position 0 = most recent<br>   - Sequential numbering shows access timeline<br>6. Decode binary values (Vista+) or string values (XP) to retrieve full paths<br>7. Correlate paths with LastVisitedMRU for application context<br>8. Build timeline of file access via different applications |
| **Tools** | • **Registry Explorer** (Eric Zimmerman) - Manual key parsing<br>• **RECmd** (Eric Zimmerman) - Command-line registry extraction<br>• **RegRipper** - OpenSaveMRU plugin<br>• **ArtiFast** - Automated OpenSaveMRU parsing<br>• **Autopsy** - Registry analysis module<br>• **X-Ways Forensics** - Registry viewer |
| **Additional Info** | • Key renamed from OpenSaveMRU to OpenSavePidlMRU in Vista+<br>• Stores up to 20 entries (10 in XP) per file extension<br>• Critical for tracking malicious file downloads<br>• Reveals user interaction with suspicious file types<br>• Does NOT include auto-complete fragments (stored in key itself)<br>• Correlates with LastVisitedMRU to identify which application accessed file<br>• Can reveal external drive paths and network share access |

---





### Prefetch Files

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Speed up application loading by caching information about programs and their dependencies. Track program execution with first run time, last run time, and execution count. |
| **Key Characteristics** | • Stores last 8 execution timestamps (Windows 8+) or last 1 (Windows 7)<br>• Contains run count (how many times program executed)<br>• Records files and directories accessed during first 10 seconds of execution<br>• Includes volume information and file references<br>• Named as `[ExecutableName]-[Hash].pf`<br>• Maximum 128-1024 files stored (Windows version dependent)<br>• Enabled by default on Windows client OS, disabled on servers |
| **Locations** | **All Windows Versions:**<br>`C:\Windows\Prefetch\*.pf`<br><br>**Prefetch Configuration:**<br>`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`<br>Key: `EnablePrefetcher` (0=Disabled, 1=Application, 2=Boot, 3=All) |
| **Parsing Steps** | 1. Navigate to `C:\Windows\Prefetch\` using forensic tool<br>2. Extract .pf files to examination directory<br>3. Parse Prefetch file structure:<br>   - Extract executable name from filename<br>   - Parse embedded timestamps (last 8 executions on Win8+)<br>   - Extract run count<br>   - Identify loaded DLLs and dependencies<br>   - Extract file and directory references<br>   - Parse volume information<br>4. Calculate hash to verify executable identity<br>5. Correlate execution times with system events<br>6. Identify malware execution patterns |
| **Tools** | • **PECmd** (Eric Zimmerman) - Command-line Prefetch parser<br>• **WinPrefetchView** (NirSoft) - GUI-based viewer<br>• **Autopsy** - Automated Prefetch analysis<br>• **X-Ways Forensics** - Prefetch file parsing<br>• **Velocir aptor** - Windows.Forensics.Prefetch artifact<br>• **Magnet AXIOM** - Timeline integration |
| **Additional Info** | • Windows 10/11: Stores last 8 execution timestamps per file<br>• Windows 7: Only last execution time preserved<br>• Run count useful for identifying frequently executed malware<br>• Can track executables run from external USB devices<br>• Prefetch hash changes if executable run from different path<br>• Valuable for malware execution timeline reconstruction<br>• Does NOT prove execution intent (could be automatic)<br>• Cleared by CCleaner and similar optimization tools |

---
