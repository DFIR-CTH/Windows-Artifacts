## 📚 File Knowledge Artifacts

### WordWheelQuery

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Record search terms entered into Windows File Explorer search box. Track user file search behavior and intentions on the system. |
| **Key Characteristics** | • Stores keywords typed in File Explorer search box<br>• MRUListEx value lists search order (most recent first)<br>• Values stored as numbered entries (0, 1, 2, ...) in binary format<br>• Persists even after file deletion or system cleanup<br>• Available Windows 7, 8, 10, 11<br>• Does NOT capture Start Menu or Cortana searches |
| **Locations** | **Windows 7/8/10/11:**<br>`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`<br><br>**Registry Hive Path:**<br>`C:\Users\<username>\NTUSER.DAT` |
| **Parsing Steps** | 1. Extract NTUSER.DAT registry hive using forensic tool<br>2. Navigate to WordWheelQuery key<br>3. Examine numbered values (0, 1, 2, ...) containing binary search terms<br>4. Parse MRUListEx to determine search order:<br>   - First entry = most recent search<br>   - Sequential order shows search timeline<br>5. Decode binary data to extract search strings<br>6. Analyze search terms for:<br>   - Suspicious keywords (malware names, hacking tools)<br>   - Sensitive file names (confidential, passwords, etc.)<br>   - Evidence of data theft intent<br>7. Correlate with file access artifacts |
| **Tools** | • **Registry Explorer** (Eric Zimmerman) - Manual key inspection<br>• **RECmd** (Eric Zimmerman) - Command-line extraction<br>• **RegRipper** - WordWheelQuery plugin<br>• **ArtiFast** - Automated Searched Strings parsing<br>• **Autopsy** - Registry analysis with search term extraction<br>• **Magnet AXIOM** - Timeline correlation |
| **Additional Info** | • Unlikely for skilled attackers to use File Explorer search<br>• More common in insider threat and user behavior investigations<br>• Normal users may have legitimate searches for work files<br>• Malicious indicators: searches for password files, confidential docs, encryption tools<br>• Does NOT store results, only search terms<br>• Cleared when user clears File Explorer history<br>• Can reveal user interest in specific file types before theft |

---

### Last Visited MRU

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Track applications used to open/save files documented in OpenSaveMRU. Store the last directory path accessed by each application through Open/Save dialogs. |
| **Key Characteristics** | • Correlates with OpenSaveMRU to provide application context<br>• Stores executable filename and last accessed folder path<br>• Binary format values (Vista+) or string format (XP)<br>• MRUListEx/MRUList tracks access order<br>• Values numbered in ascending order by creation time<br>• Helps track "Open/Save As" dialog behavior per application |
| **Locations** | **Windows XP:**<br>`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`<br><br>**Windows 7/8/10/11:**<br>`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`<br><br>**Registry Hive Path:**<br>`C:\Users\<username>\NTUSER.DAT` |
| **Parsing Steps** | 1. Extract NTUSER.DAT registry hive using forensic tool<br>2. Navigate to LastVisitedMRU (XP) or LastVisitedPidlMRU (7+) key<br>3. Parse numbered values to extract:<br>   - Application executable name<br>   - Full path to last accessed folder by that application<br>4. Decode binary format (Vista+) or read string format (XP)<br>5. Examine MRUListEx to determine access order<br>6. Cross-reference with OpenSaveMRU:<br>   - Match application with file accessed<br>   - Establish timeline of file operations<br>7. Identify suspicious application-file associations<br>8. Build comprehensive file access timeline |
| **Tools** | • **Registry Explorer** (Eric Zimmerman) - Manual analysis<br>• **RECmd** (Eric Zimmerman) - Batch processing<br>• **RegRipper** - LastVisitedMRU plugin<br>• **ArtiFast** - Automated LastVisitedMRU parsing<br>• **Autopsy** - Correlation with OpenSaveMRU<br>• **X-Ways Forensics** - Registry parsing |
| **Additional Info** | • Critical for correlating applications with file access<br>• Renamed from LastVisitedMRU to LastVisitedPidlMRU in Vista+<br>• Reveals which program opened/saved which file<br>• Useful for tracking malware that opens legitimate programs<br>• Can identify portable applications run from USB devices<br>• Shows folder paths even if files deleted<br>• Combines with OpenSaveMRU for complete file access picture |

---

### Shortcut Files (Recycle Bin Context)

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Already documented in File Opening Artifacts section. In Recycle Bin context, LNK files can track deleted files that were previously accessed as shortcuts. |
| **Key Characteristics** | • See "File Opening Artifacts - Shortcut Files" for complete details<br>• LNK files may point to deleted files<br>• Can reveal file locations before deletion<br>• Timestamps show when shortcut was last used before file deletion |
| **Locations** | • Same as documented in File Opening Artifacts - Shortcut Files section |
| **Parsing Steps** | • Refer to File Opening Artifacts - Shortcut Files section |
| **Tools** | • Refer to File Opening Artifacts - Shortcut Files section |
| **Additional Info** | • LNK files persist even after target file sent to Recycle Bin<br>• Useful for reconstructing deleted file metadata<br>• Cross-reference with Recycle Bin $I files for deletion evidence |

---

### Recycle Bin

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Temporary storage for deleted items with option to permanently remove or recover. Track file deletion metadata including original filename, path, size, and deletion timestamp. |
| **Key Characteristics** | • **Windows Vista/7/8/10/11**: Two files per deletion: `$I` (metadata) and `$R` (file content)<br>• **Windows XP/2003**: Single INFO2 file containing metadata for all deletions<br>• Stores original file name, path, size, deletion date/time<br>• Organized by user SID in separate subdirectories<br>• `$R` file contains actual file data (renamed with random 6-char string)<br>• `$I` file stores metadata: deletion time, original path, file size |
| **Locations** | **Windows Vista/7/8/10/11:**<br>`C:\$Recycle.Bin\{SID}\$I######` (metadata)<br>`C:\$Recycle.Bin\{SID}\$R######` (file content)<br><br>**Windows XP/2003:**<br>`C:\RECYCLER\{SID}\INFO2` (metadata for all deletions)<br><br>**Note:** SID = Security Identifier for user account |
| **Parsing Steps** | 1. Navigate to `C:\$Recycle.Bin\` using forensic tool<br>2. Identify user SID subfolder for target user<br>3. **For Vista+ ($I/$R files):**<br>   - Pair each `$I` file with corresponding `$R` file (same suffix)<br>   - Parse `$I` file structure:<br>     • Original file name<br>     • Original file path<br>     • File size<br>     • Deletion timestamp<br>   - Extract `$R` file for actual content<br>4. **For XP (INFO2 file):**<br>   - Parse INFO2 binary structure<br>   - Extract records for each deleted file<br>5. Correlate deletion times with user activity<br>6. Recover files if investigation requires<br>7. Check MFT for unallocated but readable `$I` files |
| **Tools** | • **Rifiuti2** - Parse INFO2 and $I files<br>• **Velocir aptor** - Windows.Forensics.RecycleBin artifact<br>• **Autopsy** - Automated Recycle Bin parsing<br>• **FTK Imager** - Extract $I and $R files<br>• **Recycle Bin Analyzer** - GUI tool for parsing<br>• **X-Ways Forensics** - Recycle Bin recovery<br>• **EnCase** - Deleted file analysis |
| **Additional Info** | • Vista+ format change: separate metadata per file (scalability)<br>• `$I` files may persist in MFT even after permanent deletion<br>• User can bypass Recycle Bin (Shift+Delete = permanent deletion)<br>• Files deleted from network shares or external drives may not use Recycle Bin<br>• Recycle Bin size limits may cause automatic permanent deletion<br>• Useful for anti-forensics detection (user clearing Recycle Bin)<br>• Critical for proving intentional file deletion vs. accidental |

---

### Typed Paths

| **Field** | **Details** |
|-----------|-------------|
| **Purpose** | Record last 25 paths typed or inserted into File Explorer address bar. Track user navigation to specific folders, network shares, and locations. |
| **Key Characteristics** | • Stores last 25 full paths manually typed in File Explorer<br>• Values named as "url1", "url2", "url3" (url1 = most recent)<br>• Names rotate: new path becomes url1, previous url1 becomes url2, etc.<br>• Paths do NOT appear instantly; committed when File Explorer window closes<br>• Multiple open windows: last closed window overwrites registry<br>• Can track local paths, network shares, removable devices |
| **Locations** | **Windows 7/8/10/11:**<br>`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`<br><br>**Registry Hive Path:**<br>`C:\Users\<username>\NTUSER.DAT` |
| **Parsing Steps** | 1. Extract NTUSER.DAT registry hive using forensic tool<br>2. Navigate to TypedPaths key<br>3. Examine values named url1, url2, url3, ..., url25<br>4. Extract full paths from string values<br>5. Determine access order (url1 = most recent)<br>6. Analyze paths for:<br>   - Access to network shares (\\\\server\\share)<br>   - External drive letters (D:, E:, F:, etc.)<br>   - Suspicious folder locations (Temp, hidden folders)<br>   - Administrative shares (C$, Admin$)<br>7. Correlate with ShellBags for folder browsing timeline<br>8. Check for lateral movement indicators (remote share access) |
| **Tools** | • **Registry Explorer** (Eric Zimmerman) - Manual inspection<br>• **RECmd** (Eric Zimmerman) - Batch extraction<br>• **RegRipper** - TypedPaths plugin<br>• **ArtiFast** - Automated Typed Paths parsing<br>• **Autopsy** - Registry analysis module<br>• **Magnet AXIOM** - Path correlation |
| **Additional Info** | • Max 25 entries stored before oldest purged<br>• User must close File Explorer window for registry update<br>• Multiple windows: last closed overwrites unique entries from first closed<br>• Useful for tracking intentional navigation to specific locations<br>• Can reveal attacker reconnaissance (browsing admin shares)<br>• Network paths indicate lateral movement or data exfiltration staging<br>• Does NOT capture paths accessed via shortcuts or "Recent" folder<br>• Critical for insider threat investigations (accessing restricted shares) |

---
