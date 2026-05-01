# YARA Rules

![YARA](https://img.shields.io/badge/YARA-4.5-blue?style=flat&logo=virustotal&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Custom malware detection rules for threat hunting, incident response, and DFIR.

---

## 📋 Rules

| Rule | Type | Target | Version |
|------|------|--------|---------|
| [MAL_RANSOM_Cerber.yar](MAL_RANSOM_Cerber.yar) | Ransomware | Cerber cryptor binary | 1.0 |

---

## 🔍 MAL_RANSOM_Cerber

Detects Cerber ransomware cryptor binaries using a correlation of:

- **Ransom indicators:** Ransom notes, encrypted file extensions
- **Persistence mechanisms:** Registry Run keys, AutoRun
- **C2 infrastructure:** Hardcoded IP addresses and ranges
- **Malware artifacts:** Mutex, C2 tag, cryptor markers

**Detection Logic:**
- **Path 1:** Ransom indicator + technical confirmation
- **Path 2:** Multiple C2 indicators + persistence mechanism

**References:**
- [VirusTotal Sample](https://www.virustotal.com/gui/file/c5b70adfa23ae3802e8b51560c64635911869b412cc1e8c1f6e1904334c0abe9/detection)

---

## 🧪 Usage

```bash
# Scan a single file
yara MAL_RANSOM_Cerber.yar suspicious_file.exe

# Scan a directory recursively
yara -s -r MAL_RANSOM_Cerber.yar /path/to/samples/

# Validate syntax
yara MAL_RANSOM_Cerber.yar /dev/null

---

📄 License

MIT © 2026 Pablo