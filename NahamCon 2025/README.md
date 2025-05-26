
# 🏁 NahamCon 2025

## Deflation Gangster [Reverse Engineering]
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/DeflationGangster1.png)">
The attachment had a windows lnk file (ImportantDocs.lnk) which had a hidden powershell script reading bytes from a zip file (ImportantDocs.zip) and saving it as flag.txt but there was no embedded zip files found in the attachment.

Then strings on the attachment (gangster.zip)  revealed a base64 encoded text. On the decoding, it revealed the flag.
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/DeflationGangster2.png)">
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/DeflationGangster3.png)">


```bash
flag{af1150f07f900872e162e230d0ef8f94}
```
---
