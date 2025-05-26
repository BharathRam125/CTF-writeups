
# 🏁 NahamCon 2025

## Deflation Gangster [REVERSE Engineering]
<img src="/images/DeflationGangster1.png)">
The attachment had a windows lnk file (ImportantDocs.lnk) which had a hidden powershell script reading bytes from a zip file (ImportantDocs.zip) and saving it as flag.txt but there was no embedded zip files found in the attachment.

Then strings on the attachment (gangster.zip)  revealed a base64 encoded text. On the decoding, it revealed the flag.
<img src="/images/DeflationGangster2.png)">
<img src="/images/DeflationGangster3.png)">


```bash
flag{af1150f07f900872e162e230d0ef8f94}
```
---
