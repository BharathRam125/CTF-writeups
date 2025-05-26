![image](https://github.com/user-attachments/assets/feabdaa6-d68c-483e-9753-bf7a0cda1bfd)
# 🏁 NahamCon 2025

## Deflation Gangster [Reverse Engineering]
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/DeflationGangster1.png">
The attachment had a windows lnk file (ImportantDocs.lnk) which had a hidden powershell script reading bytes from a zip file (ImportantDocs.zip) and saving it as flag.txt but there was no embedded zip files found in the attachment.

Then strings on the attachment (gangster.zip)  revealed a base64 encoded text. On the decoding, it revealed the flag.
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/DeflationGangster2.png">
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/DeflationGangster3.png">


```bash
flag{af1150f07f900872e162e230d0ef8f94}
```
---

## FlagsFlagsFlags [Reverse Engineering]
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/FlagsFlagsFlags1.png">

The binary checks a user-supplied flag by performing byte-by-byte comparisons between the input and a hidden flag. 

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/FlagsFlagsFlags2.png">

The disassembly had lots of fake flags.

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/FlagsFlagsFlags3.png">

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/FlagsFlagsFlags4.png">

The main comparison happens at `0x4942D6`, where `cmp r9b, r8b` is executed. This is where the byte-by-byte comparission happesns.

Using GDB set break point at the address 0x4942D6 and check the contents of the registers r9b and r8b.

r9b → user input

r8b → flag byte

then repeat the process byte by byte with the correct flag byte to get the complete flag.

```
gdb ./flagsflagsflags
break *0x4942D6
run
info registers r9 r8
```
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/FlagsFlagsFlags6.png">
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/FlagsFlagsFlags5.png">

```bash
flag{20dec9363618a397e9b2a0bf5a35b2e3}
```
---
## Puzzle Pieces [Forensics]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/Puzzle1.png">
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/Puzzle2.png">

The challenge provided an attachment containing multiple .exe files. Executing each individually caused a command prompt to flash and close immediately, revealing no visible output.

To capture the output, each .exe was executed with output redirection using:
```
program.exe >> output.txt
```
Each executable, when run this way, output four characters to the file.

Upon analyzing the executables' last modified timestamps, it was observed that the .exe files were meant to be executed in chronological order. Running the programs in order based on last modified time resulted in the correct sequence of character outputs.

Concatenating the outputs in this order revealed the complete flag.

```
flag{512faff5e7d89c9b8bd4b9517af9bfaa}
```
---
## The Martian [Misc]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/martian1.png">
Running `binwalk` on the given file revealed 4 embedded files within it:
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/martian2.png">

Extracted files had an image revealing the flag
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/martian3.png">

```
flag{0db031ac265b3e6538aff0d9f456004f}
```
---









