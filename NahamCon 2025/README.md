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

Running `binwalk ` on the given file revealed 4 embedded files within it
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/martian2.png">

Extracted files had an image revealing the flag
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/martian3.png">

```
flag{0db031ac265b3e6538aff0d9f456004f}
```
---

# Method In The Madness [Web]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/method1.png">

The challenge featured a web page with 6 checkboxes, each initially unchecked.
By experimenting with different HTTP request methods, it became clear that each checkbox responded to a specific HTTP method. The objective was to "check" all boxes by sending the HTTP method for each one.

Each checkbox responded only to a specific HTTP method: `GET , POST , PUT , DELETE , PATCH , OPTIONS`

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/method2.png">

```
flag{bd399cb9c3a8b857588d8e13f490b6fd}
```
---

# Infinite Queue [Web]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/infinite1.png">

This challenge simulated a ticket queue system. Upon submitting an email, the server responded with: An estimated wait time , `A JWT token`
This JWT was used to check queue status, and it included fields like: email , queue_time (in epoch timestamp) , exp (token expiration)

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/infinite3.png">

Inspecting the token revealed that:
- The queue_time was set in the future (2026), creating a long wait.
- Changing queue_time to a past date (e.g., 2025) and resending the JWT resulted in an error message.
- This error leaked the JWT secret key.
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/infinite4.png">

### Exploitation
- Decoded the original JWT
- Modified the queue_time to a valid past timestamp (e.g., early 2025)
- Re-signed the JWT using the leaked secret
- Sent the forged JWT in the request
- This bypassed the queue, returning: “Ticket is ready”

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/infinite5.png">

### Final Step
- Accessing the purchase endpoint with the forged JWT led to a ticket purchase screen. On completing the purchase, a PDF ticket was downloaded.
- Opening the PDF revealed the flag.

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/infinite6.png">
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/infinite7.png">

```
flag{b1bd4795215a7b81699487cc7e32d936}
```
---

# NoSequel [Web]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/seq1.png">

This challenge presented a **search interface** for querying a database with two collections:
- `Movies`
- `Flags`

While the **Movies** collection did not support complex queries, the **Flags** collection accepted **MongoDB-style queries**, including `$regex`.
The interface hinted that regex queries like:
```json
title: { "$regex": "The" }
```

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/seq2.png">

Exploitation
- Switched collection to Flags
- Crafted a regex query for the flag field:
```
flag: {$regex: "flag{"}
```
- Used Burp Suite Intruder to automate character-by-character brute forcing:
- Used a character set [0-9a-f] to match the expected 34-character hex format
- Monitored server responses for valid matches (Pattern matched in response)
- Repeated until the entire flag was recovered.

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/seq3.png">

```
flag{4cb8649d9ecb0ec59d1784263602e686}
```
---
# Quartet [Forensics]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/qua1.png">

The challenge provided four binary files:
- `quartet.z01`
- `quartet.z02`
- `quartet.z03`
- `quartet.z04`
These were parts of a **multi-part ZIP archive**.


Approach : 
1. **Concatenated** all the parts in the correct order to reconstruct the ZIP.
2. Extract the zip: Despite warnings about multi-part archive structure, the extraction succeeded and produced a file named `quartet.jpeg`.
3. Searched for the flag inside the extracted JPEG using strings

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/qua2.png">

```
flag{8f667b09d0e821f4e14d59a8037eb376}
```
---
# Screenshot [Forensizs]
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/ss1.png">

The challenge provided a **screenshot of a hex dump** of a ZIP file (`flag.zip`).
<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/Screenshot.png">

Approach
1. **Performed OCR** (Optical Character Recognition) on the screenshot to extract the **hex values** of the ZIP file from the Screenshot.png.
2. Script to reconstruct the zip from hex dump:

```python
# Raw hex data broken into groups (space-separated)
hex_dump = """
504b 0304 3300 0100 6300 2f02 b55a 0000
0000 4300 0000 2700 0000 0800 0b00 666c
6167 2e74 7874 0199 0700 0200 4145 0300
003d 42ff d1b3 5f95 0314 24f6 8b65 c3f5
7669 f14e 8df0 003f e240 b3ac 3364 859e
4c2d bc3c 36f2 d4ac c403 7613 85af e4e3
f90f bd29 d91b 614b a2c6 efde 11b7 1bcc
907a 72ed 504b 0102 3f03 3300 0100 6300
2f02 b55a 0000 0000 4300 0000 2700 0000
0800 2f00 0000 0000 0000 2080 b481 0000
0000 666c 6167 2e74 7874 0a00 2000 0000
0000 0100 1800 8213 8543 07ca db01 0000
0000 0000 0000 0000 0000 0000 0000 0199
0700 0200 4145 0300 0050 4b05 0600 0000
0001 0001 0065 0000 0074 0000 0000 00
"""

# Clean and convert to binary
hex_cleaned = hex_dump.replace("\n", "").replace(" ", "")
zip_bytes_from_blocks = bytes.fromhex(hex_cleaned)

# Save to file
block_output_path = "flag.zip"
with open(block_output_path, "wb") as f:
    f.write(zip_bytes_from_blocks)

block_output_path, len(zip_bytes_from_blocks)
```
3. Extracting the flag.zip with given password gives the flag.txt revealing the flag.

```
flag{907e5bb257cd5fc818e88a13622f3d46}
```
---

# The Oddeyssey [pwn]

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/odd1.png">

This challenge simulated reading **The Odyssey**, split into 24 books with paragraphs displayed one at a time.

Challenge Behavior
- Upon connecting to the remote server, the user is shown one paragraph at a time.
- After each paragraph, the server prompts:  `Press Enter to continue`
- The user must continue pressing Enter repeatedly through all 24 books.
- After reading all, the **flag** is displayed.


Exploitation
Automated script using **pwntools** :

```python
from pwn import *

# Set up pwntools for remote connection
host = "challenge.nahamcon.com"
port = 31491

# Start connection
conn = remote(host, port)

# Read continuously until we get the flag
while True:
  line = conn.recvline(timeout=10)
  if not line:
      break

  decoded = line.decode(errors='ignore').strip()
  print(decoded)

  # Automatically continue when prompted
  if decoded.lower().startswith("press enter"):
      conn.sendline()

  # Stop if the flag is found
  if "flag{" in decoded:
      print(f"\nFlag found: {decoded}")
      break

# Clean exit
conn.close()
```

<img src="https://raw.githubusercontent.com/BharathRam125/CTF-writeups/main/NahamCon%202025/images/odd2.png">

```
flag{0b51aae6b09b85d1bb13b0b8c3003a6a}
```

---


   










