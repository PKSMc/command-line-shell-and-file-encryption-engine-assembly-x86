DES Command-Line Shell and Classical DES Engine
================================================

Target
------
x86 32-bit protected mode, MASM (COFF), Windows 10/11, Irvine32.

Team information (complete before submission)
---------------------------------------------
1. Name / student ID / responsibility:
2. Name / student ID / responsibility:
3. Name / student ID / responsibility:
4. Name / student ID / responsibility:

Files
-----
module_a.asm             REPL, FSM-style token parser, validation, dispatch
des_key_schedule.asm     odd parity check, PC-1, 28-bit rotations, PC-2
module_C.asm             IP, E, S-boxes, P, 16 Feistel rounds, IP^-1,
                         encryption/decryption, ECB, PKCS#7, file I/O
displayHexDump.asm       16-byte hexadecimal and ASCII file dump
Histrogram.asm           256-bin histogram and top five occurrences
des_selftest.asm         official single-block known-answer test
build.bat                assembles, links, and runs the known-answer test

Build
-----
1. Install Irvine32 under C:\Irvine, or set IRVINE to its directory.
2. Open an "x86 Native Tools Command Prompt for VS" (not x64).
3. Change to this directory and run:

       build.bat

The build creates des_shell.exe and des_selftest.exe. A correct build prints:

       DES NIST known-answer test: PASSED

Known-answer vector
-------------------
Plaintext : 0123456789ABCDEF
Key       : 133457799BBCDFF1
Ciphertext: 85E813540F0AB405

Run and commands
----------------
Run des_shell.exe, then use:

KEYGEN 0x133457799BBCDFF1
ENCRYPT "secret.txt" 0x133457799BBCDFF1
DECRYPT "secret.txt.enc" 0x133457799BBCDFF1
DUMP "secret.txt.enc"
STATS "secret.txt.enc"
CLEAR
EXIT

DUMP is configured as a 16-byte preview and therefore displays only offset
00000000. The encrypted file itself still retains all ECB/PKCS#7 blocks.

ENCRYPT writes <input>.enc. DECRYPT writes <input>.dec. Encryption always adds
PKCS#7 padding, including a full 08 block when the plaintext length is already
a multiple of eight. Decryption validates every padding byte and rejects empty,
truncated, or incorrectly padded ciphertext.

Implementation notes
--------------------
- No .IF, .WHILE, or .REPEAT directives are used in parser or cipher loops.
- DES is implemented locally; no external cryptographic library is called.
- FIPS bit numbering is MSB-first. Blocks, keys, and six-byte subkeys are stored
  in display/network order so the official known-answer vector is unambiguous.
- Procedures use explicit EBP stack frames, preserve caller registers, and
  return status/results in EAX. STDCALL procedures remove their parameters.
- The supplied module_a.obj was inspected as an existing 32-bit Intel COFF
  object, but it is not linked because it represents the earlier stub-based
  module_a.asm and must be rebuilt from the corrected source.
- Output names are limited to 254 characters before the .enc/.dec suffix.
- File encryption uses an eight-byte streaming loop, so plaintext size is not
  limited by a fixed in-memory file buffer.

Status codes returned by Module C
---------------------------------
0 success
1 bad argument
2 unable to open input
3 unable to create output
4 read/crypto error
5 write error
6 invalid ciphertext or PKCS#7 padding
