# Review against the assignment and FIPS 46-3

## Scope reviewed

The review covered both supplied PDFs and every attached artifact:

- `module_a.asm` and `module_a.obj`
- `module_C.asm` / `module_C.inc`
- `Histrogram.asm` / `_Hisrtrogram.inc`
- `displayHexDump.asm` / `displayHex_Dump.inc`
- `des_key_schedule.asm` / `des_key_schedule.inc`

The supplied `module_a.obj` is a 32-bit Intel COFF object (`Machine = 014Ch`),
with four sections (`.text`, `.data`, `STACK`, `.drectve`), 50 symbols, and 73
text relocations. It was built from the old stub-based source and therefore is
not suitable for the corrected link. The delivered `module_a.obj` is a fresh
build from the corrected source.

## Principal faults in the supplied source

### Module A

- `KEYGEN`, `ENCRYPT`, `DECRYPT`, `DUMP`, and `STATS` dispatched only to stubs.
- Stack cleanup mixed caller-cleanup with intended STDCALL interfaces.
- `ParseHex64` used inconsistent failure conventions between the high and low
  halves and exposed success through EBX instead of EAX.
- Quoted-token loops had no capacity check, unmatched-quote error, or rejection
  of trailing extra tokens.
- Individual procedures did not consistently preserve caller state or return a
  status through EAX.

### Module B

- The supplied key schedule was the strongest component. Its PC-1, rotation
  schedule, PC-2, and parity checker were retained after table verification.
- It was not integrated with the shell or cipher in the supplied project.

### Module C

- Subkeys were allocated but never generated before encryption.
- The S-box stage treated one byte as one S-box input. DES requires eight
  consecutive six-bit groups, with row selected by the outer bits and column by
  the middle four bits.
- The original P-permutation extracted source bits in the wrong direction.
- DWORD loads/stores mixed little-endian x86 layout with FIPS display-order
  bit numbering, so the official test vector could not be reliable.
- `Apply_PKCS7_Padding` used `rep stosb` and then added ECX after REP had reduced
  ECX to zero, leaving the stored length unchanged.
- There was no reverse-subkey decryption path, padding validation/removal, file
  input/output transform, or reusable module interface.
- The source contained a separate interactive `main`, conflicting with the
  shell executable's entry point.

### Module D

- Both files were standalone debug programs with their own `main` procedures.
- Interfaces depended on undocumented register inputs instead of stack
  parameters.
- The original top-five routine destroyed the only histogram while reporting.
- There was no real file-loading integration for `DUMP` or `STATS`.

## Corrected design

- `module_a.asm` owns the single shell entry point and an explicit FSM-style
  tokenizer. It handles quoted filenames, exact arity, extra tokens, key syntax,
  and odd parity.
- `des_key_schedule.asm` produces 16 six-byte subkeys in FIPS display order.
- `module_C.asm` implements IP, expansion E, subkey XOR, all eight S-boxes, P,
  16 Feistel rounds, the final swap, IP inverse, forward/reverse key order, ECB,
  streaming file I/O, and strict PKCS#7 add/remove validation.
- `displayHexDump.asm` prints 16 bytes per line, an eight-digit offset, aligned
  hex columns, and printable ASCII with `.` outside `20h..7Eh`.
- `Histrogram.asm` computes all 256 bins and reports the top five from a copy so
  the source histogram remains intact. The shell output follows the assignment
  screenshot: total size, entropy-status text, and Top 5 only; equal counts are
  ordered by first appearance in the file.
- The parser and cryptographic loops use CMP/TEST plus conditional jumps. No
  `.IF`, `.WHILE`, or `.REPEAT` directive appears in the source.

## Verification performed here

- Extracted PC-1, PC-2, shifts, IP, inverse IP, E, P, and all eight S-box tables
  directly from the corrected assembly and evaluated an independent reference
  model.
- Verified `K1 = 1B02EFFC7072` and `K16 = CB3D8B0E17F5` for key
  `133457799BBCDFF1`.
- Verified encryption `0123456789ABCDEF -> 85E813540F0AB405`.
- Verified reverse-key decryption recovers `0123456789ABCDEF`.
- Scanned all ASM/INC files for forbidden high-level control directives and
  leftover stubs/placeholders.

A native build was completed with MASM32 `ml.exe`/`link.exe` and Irvine32. The
standalone known-answer executable printed `DES NIST known-answer test: PASSED`.
The interactive shell was then exercised with KEYGEN, ENCRYPT, DECRYPT, DUMP,
STATS, and EXIT. A 30-byte test file encrypted to 32 bytes and decrypted back to
an exact byte-for-byte copy. `build.bat` reproduces the build with either an x86
Visual Studio tools prompt or a conventional `C:\masm32` installation.

## Remaining cautions

- The sample transcript shows a 16-byte plaintext becoming 16 bytes of
  ciphertext, but PKCS#7 requires an additional full `08 08 08 08 08 08 08 08`
  block when the input length is already divisible by eight. This implementation
  follows the explicit PKCS#7 requirement, so that sample input produces 24
  encrypted bytes. The raw one-block NIST vector is tested by `des_selftest.exe`
  without file padding.
- A failed decrypt can leave a partial `.dec` file because output is streamed;
  check the returned status before using it.
- Output names append `.enc` or `.dec` and require room for the suffix.
- DES and ECB are obsolete for real security; they are implemented here only
  because the course assignment explicitly requires classical DES/ECB.
- Complete the team member section in `readme.txt` before submission.
