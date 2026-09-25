; =========================================================================
; Module A: Shell Core & FSM Command Parser
; Target: x86 32-bit Protected Mode (MASM / Irvine32)
; =========================================================================

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

; --- Buffer Sizes ---
MAX_CMD_LEN     EQU 256
MAX_ARG_LEN     EQU 256

.data
    ; Prompts and Messages
    promptStr       BYTE "DES-SHELL> ", 0
    msgWelcome      BYTE "=== DES Command-Line Shell Initialized ===", 0Dh, 0Ah, 0
    msgExit         BYTE "Exiting DES Command-Line Shell...", 0Dh, 0Ah, 0
    
    ; Error Messages
    errUnknownCmd   BYTE "Error: Unknown command. Type KEYGEN, ENCRYPT, DECRYPT, DUMP, STATS, CLEAR, or EXIT.", 0Dh, 0Ah, 0
    errMissingArg   BYTE "Error: Missing required argument(s).", 0Dh, 0Ah, 0
    errInvalidHex   BYTE "Error: Invalid 64-bit hex key format (e.g., 0x133457799BBCDFF1).", 0Dh, 0Ah, 0

    ; Command String Constants for Comparison
    cmd_KEYGEN      BYTE "KEYGEN", 0
    cmd_ENCRYPT     BYTE "ENCRYPT", 0
    cmd_DECRYPT     BYTE "DECRYPT", 0
    cmd_DUMP        BYTE "DUMP", 0
    cmd_STATS       BYTE "STATS", 0
    cmd_CLEAR       BYTE "CLEAR", 0
    cmd_EXIT        BYTE "EXIT", 0

    ; Output Messages for Module Integration
    msgEncSuccess   BYTE "File encrypted successfully.", 0Dh, 0Ah, 0
    msgDecSuccess   BYTE "File decrypted successfully.", 0Dh, 0Ah, 0

    ; Command Line Parsing Buffers
    inputBuffer     BYTE MAX_CMD_LEN DUP(0)
    cmdVerb         BYTE MAX_ARG_LEN DUP(0)
    arg1Buffer      BYTE MAX_ARG_LEN DUP(0)
    arg2Buffer      BYTE MAX_ARG_LEN DUP(0)

    ; Parsed Key Storage (64-bit)
    keyHigh         DWORD 0     ; Bits 63..32
    keyLow          DWORD 0     ; Bits 31..0

.code

; =========================================================================
; Procedure: Main / Shell Loop
; =========================================================================
main PROC
    call Clrscr
    mov edx, OFFSET msgWelcome
    call WriteString

ShellLoop:
    ; 1. Print Shell Prompt
    mov edx, OFFSET promptStr
    call WriteString

    ; 2. Read User Input Line
    mov edx, OFFSET inputBuffer
    mov ecx, MAX_CMD_LEN - 1
    call ReadString
    
    ; If empty input, re-prompt
    cmp eax, 0
    je ShellLoop

    ; 3. Parse Command Line via FSM
    push OFFSET inputBuffer
    call ParseCommandLine
    add esp, 4                  ; Clean stack

    ; Check if command verb is empty
    cmp BYTE PTR [cmdVerb], 0
    je ShellLoop

    ; 4. Dispatch Command
    push OFFSET cmdVerb
    call DispatchCommand
    add esp, 4                  ; Clean stack

    ; If EAX == 1, EXIT command was given
    cmp eax, 1
    je ShellExit

    jmp ShellLoop

ShellExit:
    mov edx, OFFSET msgExit
    call WriteString
    exit
main ENDP


; =========================================================================
; Procedure: ParseCommandLine (FSM String Parser)
; Parses inputBuffer -> cmdVerb, arg1Buffer, arg2Buffer
; =========================================================================
ParseCommandLine PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    ; Clear output buffers
    push OFFSET cmdVerb
    call ClearBuffer
    push OFFSET arg1Buffer
    call ClearBuffer
    push OFFSET arg2Buffer
    call ClearBuffer
    add esp, 12

    mov esi, [ebp + 8]          ; ESI = input string pointer
    
    ; ---------------------------------------------------------------------
    ; State 1: Extract Command Verb
    ; ---------------------------------------------------------------------
    call SkipSpaces
    mov edi, OFFSET cmdVerb
    mov ecx, 0                  ; Length counter

ParseCmdLoop:
    mov al, [esi]
    cmp al, 0
    je ParseDone
    cmp al, ' '
    je CmdParsed
    cmp al, 09h                 ; Tab character
    je CmdParsed
    
    mov [edi], al
    inc esi
    inc edi
    inc ecx
    cmp ecx, MAX_ARG_LEN - 1
    jb ParseCmdLoop

CmdParsed:
    mov BYTE PTR [edi], 0       ; Null terminate cmdVerb

    ; ---------------------------------------------------------------------
    ; State 2: Extract Arg1 (Handles quotes for filenames)
    ; ---------------------------------------------------------------------
    call SkipSpaces
    mov al, [esi]
    cmp al, 0
    je ParseDone

    mov edi, OFFSET arg1Buffer
    mov ecx, 0

    ; Check if argument starts with double quotes
    cmp al, '"'
    jne ParseArg1Unquoted
    
    inc esi                     ; Skip opening quote
ParseArg1Quoted:
    mov al, [esi]
    cmp al, 0
    je ParseDone
    cmp al, '"'
    je Arg1QuoteDone
    mov [edi], al
    inc esi
    inc edi
    jmp ParseArg1Quoted
Arg1QuoteDone:
    inc esi                     ; Skip closing quote
    jmp Arg1Parsed

ParseArg1Unquoted:
    mov al, [esi]
    cmp al, 0
    je ParseDone
    cmp al, ' '
    je Arg1Parsed
    cmp al, 09h
    je Arg1Parsed
    mov [edi], al
    inc esi
    inc edi
    jmp ParseArg1Unquoted

Arg1Parsed:
    mov BYTE PTR [edi], 0       ; Null terminate arg1Buffer

    ; ---------------------------------------------------------------------
    ; State 3: Extract Arg2
    ; ---------------------------------------------------------------------
    call SkipSpaces
    mov al, [esi]
    cmp al, 0
    je ParseDone

    mov edi, OFFSET arg2Buffer
    mov ecx, 0

    cmp al, '"'
    jne ParseArg2Unquoted
    inc esi
ParseArg2Quoted:
    mov al, [esi]
    cmp al, 0
    je ParseDone
    cmp al, '"'
    je Arg2QuoteDone
    mov [edi], al
    inc esi
    inc edi
    jmp ParseArg2Quoted
Arg2QuoteDone:
    inc esi
    jmp Arg2Parsed

ParseArg2Unquoted:
    mov al, [esi]
    cmp al, 0
    je ParseDone
    cmp al, ' '
    je Arg2Parsed
    cmp al, 09h
    je Arg2Parsed
    mov [edi], al
    inc esi
    inc edi
    jmp ParseArg2Unquoted

Arg2Parsed:
    mov BYTE PTR [edi], 0       ; Null terminate arg2Buffer

ParseDone:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
ParseCommandLine ENDP


; =========================================================================
; Helper Procedure: SkipSpaces (Advances ESI past ' ' and '\t')
; =========================================================================
SkipSpaces PROC
SkipLoop:
    mov al, [esi]
    cmp al, ' '
    je DoSkip
    cmp al, 09h                 ; Tab
    je DoSkip
    ret
DoSkip:
    inc esi
    jmp SkipLoop
SkipSpaces ENDP


; =========================================================================
; Helper Procedure: ClearBuffer (Fills a 256-byte buffer with 0)
; =========================================================================
ClearBuffer PROC
    push ebp
    mov ebp, esp
    push edi
    push ecx
    push eax

    mov edi, [ebp + 8]
    mov ecx, MAX_ARG_LEN
    mov al, 0
ClearLoop:
    mov [edi], al
    inc edi
    loop ClearLoop

    pop eax
    pop ecx
    pop edi
    pop ebp
    ret
ClearBuffer ENDP


; =========================================================================
; Procedure: DispatchCommand (Evaluates verb and routes execution)
; Returns EAX = 1 if EXIT command was called, 0 otherwise
; =========================================================================
DispatchCommand PROC
    push ebp
    mov ebp, esp
    push ebx

    ; 1. Check CLEAR
    push OFFSET cmdVerb
    push OFFSET cmd_CLEAR
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne CheckExit
    call Clrscr
    mov eax, 0
    jmp DispatchDone

CheckExit:
    ; 2. Check EXIT
    push OFFSET cmdVerb
    push OFFSET cmd_EXIT
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne CheckKeygen
    mov eax, 1                  ; Signal Exit to caller
    jmp DispatchDone

CheckKeygen:
    ; 3. Check KEYGEN <64-bit Hex Key>
    push OFFSET cmdVerb
    push OFFSET cmd_KEYGEN
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne CheckEncrypt
    
    cmp BYTE PTR [arg1Buffer], 0
    je ErrMissing
    push OFFSET arg1Buffer
    call ParseHex64
    add esp, 4
    cmp ebx, 0                  ; Error check from ParseHex64
    je ErrHex
    mov keyHigh, edx
    mov keyLow, eax
    
    ; Call Module B Procedure
    push keyHigh
    push keyLow
    call ModuleB_KeyGen
    add esp, 8
    mov eax, 0
    jmp DispatchDone

CheckEncrypt:
    ; 4. Check ENCRYPT <filename> <64-bit Hex Key>
    push OFFSET cmdVerb
    push OFFSET cmd_ENCRYPT
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne CheckDecrypt

    cmp BYTE PTR [arg1Buffer], 0
    je ErrMissing
    cmp BYTE PTR [arg2Buffer], 0
    je ErrMissing

    push OFFSET arg2Buffer
    call ParseHex64
    add esp, 4
    cmp ebx, 0
    je ErrHex
    mov keyHigh, edx
    mov keyLow, eax

    ; Call Module C Encryption Interfacing
    push keyHigh
    push keyLow
    push OFFSET arg1Buffer
    call ModuleC_Encrypt
    add esp, 12
    mov eax, 0
    jmp DispatchDone

CheckDecrypt:
    ; 5. Check DECRYPT <filename> <64-bit Hex Key>
    push OFFSET cmdVerb
    push OFFSET cmd_DECRYPT
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne CheckDump

    cmp BYTE PTR [arg1Buffer], 0
    je ErrMissing
    cmp BYTE PTR [arg2Buffer], 0
    je ErrMissing

    push OFFSET arg2Buffer
    call ParseHex64
    add esp, 4
    cmp ebx, 0
    je ErrHex
    mov keyHigh, edx
    mov keyLow, eax

    ; Call Module C Decryption Interfacing
    push keyHigh
    push keyLow
    push OFFSET arg1Buffer
    call ModuleC_Decrypt
    add esp, 12
    mov eax, 0
    jmp DispatchDone

CheckDump:
    ; 6. Check DUMP <filename>
    push OFFSET cmdVerb
    push OFFSET cmd_DUMP
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne CheckStats

    cmp BYTE PTR [arg1Buffer], 0
    je ErrMissing

    push OFFSET arg1Buffer
    call ModuleD_Dump
    add esp, 4
    mov eax, 0
    jmp DispatchDone

CheckStats:
    ; 7. Check STATS <filename>
    push OFFSET cmdVerb
    push OFFSET cmd_STATS
    call StringEqualsIgnoreCase
    add esp, 8
    cmp eax, 1
    jne ErrUnknown

    cmp BYTE PTR [arg1Buffer], 0
    je ErrMissing

    push OFFSET arg1Buffer
    call ModuleD_Stats
    add esp, 4
    mov eax, 0
    jmp DispatchDone

ErrMissing:
    mov edx, OFFSET errMissingArg
    call WriteString
    mov eax, 0
    jmp DispatchDone

ErrHex:
    mov edx, OFFSET errInvalidHex
    call WriteString
    mov eax, 0
    jmp DispatchDone

ErrUnknown:
    mov edx, OFFSET errUnknownCmd
    call WriteString
    mov eax, 0

DispatchDone:
    pop ebx
    pop ebp
    ret
DispatchCommand ENDP


; =========================================================================
; Helper Procedure: StringEqualsIgnoreCase
; Returns EAX = 1 if match, 0 if mismatch
; =========================================================================
StringEqualsIgnoreCase PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov esi, [ebp + 8]          ; Str1
    mov edi, [ebp + 12]         ; Str2

CompareLoop:
    mov al, [esi]
    mov bl, [edi]

    ; Convert AL to uppercase
    cmp al, 'a'
    jb UpperAL
    cmp al, 'z'
    ja UpperAL
    sub al, 32
UpperAL:

    ; Convert BL to uppercase
    cmp bl, 'a'
    jb UpperBL
    cmp bl, 'z'
    ja UpperBL
    sub bl, 32
UpperBL:

    cmp al, bl
    jne CompareMismatch

    cmp al, 0
    je CompareMatch

    inc esi
    inc edi
    jmp CompareLoop

CompareMatch:
    mov eax, 1
    jmp CompareDone

CompareMismatch:
    mov eax, 0

CompareDone:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
StringEqualsIgnoreCase ENDP


; =========================================================================
; Helper Procedure: ParseHex64
; Parses hex string (e.g., "0x133457799BBCDFF1" or "133457799BBCDFF1")
; Output: EDX:EAX = 64-bit key, EBX = 1 (Success) / 0 (Fail)
; =========================================================================
ParseHex64 PROC
    push ebp
    mov ebp, esp
    push esi
    push ecx
    push edi

    mov esi, [ebp + 8]          ; Pointer to hex string

    ; Check for '0x' or '0X' prefix
    mov al, [esi]
    cmp al, '0'
    jne CheckHexLen
    mov al, [esi + 1]
    cmp al, 'x'
    je SkipPrefix
    cmp al, 'X'
    jne CheckHexLen
SkipPrefix:
    add esi, 2

CheckHexLen:
    ; Count hex digits (must be 16 characters)
    mov edi, esi
    mov ecx, 0
CountHexDigits:
    mov al, [edi]
    cmp al, 0
    je DoneCount
    inc ecx
    inc edi
    jmp CountHexDigits
DoneCount:
    cmp ecx, 16
    jne ParseHexFail

    ; Convert High 32 bits (8 hex digits)
    mov edx, 0
    mov ecx, 8
ParseHighLoop:
    mov al, [esi]
    call HexCharToNibble
    cmp ebx, 0
    je ParseHexFail
    shl edx, 4
    or dl, al
    inc esi
    loop ParseHighLoop

    ; Convert Low 32 bits (8 hex digits)
    mov eax, 0
    mov ecx, 8
ParseLowLoop:
    mov bl, [esi]
    push eax
    mov al, bl
    call HexCharToNibble
    mov bl, al
    pop eax
    cmp ebx, 0FFh               ; Error sentinel
    je ParseHexFail
    shl eax, 4
    or al, bl
    inc esi
    loop ParseLowLoop

    mov ebx, 1                  ; Success flag
    jmp ParseHexDone

ParseHexFail:
    mov eax, 0
    mov edx, 0
    mov ebx, 0                  ; Fail flag

ParseHexDone:
    pop edi
    pop ecx
    pop esi
    pop ebp
    ret
ParseHex64 ENDP

; =========================================================================
; Helper Procedure: HexCharToNibble
; Converts ASCII character in AL to 0-15 value in AL. EBX=1 (OK), EBX=0 (Fail)
; =========================================================================
HexCharToNibble PROC
    cmp al, '0'
    jb HexFail
    cmp al, '9'
    jbe HexDigit        ; Renamed from IsDigit to avoid collision
    cmp al, 'A'
    jb CheckLower
    cmp al, 'F'
    jbe HexUpper        ; Renamed from IsUpper
CheckLower:
    cmp al, 'a'
    jb HexFail
    cmp al, 'f'
    jbe HexLower        ; Renamed from IsLower
    jmp HexFail

HexDigit:
    sub al, '0'
    mov ebx, 1
    ret

HexUpper:
    sub al, 'A'
    add al, 10
    mov ebx, 1
    ret

HexLower:
    sub al, 'a'
    add al, 10
    mov ebx, 1
    ret

HexFail:
    mov ebx, 0
    ret
HexCharToNibble ENDP


; =========================================================================
; MODULE INTERFACE STUBS (To be linked with Modules B, C, D)
; =========================================================================

ModuleB_KeyGen PROC
    push ebp
    mov ebp, esp
    ; [ebp + 8]  = Key Low (32-bit)
    ; [ebp + 12] = Key High (32-bit)
    
    ; Placeholder display until Module B is linked
    mov edx, OFFSET arg1Buffer
    call WriteString
    call Crlf
    pop ebp
    ret
ModuleB_KeyGen ENDP

ModuleC_Encrypt PROC
    push ebp
    mov ebp, esp
    ; [ebp + 8]  = Filename Pointer
    ; [ebp + 12] = Key Low
    ; [ebp + 16] = Key High

    mov edx, OFFSET msgEncSuccess
    call WriteString
    pop ebp
    ret
ModuleC_Encrypt ENDP

ModuleC_Decrypt PROC
    push ebp
    mov ebp, esp
    ; [ebp + 8]  = Filename Pointer
    ; [ebp + 12] = Key Low
    ; [ebp + 16] = Key High

    mov edx, OFFSET msgDecSuccess
    call WriteString
    pop ebp
    ret
ModuleC_Decrypt ENDP

ModuleD_Dump PROC
    push ebp
    mov ebp, esp
    ; [ebp + 8] = Filename Pointer
    pop ebp
    ret
ModuleD_Dump ENDP

ModuleD_Stats PROC
    push ebp
    mov ebp, esp
    ; [ebp + 8] = Filename Pointer
    pop ebp
    ret
ModuleD_Stats ENDP

END main
