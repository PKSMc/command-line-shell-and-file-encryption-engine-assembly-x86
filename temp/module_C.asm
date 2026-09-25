.386
.model flat, stdcall
option casemap :none

; ====================================================================
; Import Windows API Libraries
; ====================================================================
includelib \masm32\lib\kernel32.lib


; --- Win32 API Prototypes & Constants ---
STD_INPUT_HANDLE  EQU -10
STD_OUTPUT_HANDLE EQU -11

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteConsoleA   PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ReadConsoleA    PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
include des_key_schedule.inc

.data
    MasterKey DB 001h, 034h, 057h, 079h, 09Bh, 0BCh, 0DFh, 0F1h
    Subkeys   DB DES_SCHEDULE_BYTES DUP(0) ; Uses constant from .inc file

    ; --- DES Permutation Tables ---
    IP_Table DB 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4
             DB 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8
             DB 57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3
             DB 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7

    IP_Inv_Table DB 40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31
                 DB 38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29
                 DB 36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27
                 DB 34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25

    E_Table DB 32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9
            DB  8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17
            DB 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25
            DB 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1

    P_Table DB 16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10
            DB  2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25

    ; --- DES S-Boxes (S1 to S8) ---
    SBox_1 DB 14, 4, 13, 1, 2,15, 11, 8, 3,10, 6,12, 5, 9, 0, 7
           DB  0,15,  7, 4,14, 2, 13, 1,10, 6,12,11, 9, 5, 3, 8
           DB  4, 1, 14, 8,13, 6,  2,11,15,12, 9, 7, 3,10, 5, 0
           DB 15,12,  8, 2, 4, 9,  1, 7, 5,11, 3,14,10, 0, 6,13

    SBox_2 DB 15, 1,  8,14, 6,11,  3, 4, 9, 7, 2,13,12, 0, 5,10
           DB  3,13,  4, 7,15, 2,  8,14,12, 0, 1,10, 6, 9,11, 5
           DB  0,14,  7,11,10, 4, 13, 1, 5, 8,12, 6, 9, 3, 2,15
           DB 13, 8, 10, 1, 3,15,  4, 2,11, 6, 7,12, 0, 5,14, 9

    SBox_3 DB 10, 0,  9,14, 6, 3, 15, 5, 1,13,12, 7,11, 4, 2, 8
           DB 13, 7,  0, 9, 3, 4,  6,10, 2, 8, 5,14,12,11,15, 1
           DB 13, 6,  4, 9, 8,15,  3, 0,11, 1, 2,12, 5,10,14, 7
           DB  1,10, 13, 0, 6, 9,  8, 7, 4,15,14, 3,11, 5, 2,12

    SBox_4 DB  7,13, 14, 3, 0, 6,  9,10, 1, 2, 8, 5,11,12, 4,15
           DB 13, 8, 11, 5, 6,15,  0, 3, 4, 7, 2,12, 1,10,14, 9
           DB 10, 6,  9, 0,12,11,  7,13,15, 1, 3,14, 5, 2, 8, 4
           DB  3,15,  0, 6,10, 1, 13, 8, 9, 4, 5,11,12, 7, 2,14

    SBox_5 DB  2,12,  4, 1, 7,10, 11, 6, 8, 5, 3,15,13, 0,14, 9
           DB 14,11,  2,12, 4, 7, 13, 1, 5, 0,15,10, 3, 9, 8, 6
           DB  4, 2,  1,11,10,13,  7, 8,15, 9,12, 5, 6, 3, 0,14
           DB 11, 8, 12, 7, 1,14,  2,13, 6,15, 0, 9,10, 4, 5, 3

    SBox_6 DB 12, 1, 10,15, 9, 2,  6, 8, 0,13, 3, 4,14, 7, 5,11
           DB 10,15,  4, 2, 7,12,  9, 5, 6, 1,13,14, 0,11, 3, 8
           DB  9,14, 15, 5, 2, 8, 12, 3, 7, 0, 4,10, 1,13,11, 6
           DB  4, 3,  2,12, 9, 5, 15,10,11,14, 1, 7, 6, 0, 8,13

    SBox_7 DB  4,11,  2,14,15, 0,  8,13, 3,12, 9, 7, 5,10, 6, 1
           DB 13, 0, 11, 7, 4, 9,  1,10,14, 3, 5,12, 2,15, 8, 6
           DB  1, 4, 11,13,12, 3,  7,14,10,15, 6, 8, 0, 5, 9, 2
           DB  6,11, 13, 8, 1, 4, 10, 7, 9, 5, 0,15,14, 2, 3,12

    SBox_8 DB 13, 2,  8, 4, 6,15, 11, 1,10, 9, 3,14, 5, 0,12, 7
           DB  1,15, 13, 8,10, 3,  7, 4,12, 5, 6,11, 0,14, 9, 2
           DB  7,11,  4, 1, 9,12, 14, 2, 0, 6,10,13,15, 3, 5, 8
           DB  2, 1, 14, 7, 4,10,  8,13,15,12, 9, 0, 3, 5, 6,11

    SBox_Addresses DD OFFSET SBox_1, OFFSET SBox_2, OFFSET SBox_3, OFFSET SBox_4
                   DD OFFSET SBox_5, OFFSET SBox_6, OFFSET SBox_7, OFFSET SBox_8

    

    ; --- User Input & Working Data Buffers ---
    InputText    DB 256 DUP(0)      ; Dynamic input storage (replacing "HELLO123")
    DataBuffer   DB 1024 DUP(0)
    DataLen      DD 0
    BytesRead    DD 0
    BytesWritten DD 0

    ; --- Console Messages ---
    PromptMsg    DB "Enter text to encrypt: ", 0
    PromptLen    EQU $ - PromptMsg - 1

    MsgDone      DB "DES Encryption Completed Successfully!", 0Dh, 0Ah, 0
    MsgDoneLen   EQU $ - MsgDone - 1

.code

; ====================================================================
; Procedure: GetBitFromBuffer
; Extract bit value (1 or 0) from buffer.
; Params: [ebp+8] = Buffer PTR, [ebp+12] = Bit Position (1-indexed)
; Returns: EAX = Bit Value (0 or 1)
; ====================================================================
GetBitFromBuffer PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx

    mov  esi, dword ptr [ebp + 8]    ; Buffer Address
    mov  eax, dword ptr [ebp + 12]   ; Bit Position (1..64)

    dec  eax                         ; Convert to 0-index
    mov  ecx, eax
    shr  eax, 3                      ; Byte Offset = BitIndex / 8
    and  ecx, 7                      ; Bit Offset  = BitIndex % 8

    mov  dl, 80h                     ; Bitmask 10000000b
    shr  dl, cl                      ; Shift to target bit position

    mov  al, byte ptr [esi + eax]
    and  al, dl
    jz   BitIsZero

    mov  eax, 1
    jmp  BitExit

BitIsZero:
    xor  eax, eax

BitExit:
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
GetBitFromBuffer ENDP

; ====================================================================
; Procedure: Apply_Permutation_64
; Applies 64-bit permutation (IP / IP^-1)
; Params: [ebp+8] = Src, [ebp+12] = Dest, [ebp+16] = Table
; ====================================================================
Apply_Permutation_64 PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, dword ptr [ebp + 8]   ; Src
    mov  edi, dword ptr [ebp + 12]  ; Dest
    mov  ebx, dword ptr [ebp + 16]  ; Table

    mov  dword ptr [edi], 0
    mov  dword ptr [edi + 4], 0

    xor  ecx, ecx                   ; Bit counter (0..63)
PermLoop:
    mov  al, byte ptr [ebx + ecx]
    movzx eax, al

    push eax                        ; Arg 2: Bit Position
    push esi                        ; Arg 1: Buffer Ptr
    call GetBitFromBuffer           ; Returns bit in EAX

    cmp  eax, 0
    je   SkipBitSet

    mov  eax, ecx
    shr  eax, 3                     ; Dest Byte Index
    mov  edx, ecx
    and  edx, 7                     ; Dest Bit Index

    mov  dh, 80h
    push ecx
    mov  ecx, edx
    shr  dh, cl
    pop  ecx
    or   byte ptr [edi + eax], dh

SkipBitSet:
    inc  ecx
    cmp  ecx, 64
    jne  PermLoop

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  12
Apply_Permutation_64 ENDP

; ====================================================================
; Procedure: Apply_PKCS7_Padding
; Pads DataBuffer to 8-byte block alignment
; ====================================================================
Apply_PKCS7_Padding PROC
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push edi

    mov  eax, [DataLen]
    xor  edx, edx
    mov  ebx, 8
    div  ebx                         ; EAX = DataLen / 8, EDX = DataLen % 8

    mov  ecx, 8
    sub  ecx, edx                    ; Padding byte value = 8 - (DataLen % 8)

    mov  edi, OFFSET DataBuffer
    add  edi, [DataLen]

    mov  al, cl
    rep  stosb                       ; Fill memory with padding byte

    mov  eax, [DataLen]
    add  eax, ecx
    mov  [DataLen], eax              ; Save updated padded size

    pop  edi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret
Apply_PKCS7_Padding ENDP

; ====================================================================
; Procedure: Feistel_F
; DES Feistel Round Function f(R, K)
; Params: [ebp+8] = 32-bit R, [ebp+12] = Subkey PTR
; Returns: EAX = 32-bit output
; ====================================================================
Feistel_F PROC
    push ebp
    mov  ebp, esp
    sub  esp, 16                     ; [ebp-4]=TempR, [ebp-10]=Exp48, [ebp-14]=SBoxOut
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  eax, dword ptr [ebp + 8]
    mov  dword ptr [ebp - 4], eax    ; Save R to TempR
    mov  ebx, dword ptr [ebp + 12]   ; Subkey pointer

    ; 1. E-Table Expansion (32 -> 48 bits)
    xor  ecx, ecx
ExpLoop:
    mov  al, byte ptr [E_Table + ecx]
    movzx eax, al
    lea  esi, [ebp - 4]

    push eax
    push esi
    call GetBitFromBuffer            ; Extract bit into EAX

    mov  edx, ecx
    shr  edx, 3
    mov  edi, ecx
    and  edi, 7

    cmp  ecx, 0
    jne  CheckExpClear
    mov  dword ptr [ebp - 10], 0
    mov  word ptr [ebp - 6], 0
CheckExpClear:

    cmp  eax, 0
    je   SkipExpSet

    mov  dh, 80h
    push ecx
    mov  ecx, edi
    shr  dh, cl
    pop  ecx
    lea  esi, [ebp - 10]
    or   byte ptr [esi + edx], dh

SkipExpSet:
    inc  ecx
    cmp  ecx, 48
    jne  ExpLoop

    ; 2. XOR with Subkey (48 bits)
    xor  ecx, ecx
XORLoop:
    mov  al, byte ptr [ebx + ecx]
    lea  esi, [ebp - 10]
    xor  byte ptr [esi + ecx], al
    inc  ecx
    cmp  ecx, 6
    jne  XORLoop

    ; 3. S-Box Lookups
    mov  dword ptr [ebp - 14], 0    ; Clear SBoxOut
    xor  ecx, ecx
SBoxLoop:
    mov  edx, dword ptr [SBox_Addresses + ecx * 4]
    lea  esi, [ebp - 10]
    mov  al, byte ptr [esi + ecx]
    and  al, 0Fh
    movzx eax, byte ptr [edx + eax]  ; Fetch S-Box value

    push ecx
    mov  ecx, 7
    sub  ecx, [esp]                  ; 7 - SBoxIndex
    shl  ecx, 2                      ; * 4
    shl  eax, cl
    or   dword ptr [ebp - 14], eax   ; Accumulate into SBoxOut
    pop  ecx

    inc  ecx
    cmp  ecx, 8
    jne  SBoxLoop

    ; 4. P-Permutation (32 -> 32 bits)
    xor  eax, eax
    xor  ecx, ecx
PLoop:
    mov  dl, byte ptr [P_Table + ecx]
    movzx edx, dl
    dec  edx

    mov  edi, dword ptr [ebp - 14]
    push ecx
    mov  ecx, edx
    shr  edi, cl
    and  edi, 1
    pop  ecx

    cmp  edi, 0
    je   SkipPBit

    mov  edx, 31
    sub  edx, ecx
    mov  edi, 1
    push ecx
    mov  ecx, edx
    shl  edi, cl
    pop  ecx
    or   eax, edi                    ; Accumulate output bit into EAX

SkipPBit:
    inc  ecx
    cmp  ecx, 32
    jne  PLoop

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
Feistel_F ENDP

; ====================================================================
; Procedure: DES_16_Round_Core
; Executes 16 Feistel Rounds
; Params: [ebp+8] = High 32-bit block, [ebp+12] = Low 32-bit block
; Returns: EDX = Encrypted High 32 bits, EAX = Encrypted Low 32 bits
; ====================================================================
DES_16_Round_Core PROC
    push ebp
    mov  ebp, esp
    sub  esp, 16                     ; [ebp-8]=BlockData, [ebp-16]=IP_Result
    push ebx
    push esi
    push edi

    mov  eax, dword ptr [ebp + 8]
    mov  dword ptr [ebp - 8], eax
    mov  eax, dword ptr [ebp + 12]
    mov  dword ptr [ebp - 4], eax

    ; 1. Initial Permutation (IP)
    lea  esi, [ebp - 8]
    lea  edi, [ebp - 16]
    lea  ebx, IP_Table

    push ebx
    push edi
    push esi
    call Apply_Permutation_64

    mov  edi, dword ptr [ebp - 16]   ; L_0
    mov  esi, dword ptr [ebp - 12]   ; R_0

    ; 2. 16 Feistel Rounds Loop
    xor  ecx, ecx
    lea  ebx, Subkeys

FeistelLoop:
    push ecx
    push esi                         ; Save current R (becomes next L)

    push ebx                         ; Subkey ptr
    push esi                         ; Current R
    call Feistel_F                   ; Returns in EAX

    xor  eax, edi                    ; L XOR f(R, K)
    mov  esi, eax                    ; New R
    pop  edi                         ; New L

    add  ebx, 6
    pop  ecx
    inc  ecx
    cmp  ecx, 16
    jne  FeistelLoop

    ; 3. Pre-IP^-1 Swap (R_16 : L_16)
    mov  dword ptr [ebp - 8], esi
    mov  dword ptr [ebp - 4], edi

    ; 4. Inverse Initial Permutation (IP^-1)
    lea  esi, [ebp - 8]
    lea  edi, [ebp - 16]
    lea  ebx, IP_Inv_Table

    push ebx
    push edi
    push esi
    call Apply_Permutation_64

    ; Return 64-bit ciphertext in EDX:EAX
    mov  edx, dword ptr [ebp - 16]
    mov  eax, dword ptr [ebp - 12]

    pop  edi
    pop  esi
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
DES_16_Round_Core ENDP

; ====================================================================
; Procedure: main
; Entry Point
; ====================================================================
main PROC
    push ebp
    mov  ebp, esp
    sub  esp, 8                     ; [ebp-4] = hStdOut, [ebp-8] = hStdIn

    ; 1. Get Handles for Console Input & Output
    push STD_OUTPUT_HANDLE
    call GetStdHandle
    mov  dword ptr [ebp - 4], eax

    push STD_INPUT_HANDLE
    call GetStdHandle
    mov  dword ptr [ebp - 8], eax

    ; 2. Print Prompt Message
    push 0
    lea  eax, BytesWritten
    push eax
    push PromptLen
    push OFFSET PromptMsg
    push dword ptr [ebp - 4]
    call WriteConsoleA

    ; 3. Read Input from User Console
    push 0
    lea  eax, BytesRead
    push eax
    push 255                         ; Max characters to read
    push OFFSET InputText
    push dword ptr [ebp - 8]
    call ReadConsoleA

    ; 4. Strip Trailing '\r' and '\n' from ReadConsoleA
    mov  eax, [BytesRead]
StripLoop:
    cmp  eax, 0
    je   StripDone
    
    mov  bl, byte ptr [InputText + eax - 1]
    cmp  bl, 0Dh                     ; Carriage Return (\r)
    je   TrimChar
    cmp  bl, 0Ah                     ; Line Feed (\n)
    je   TrimChar
    jmp  StripDone

TrimChar:
    mov  byte ptr [InputText + eax - 1], 0
    dec  eax
    jmp  StripLoop

StripDone:
    mov  [DataLen], eax

    ; 5. Copy User Input to DataBuffer
    mov  ecx, [DataLen]
    lea  esi, InputText
    lea  edi, DataBuffer
    rep  movsb

    ; 6. Apply PKCS#7 Padding to User Input
    call Apply_PKCS7_Padding

    ; 7. Process Blocks in ECB Mode
    xor  ecx, ecx
BlockLoop:
    mov  edx, dword ptr [DataBuffer + ecx]
    mov  eax, dword ptr [DataBuffer + ecx + 4]

    push ecx
    push eax                         ; Low 32 bits
    push edx                         ; High 32 bits
    call DES_16_Round_Core           ; Encrypted result in EDX:EAX
    pop  ecx

    mov  dword ptr [DataBuffer + ecx], edx
    mov  dword ptr [DataBuffer + ecx + 4], eax

    add  ecx, 8
    cmp  ecx, [DataLen]
    jne  BlockLoop

    ; 8. Display Completion Message
    push 0
    lea  eax, BytesWritten
    push eax
    push MsgDoneLen
    push OFFSET MsgDone
    push dword ptr [ebp - 4]
    call WriteConsoleA

    ; 9. Clean Exit
    push 0
    call ExitProcess

    mov  esp, ebp
    pop  ebp
    ret
main ENDP

END main