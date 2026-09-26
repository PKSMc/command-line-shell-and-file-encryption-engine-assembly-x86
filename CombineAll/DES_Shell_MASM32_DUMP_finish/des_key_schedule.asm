; -----------------------------------------------------------------------------
; DES key schedule generator for 32-bit MASM
;
; Implements FIPS 46-3 Appendix 1:
;   - Permuted Choice 1 (PC-1)
;   - 28-bit circular-left rotation schedule
;   - Permuted Choice 2 (PC-2)
;
; This file has no dependency on an encryption library or Irvine32.
; Every procedure uses an explicit EBP stack frame, preserves caller registers,
; and returns its status/result through EAX.
; -----------------------------------------------------------------------------

.386
.model flat, stdcall
option casemap:none
option prologue:none
option epilogue:none

include des_key_schedule.inc

PUBLIC GenerateDESSubkeys
PUBLIC ValidateDESOddParity

.data

; Bit masks for FIPS bit numbering inside a byte (bit 1 is the MSB).
BitMask BYTE 80h,40h,20h,10h,08h,04h,02h,01h

PC1Table BYTE 57,49,41,33,25,17,9
         BYTE 1,58,50,42,34,26,18
         BYTE 10,2,59,51,43,35,27
         BYTE 19,11,3,60,52,44,36
         BYTE 63,55,47,39,31,23,15
         BYTE 7,62,54,46,38,30,22
         BYTE 14,6,61,53,45,37,29
         BYTE 21,13,5,28,20,12,4

PC2Table BYTE 14,17,11,24,1,5
         BYTE 3,28,15,6,21,10
         BYTE 23,19,12,4,26,8
         BYTE 16,7,27,20,13,2
         BYTE 41,52,31,37,47,55
         BYTE 30,40,51,45,33,48
         BYTE 44,49,39,56,34,53
         BYTE 46,42,50,36,29,32

LeftShiftTable BYTE 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1

.code

; -----------------------------------------------------------------------------
; ValidateDESOddParity
;
; Validates odd parity independently in each of the eight key bytes.
;
; Parameters:
;   [EBP+8] = pointer to the eight key bytes
; Returns:
;   EAX = 0  valid odd parity
;   EAX = 1  at least one byte has even parity
;   EAX = 2  null pointer
; -----------------------------------------------------------------------------
ValidateDESOddParity PROC STDCALL pKey:PTR BYTE
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, DWORD PTR [ebp+8]
    test esi, esi
    jz   parity_null

    xor  ecx, ecx                    ; byte index

parity_byte_loop:
    mov  dl, BYTE PTR [esi+ecx]
    xor  ebx, ebx                    ; count of one bits
    mov  edi, 8

parity_bit_loop:
    shr  dl, 1
    jnc  parity_no_increment
    inc  ebx

parity_no_increment:
    dec  edi
    jnz  parity_bit_loop

    test ebx, 1
    jz   parity_invalid

    inc  ecx
    cmp  ecx, DES_KEY_BYTES
    jb   parity_byte_loop

    xor  eax, eax
    jmp  parity_done

parity_invalid:
    mov  eax, 1
    jmp  parity_done

parity_null:
    mov  eax, 2

parity_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  4
ValidateDESOddParity ENDP

; -----------------------------------------------------------------------------
; ApplyPC1 (internal)
;
; Selects 56 bits from the 64-bit key and produces C0 and D0.
; Both outputs use only the low 28 bits of their DWORD.
;
; Parameters:
;   [EBP+8]  = pointer to key bytes
;   [EBP+12] = pointer to output C0 DWORD
;   [EBP+16] = pointer to output D0 DWORD
; Returns:
;   EAX = 0
; -----------------------------------------------------------------------------
ApplyPC1 PROC STDCALL pKey:PTR BYTE, pC:PTR DWORD, pD:PTR DWORD
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, DWORD PTR [ebp+8]
    xor  ebx, ebx                    ; C0 accumulator
    xor  ecx, ecx                    ; PC-1 table index

pc1_c_loop:
    shl  ebx, 1

    movzx edx, BYTE PTR PC1Table[ecx]
    dec  edx                         ; convert FIPS position to zero based
    mov  eax, edx
    shr  eax, 3                      ; source byte index
    and  edx, 7                      ; bit index within source byte
    movzx edx, BYTE PTR BitMask[edx]
    test BYTE PTR [esi+eax], dl
    jz   pc1_c_zero
    or   ebx, 1

pc1_c_zero:
    inc  ecx
    cmp  ecx, 28
    jb   pc1_c_loop

    and  ebx, 0FFFFFFFh
    mov  edi, DWORD PTR [ebp+12]
    mov  DWORD PTR [edi], ebx

    xor  ebx, ebx                    ; D0 accumulator

pc1_d_loop:
    shl  ebx, 1

    movzx edx, BYTE PTR PC1Table[ecx]
    dec  edx
    mov  eax, edx
    shr  eax, 3
    and  edx, 7
    movzx edx, BYTE PTR BitMask[edx]
    test BYTE PTR [esi+eax], dl
    jz   pc1_d_zero
    or   ebx, 1

pc1_d_zero:
    inc  ecx
    cmp  ecx, 56
    jb   pc1_d_loop

    and  ebx, 0FFFFFFFh
    mov  edi, DWORD PTR [ebp+16]
    mov  DWORD PTR [edi], ebx

    xor  eax, eax

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  12
ApplyPC1 ENDP

; -----------------------------------------------------------------------------
; RotateLeft28 (internal)
;
; Circular-left rotation restricted to the low 28 bits. A normal 32-bit ROL
; cannot be used directly because it would rotate the unused upper four bits.
;
; Parameters:
;   [EBP+8]  = 28-bit value
;   [EBP+12] = count (1 or 2 for the DES schedule)
; Returns:
;   EAX = rotated 28-bit value
; -----------------------------------------------------------------------------
RotateLeft28 PROC STDCALL value:DWORD, count:DWORD
    push ebp
    mov  ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  eax, DWORD PTR [ebp+8]
    mov  edx, eax
    mov  ecx, DWORD PTR [ebp+12]
    shl  eax, cl

    mov  ebx, 28
    sub  ebx, ecx
    mov  ecx, ebx
    shr  edx, cl

    or   eax, edx
    and  eax, 0FFFFFFFh

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
RotateLeft28 ENDP

; -----------------------------------------------------------------------------
; ApplyPC2 (internal)
;
; Selects 48 bits from Cn||Dn. The result is written as six bytes in FIPS
; display order, most-significant byte first.
;
; Parameters:
;   [EBP+8]  = Cn (low 28 bits)
;   [EBP+12] = Dn (low 28 bits)
;   [EBP+16] = output pointer (six bytes)
; Returns:
;   EAX = 0
; -----------------------------------------------------------------------------
ApplyPC2 PROC STDCALL valueC:DWORD, valueD:DWORD, pOutput:PTR BYTE
    push ebp
    mov  ebp, esp
    sub  esp, 4                      ; [EBP-4] = bits in current output byte
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  DWORD PTR [ebp-4], 0
    mov  edi, DWORD PTR [ebp+16]
    xor  esi, esi                    ; PC-2 table index
    xor  ebx, ebx                    ; BL = output byte accumulator

pc2_loop:
    shl  bl, 1
    movzx edx, BYTE PTR PC2Table[esi]
    cmp  edx, 28
    ja   pc2_from_d

    mov  eax, DWORD PTR [ebp+8]
    mov  ecx, 28
    sub  ecx, edx
    shr  eax, cl
    and  eax, 1
    jmp  pc2_have_bit

pc2_from_d:
    mov  eax, DWORD PTR [ebp+12]
    mov  ecx, 56
    sub  ecx, edx
    shr  eax, cl
    and  eax, 1

pc2_have_bit:
    or   bl, al
    inc  esi
    inc  DWORD PTR [ebp-4]
    cmp  DWORD PTR [ebp-4], 8
    jne  pc2_continue

    mov  BYTE PTR [edi], bl
    inc  edi
    xor  ebx, ebx
    mov  DWORD PTR [ebp-4], 0

pc2_continue:
    cmp  esi, 48
    jb   pc2_loop

    xor  eax, eax

    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  12
ApplyPC2 ENDP

; -----------------------------------------------------------------------------
; GenerateDESSubkeys
;
; Generates K1 through K16. Parity bits are ignored by PC-1 as required by
; DES. Call ValidateDESOddParity separately when input validation is desired.
;
; Parameters:
;   [EBP+8]  = pointer to 8-byte key, MSB first
;   [EBP+12] = pointer to a 96-byte schedule buffer
; Returns:
;   EAX = 0  success
;   EAX = 2  null pointer
; -----------------------------------------------------------------------------
GenerateDESSubkeys PROC STDCALL pKey:PTR BYTE, pSchedule:PTR BYTE
    push ebp
    mov  ebp, esp
    sub  esp, 12                     ; C, D, round
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov  esi, DWORD PTR [ebp+8]
    mov  edi, DWORD PTR [ebp+12]
    test esi, esi
    jz   generate_null
    test edi, edi
    jz   generate_null

    lea  eax, DWORD PTR [ebp-8]      ; &D
    push eax
    lea  eax, DWORD PTR [ebp-4]      ; &C
    push eax
    push esi
    call ApplyPC1

    mov  DWORD PTR [ebp-12], 0

generate_round_loop:
    mov  ecx, DWORD PTR [ebp-12]
    movzx ebx, BYTE PTR LeftShiftTable[ecx]

    push ebx
    push DWORD PTR [ebp-4]
    call RotateLeft28
    mov  DWORD PTR [ebp-4], eax

    push ebx
    push DWORD PTR [ebp-8]
    call RotateLeft28
    mov  DWORD PTR [ebp-8], eax

    mov  eax, DWORD PTR [ebp-12]
    imul eax, DES_SUBKEY_BYTES
    add  eax, edi

    push eax
    push DWORD PTR [ebp-8]
    push DWORD PTR [ebp-4]
    call ApplyPC2

    inc  DWORD PTR [ebp-12]
    cmp  DWORD PTR [ebp-12], DES_ROUNDS
    jb   generate_round_loop

    xor  eax, eax
    jmp  generate_done

generate_null:
    mov  eax, 2

generate_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp, ebp
    pop  ebp
    ret  8
GenerateDESSubkeys ENDP

END
