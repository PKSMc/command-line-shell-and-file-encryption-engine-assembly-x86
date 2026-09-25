; ====================================================================
; module_C.inc - Header File for DES Core Module C
; ====================================================================

IFNDEF MODULE_C_INC
MODULE_C_INC EQU <1>

; --- DES Core Constants ---
DES_BLOCK_BYTES     EQU 8
DES_BLOCK_BITS      EQU 64
DES_HALF_BLOCK_BITS EQU 32

; --- Procedure Prototypes ---

; Input: High 32-bit dword, Low 32-bit dword of 64-bit plaintext block.
; Output: Ciphertext returned in EDX:EAX (EDX = High 32 bits, EAX = Low 32 bits).
DES_16_Round_Core PROTO STDCALL :DWORD, :DWORD

; Input: 32-bit R block, Pointer to 6-byte subkey array.
; Output: 32-bit Feistel function output returned in EAX.
Feistel_F PROTO STDCALL :DWORD, :PTR BYTE

; Input: Pointer to Source buffer, Pointer to Destination buffer, Pointer to Permutation table.
Apply_Permutation_64 PROTO STDCALL :PTR BYTE, :PTR BYTE, :PTR BYTE

; Input: Pointer to buffer, 1-indexed bit position (1 to 64).
; Output: Bit value (0 or 1) returned in EAX.
GetBitFromBuffer PROTO STDCALL :PTR BYTE, :DWORD

; Pads DataBuffer to 8-byte block alignment using PKCS#7 standard.
Apply_PKCS7_Padding PROTO STDCALL

ENDIF ; MODULE_C_INC