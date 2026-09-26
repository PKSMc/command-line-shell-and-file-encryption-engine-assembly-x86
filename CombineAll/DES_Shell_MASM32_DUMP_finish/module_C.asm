; DES 16-round Feistel core and ECB file transforms.
; Bit positions and byte order follow FIPS 46-3 (MSB first).

.386
.model flat, stdcall
option casemap:none
option prologue:none
option epilogue:none

include des_key_schedule.inc
include module_C.inc

includelib kernel32.lib

CreateFileA  PROTO STDCALL :PTR BYTE,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ReadFile     PROTO STDCALL :DWORD,:PTR BYTE,:DWORD,:PTR DWORD,:DWORD
WriteFile    PROTO STDCALL :DWORD,:PTR BYTE,:DWORD,:PTR DWORD,:DWORD
CloseHandle  PROTO STDCALL :DWORD

GENERIC_READ        EQU 80000000h
GENERIC_WRITE       EQU 40000000h
FILE_SHARE_READ     EQU 1
OPEN_EXISTING       EQU 3
CREATE_ALWAYS       EQU 2
FILE_ATTRIBUTE_NORMAL EQU 80h
INVALID_HANDLE_VALUE EQU -1

PUBLIC GetBitFromBuffer
PUBLIC ApplyPermutation
PUBLIC Feistel_F
PUBLIC DES_TransformBlock
PUBLIC Apply_PKCS7_Padding
PUBLIC Remove_PKCS7_Padding
PUBLIC ModuleC_Encrypt
PUBLIC ModuleC_Decrypt

.data

IP_Table BYTE 58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4
         BYTE 62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8
         BYTE 57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3
         BYTE 61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7

IP_Inv_Table BYTE 40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31
             BYTE 38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29
             BYTE 36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27
             BYTE 34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25

E_Table BYTE 32,1,2,3,4,5,4,5,6,7,8,9
        BYTE 8,9,10,11,12,13,12,13,14,15,16,17
        BYTE 16,17,18,19,20,21,20,21,22,23,24,25
        BYTE 24,25,26,27,28,29,28,29,30,31,32,1

P_Table BYTE 16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10
        BYTE 2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25

SBox_1 BYTE 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7
       BYTE 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8
       BYTE 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0
       BYTE 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
SBox_2 BYTE 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10
       BYTE 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5
       BYTE 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15
       BYTE 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
SBox_3 BYTE 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8
       BYTE 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1
       BYTE 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7
       BYTE 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
SBox_4 BYTE 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15
       BYTE 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9
       BYTE 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4
       BYTE 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
SBox_5 BYTE 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9
       BYTE 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6
       BYTE 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14
       BYTE 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
SBox_6 BYTE 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11
       BYTE 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8
       BYTE 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6
       BYTE 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
SBox_7 BYTE 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1
       BYTE 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6
       BYTE 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2
       BYTE 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
SBox_8 BYTE 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7
       BYTE 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2
       BYTE 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8
       BYTE 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11

SBox_Addresses DWORD OFFSET SBox_1,OFFSET SBox_2,OFFSET SBox_3,OFFSET SBox_4
               DWORD OFFSET SBox_5,OFFSET SBox_6,OFFSET SBox_7,OFFSET SBox_8

SuffixEnc BYTE ".enc",0
SuffixDec BYTE ".dec",0
OutputName BYTE 260 DUP(0)

.code

GetBitFromBuffer PROC STDCALL pBuffer:PTR BYTE, bitPosition:DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    mov  esi,DWORD PTR [ebp+8]
    mov  eax,DWORD PTR [ebp+12]
    test esi,esi
    jz   gb_bad
    test eax,eax
    jz   gb_bad
    dec  eax
    mov  ecx,eax
    shr  eax,3
    and  ecx,7
    mov  dl,80h
    shr  dl,cl
    test BYTE PTR [esi+eax],dl
    jz   gb_zero
    mov  eax,1
    jmp  gb_done
gb_zero:
    xor  eax,eax
    jmp  gb_done
gb_bad:
    xor  eax,eax
gb_done:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
GetBitFromBuffer ENDP

ApplyPermutation PROC STDCALL pSource:PTR BYTE,pDestination:PTR BYTE,pTable:PTR BYTE,bitCount:DWORD
    push ebp
    mov  ebp,esp
    sub  esp,8
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,DWORD PTR [ebp+12]
    mov  ebx,DWORD PTR [ebp+16]
    test esi,esi
    jz   perm_bad
    test edi,edi
    jz   perm_bad
    test ebx,ebx
    jz   perm_bad
    mov  eax,DWORD PTR [ebp+20]
    test eax,eax
    jz   perm_bad
    add  eax,7
    shr  eax,3
    mov  ecx,eax
    xor  eax,eax
    push edi
    rep  stosb
    pop  edi
    xor  ecx,ecx
perm_loop:
    movzx eax,BYTE PTR [ebx+ecx]
    push eax
    push esi
    call GetBitFromBuffer
    test eax,eax
    jz   perm_next
    mov  eax,ecx
    mov  edx,ecx
    shr  eax,3
    and  edx,7
    mov  DWORD PTR [ebp-4],eax
    mov  DWORD PTR [ebp-8],edx
    mov  al,80h
    push ecx
    mov  ecx,DWORD PTR [ebp-8]
    shr  al,cl
    pop  ecx
    mov  edx,DWORD PTR [ebp-4]
    or   BYTE PTR [edi+edx],al
perm_next:
    inc  ecx
    cmp  ecx,DWORD PTR [ebp+20]
    jb   perm_loop
    xor  eax,eax
    jmp  perm_done
perm_bad:
    mov  eax,DES_STATUS_BAD_ARGUMENT
perm_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  16
ApplyPermutation ENDP

Feistel_F PROC STDCALL pRight:PTR BYTE,pSubkey:PTR BYTE,pOutput:PTR BYTE
    push ebp
    mov  ebp,esp
    sub  esp,16
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  ebx,DWORD PTR [ebp+12]
    mov  edi,DWORD PTR [ebp+16]
    test esi,esi
    jz   ff_bad
    test ebx,ebx
    jz   ff_bad
    test edi,edi
    jz   ff_bad
    lea  eax,[ebp-6]
    push 48
    push OFFSET E_Table
    push eax
    push esi
    call ApplyPermutation
    xor  ecx,ecx
ff_xor_loop:
    mov  al,BYTE PTR [ebx+ecx]
    xor  BYTE PTR [ebp+ecx-6],al
    inc  ecx
    cmp  ecx,6
    jb   ff_xor_loop
    mov  DWORD PTR [ebp-10],0
    xor  ecx,ecx
ff_sbox_loop:
    xor  edx,edx
    xor  ebx,ebx
ff_sixbit_loop:
    shl  edx,1
    mov  eax,ecx
    imul eax,6
    add  eax,ebx
    inc  eax
    push eax
    lea  eax,[ebp-6]
    push eax
    call GetBitFromBuffer
    or   edx,eax
    inc  ebx
    cmp  ebx,6
    jb   ff_sixbit_loop
    mov  eax,edx
    and  eax,1
    mov  ebx,edx
    and  ebx,20h
    shr  ebx,4
    or   eax,ebx
    shl  eax,4
    shr  edx,1
    and  edx,0Fh
    add  eax,edx
    mov  ebx,DWORD PTR SBox_Addresses[ecx*4]
    movzx eax,BYTE PTR [ebx+eax]
    mov  edx,ecx
    shr  edx,1
    test ecx,1
    jnz  ff_low_nibble
    shl  al,4
ff_low_nibble:
    or   BYTE PTR [ebp+edx-10],al
    inc  ecx
    cmp  ecx,8
    jb   ff_sbox_loop
    push 32
    push OFFSET P_Table
    push edi
    lea  eax,[ebp-10]
    push eax
    call ApplyPermutation
    jmp  ff_done
ff_bad:
    mov  eax,DES_STATUS_BAD_ARGUMENT
ff_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  12
Feistel_F ENDP

DES_TransformBlock PROC STDCALL pInput:PTR BYTE,pOutput:PTR BYTE,pSchedule:PTR BYTE,decryptFlag:DWORD
    push ebp
    mov  ebp,esp
    sub  esp,32
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,DWORD PTR [ebp+12]
    test esi,esi
    jz   dt_bad
    test edi,edi
    jz   dt_bad
    mov  eax,DWORD PTR [ebp+16]
    test eax,eax
    jz   dt_bad
    push 64
    push OFFSET IP_Table
    lea  eax,[ebp-8]
    push eax
    push esi
    call ApplyPermutation
    xor  ecx,ecx
dt_split:
    mov  al,BYTE PTR [ebp+ecx-8]
    mov  BYTE PTR [ebp+ecx-12],al
    mov  al,BYTE PTR [ebp+ecx-4]
    mov  BYTE PTR [ebp+ecx-16],al
    inc  ecx
    cmp  ecx,4
    jb   dt_split
    xor  ebx,ebx
dt_round_loop:
    mov  eax,ebx
    cmp  DWORD PTR [ebp+20],0
    je   dt_key_index_ready
    mov  eax,15
    sub  eax,ebx
dt_key_index_ready:
    imul eax,DES_SUBKEY_BYTES
    add  eax,DWORD PTR [ebp+16]
    lea  edx,[ebp-20]
    push edx
    push eax
    lea  eax,[ebp-16]
    push eax
    call Feistel_F
    xor  ecx,ecx
dt_make_new_r:
    mov  al,BYTE PTR [ebp+ecx-12]
    xor  al,BYTE PTR [ebp+ecx-20]
    mov  BYTE PTR [ebp+ecx-24],al
    inc  ecx
    cmp  ecx,4
    jb   dt_make_new_r
    xor  ecx,ecx
dt_rotate_halves:
    mov  al,BYTE PTR [ebp+ecx-16]
    mov  BYTE PTR [ebp+ecx-12],al
    mov  al,BYTE PTR [ebp+ecx-24]
    mov  BYTE PTR [ebp+ecx-16],al
    inc  ecx
    cmp  ecx,4
    jb   dt_rotate_halves
    inc  ebx
    cmp  ebx,DES_ROUNDS
    jb   dt_round_loop
    xor  ecx,ecx
dt_preoutput:
    mov  al,BYTE PTR [ebp+ecx-16]
    mov  BYTE PTR [ebp+ecx-32],al
    mov  al,BYTE PTR [ebp+ecx-12]
    mov  BYTE PTR [ebp+ecx-28],al
    inc  ecx
    cmp  ecx,4
    jb   dt_preoutput
    push 64
    push OFFSET IP_Inv_Table
    push edi
    lea  eax,[ebp-32]
    push eax
    call ApplyPermutation
    jmp  dt_done
dt_bad:
    mov  eax,DES_STATUS_BAD_ARGUMENT
dt_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  16
DES_TransformBlock ENDP

Apply_PKCS7_Padding PROC STDCALL pBuffer:PTR BYTE,dataLength:DWORD,capacity:DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push edi
    mov  edi,DWORD PTR [ebp+8]
    test edi,edi
    jz   pad_error
    mov  eax,DWORD PTR [ebp+12]
    mov  ecx,eax
    and  ecx,7
    mov  edx,8
    sub  edx,ecx
    mov  ebx,eax
    add  ebx,edx
    cmp  ebx,DWORD PTR [ebp+16]
    ja   pad_error
    add  edi,eax
    mov  ecx,edx
    mov  eax,edx
    rep  stosb
    mov  eax,ebx
    jmp  pad_done
pad_error:
    mov  eax,0FFFFFFFFh
pad_done:
    pop  edi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  12
Apply_PKCS7_Padding ENDP

Remove_PKCS7_Padding PROC STDCALL pBuffer:PTR BYTE,dataLength:DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    mov  esi,DWORD PTR [ebp+8]
    mov  edx,DWORD PTR [ebp+12]
    test esi,esi
    jz   unpad_error
    test edx,edx
    jz   unpad_error
    test edx,7
    jnz  unpad_error
    movzx ebx,BYTE PTR [esi+edx-1]
    cmp  ebx,1
    jb   unpad_error
    cmp  ebx,8
    ja   unpad_error
    cmp  ebx,edx
    ja   unpad_error
    xor  ecx,ecx
unpad_check:
    mov  eax,edx
    dec  eax
    sub  eax,ecx
    cmp  BYTE PTR [esi+eax],bl
    jne  unpad_error
    inc  ecx
    cmp  ecx,ebx
    jb   unpad_check
    mov  eax,edx
    sub  eax,ebx
    jmp  unpad_done
unpad_error:
    mov  eax,0FFFFFFFFh
unpad_done:
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
Remove_PKCS7_Padding ENDP

CopyNameWithSuffix PROC STDCALL pName:PTR BYTE,pSuffix:PTR BYTE,pDest:PTR BYTE
    push ebp
    mov  ebp,esp
    push ecx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,DWORD PTR [ebp+16]
    xor  ecx,ecx
cns_name:
    mov  al,BYTE PTR [esi]
    test al,al
    jz   cns_suffix_start
    cmp  ecx,254
    jae  cns_error
    mov  BYTE PTR [edi],al
    inc  esi
    inc  edi
    inc  ecx
    jmp  cns_name
cns_suffix_start:
    mov  esi,DWORD PTR [ebp+12]
cns_suffix:
    mov  al,BYTE PTR [esi]
    mov  BYTE PTR [edi],al
    inc  esi
    inc  edi
    test al,al
    jnz  cns_suffix
    xor  eax,eax
    jmp  cns_done
cns_error:
    mov  eax,DES_STATUS_BAD_ARGUMENT
cns_done:
    pop  edi
    pop  esi
    pop  ecx
    mov  esp,ebp
    pop  ebp
    ret  12
CopyNameWithSuffix ENDP

ModuleC_Encrypt PROC STDCALL pFilename:PTR BYTE,pKey:PTR BYTE
    push ebp
    mov  ebp,esp
    sub  esp,128
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  DWORD PTR [ebp-4],INVALID_HANDLE_VALUE
    mov  DWORD PTR [ebp-8],INVALID_HANDLE_VALUE
    lea  eax,[ebp-128]
    push eax
    push DWORD PTR [ebp+12]
    call GenerateDESSubkeys
    test eax,eax
    jnz  enc_bad_arg
    push OFFSET OutputName
    push OFFSET SuffixEnc
    push DWORD PTR [ebp+8]
    call CopyNameWithSuffix
    test eax,eax
    jnz  enc_bad_arg
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push OPEN_EXISTING
    push 0
    push FILE_SHARE_READ
    push GENERIC_READ
    push DWORD PTR [ebp+8]
    call CreateFileA
    mov  DWORD PTR [ebp-4],eax
    cmp  eax,INVALID_HANDLE_VALUE
    je   enc_open_error
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push CREATE_ALWAYS
    push 0
    push 0
    push GENERIC_WRITE
    push OFFSET OutputName
    call CreateFileA
    mov  DWORD PTR [ebp-8],eax
    cmp  eax,INVALID_HANDLE_VALUE
    je   enc_create_error
enc_read_loop:
    mov  DWORD PTR [ebp-24],0
    mov  DWORD PTR [ebp-20],0
    push 0
    lea  eax,[ebp-12]
    push eax
    push 8
    lea  eax,[ebp-24]
    push eax
    push DWORD PTR [ebp-4]
    call ReadFile
    test eax,eax
    jz   enc_read_error
    mov  ecx,DWORD PTR [ebp-12]
    cmp  ecx,8
    je   enc_transform
    cmp  ecx,8
    ja   enc_read_error
    lea  eax,[ebp-24]
    push 8
    push ecx
    push eax
    call Apply_PKCS7_Padding
    cmp  eax,8
    jne  enc_read_error
enc_transform:
    push 0
    lea  eax,[ebp-128]
    push eax
    lea  eax,[ebp-32]
    push eax
    lea  eax,[ebp-24]
    push eax
    call DES_TransformBlock
    test eax,eax
    jnz  enc_read_error
    push 0
    lea  eax,[ebp-16]
    push eax
    push 8
    lea  eax,[ebp-32]
    push eax
    push DWORD PTR [ebp-8]
    call WriteFile
    test eax,eax
    jz   enc_write_error
    cmp  DWORD PTR [ebp-16],8
    jne  enc_write_error
    cmp  DWORD PTR [ebp-12],8
    je   enc_read_loop
    xor  ebx,ebx
    jmp  enc_cleanup
enc_bad_arg:
    mov  ebx,DES_STATUS_BAD_ARGUMENT
    jmp  enc_cleanup
enc_open_error:
    mov  ebx,DES_STATUS_OPEN_INPUT
    jmp  enc_cleanup
enc_create_error:
    mov  ebx,DES_STATUS_CREATE_OUTPUT
    jmp  enc_cleanup
enc_read_error:
    mov  ebx,DES_STATUS_READ_ERROR
    jmp  enc_cleanup
enc_write_error:
    mov  ebx,DES_STATUS_WRITE_ERROR
enc_cleanup:
    mov  eax,DWORD PTR [ebp-8]
    cmp  eax,INVALID_HANDLE_VALUE
    je   enc_close_input
    push eax
    call CloseHandle
enc_close_input:
    mov  eax,DWORD PTR [ebp-4]
    cmp  eax,INVALID_HANDLE_VALUE
    je   enc_return
    push eax
    call CloseHandle
enc_return:
    mov  eax,ebx
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
ModuleC_Encrypt ENDP

ModuleC_Decrypt PROC STDCALL pFilename:PTR BYTE,pKey:PTR BYTE
    push ebp
    mov  ebp,esp
    sub  esp,144
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  DWORD PTR [ebp-4],INVALID_HANDLE_VALUE
    mov  DWORD PTR [ebp-8],INVALID_HANDLE_VALUE
    lea  eax,[ebp-144]
    push eax
    push DWORD PTR [ebp+12]
    call GenerateDESSubkeys
    test eax,eax
    jnz  dec_bad_arg
    push OFFSET OutputName
    push OFFSET SuffixDec
    push DWORD PTR [ebp+8]
    call CopyNameWithSuffix
    test eax,eax
    jnz  dec_bad_arg
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push OPEN_EXISTING
    push 0
    push FILE_SHARE_READ
    push GENERIC_READ
    push DWORD PTR [ebp+8]
    call CreateFileA
    mov  DWORD PTR [ebp-4],eax
    cmp  eax,INVALID_HANDLE_VALUE
    je   dec_open_error
    push 0
    push FILE_ATTRIBUTE_NORMAL
    push CREATE_ALWAYS
    push 0
    push 0
    push GENERIC_WRITE
    push OFFSET OutputName
    call CreateFileA
    mov  DWORD PTR [ebp-8],eax
    cmp  eax,INVALID_HANDLE_VALUE
    je   dec_create_error
    push 0
    lea  eax,[ebp-12]
    push eax
    push 8
    lea  eax,[ebp-24]
    push eax
    push DWORD PTR [ebp-4]
    call ReadFile
    test eax,eax
    jz   dec_read_error
    cmp  DWORD PTR [ebp-12],8
    jne  dec_bad_cipher
dec_lookahead:
    push 0
    lea  eax,[ebp-12]
    push eax
    push 8
    lea  eax,[ebp-32]
    push eax
    push DWORD PTR [ebp-4]
    call ReadFile
    test eax,eax
    jz   dec_read_error
    cmp  DWORD PTR [ebp-12],8
    je   dec_not_last
    cmp  DWORD PTR [ebp-12],0
    jne  dec_bad_cipher
    push 1
    lea  eax,[ebp-144]
    push eax
    lea  eax,[ebp-40]
    push eax
    lea  eax,[ebp-24]
    push eax
    call DES_TransformBlock
    test eax,eax
    jnz  dec_bad_cipher
    push 8
    lea  eax,[ebp-40]
    push eax
    call Remove_PKCS7_Padding
    cmp  eax,0FFFFFFFFh
    je   dec_bad_cipher
    mov  DWORD PTR [ebp-44],eax
    push 0
    lea  eax,[ebp-16]
    push eax
    push DWORD PTR [ebp-44]
    lea  eax,[ebp-40]
    push eax
    push DWORD PTR [ebp-8]
    call WriteFile
    test eax,eax
    jz   dec_write_error
    mov  eax,DWORD PTR [ebp-44]
    cmp  DWORD PTR [ebp-16],eax
    jne  dec_write_error
    xor  ebx,ebx
    jmp  dec_cleanup
dec_not_last:
    push 1
    lea  eax,[ebp-144]
    push eax
    lea  eax,[ebp-40]
    push eax
    lea  eax,[ebp-24]
    push eax
    call DES_TransformBlock
    test eax,eax
    jnz  dec_bad_cipher
    push 0
    lea  eax,[ebp-16]
    push eax
    push 8
    lea  eax,[ebp-40]
    push eax
    push DWORD PTR [ebp-8]
    call WriteFile
    test eax,eax
    jz   dec_write_error
    cmp  DWORD PTR [ebp-16],8
    jne  dec_write_error
    mov  eax,DWORD PTR [ebp-32]
    mov  DWORD PTR [ebp-24],eax
    mov  eax,DWORD PTR [ebp-28]
    mov  DWORD PTR [ebp-20],eax
    jmp  dec_lookahead
dec_bad_arg:
    mov  ebx,DES_STATUS_BAD_ARGUMENT
    jmp  dec_cleanup
dec_open_error:
    mov  ebx,DES_STATUS_OPEN_INPUT
    jmp  dec_cleanup
dec_create_error:
    mov  ebx,DES_STATUS_CREATE_OUTPUT
    jmp  dec_cleanup
dec_read_error:
    mov  ebx,DES_STATUS_READ_ERROR
    jmp  dec_cleanup
dec_write_error:
    mov  ebx,DES_STATUS_WRITE_ERROR
    jmp  dec_cleanup
dec_bad_cipher:
    mov  ebx,DES_STATUS_BAD_CIPHERTEXT
dec_cleanup:
    mov  eax,DWORD PTR [ebp-8]
    cmp  eax,INVALID_HANDLE_VALUE
    je   dec_close_input
    push eax
    call CloseHandle
dec_close_input:
    mov  eax,DWORD PTR [ebp-4]
    cmp  eax,INVALID_HANDLE_VALUE
    je   dec_return
    push eax
    call CloseHandle
dec_return:
    mov  eax,ebx
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
ModuleC_Decrypt ENDP

END
