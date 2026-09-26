; Module D - hexadecimal/ASCII dump support.

.386
option casemap:none
option prologue:none
option epilogue:none

include Irvine32.inc
include displayHex_Dump.inc

INVALID_HANDLE_VALUE EQU -1

PUBLIC PrintHexByte
PUBLIC DisplayHexDump
PUBLIC DisplayFileHexDump

.data
HexDigits BYTE "0123456789ABCDEF"
DumpHeader BYTE "[Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  | ASCII",0
DumpRule BYTE "------------------------------------------------------------------",0
DumpBuffer BYTE 16 DUP(0)

.code

PrintHexByte PROC STDCALL value:DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push edx
    mov  ebx,DWORD PTR [ebp+8]
    mov  edx,ebx
    shr  edx,4
    and  edx,0Fh
    mov  al,BYTE PTR HexDigits[edx]
    call WriteChar
    mov  edx,ebx
    and  edx,0Fh
    mov  al,BYTE PTR HexDigits[edx]
    call WriteChar
    xor  eax,eax
    pop  edx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  4
PrintHexByte ENDP

DisplayHexDump PROC STDCALL pBuffer:PTR BYTE,byteCount:DWORD,baseOffset:DWORD
    push ebp
    mov  ebp,esp
    sub  esp,20
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  eax,DWORD PTR [ebp+8]
    test eax,eax
    jz   dump_bad
    mov  DWORD PTR [ebp-20],eax
    mov  eax,DWORD PTR [ebp+12]
    mov  DWORD PTR [ebp-4],eax
    mov  eax,DWORD PTR [ebp+16]
    mov  DWORD PTR [ebp-8],eax
dump_next_line:
    cmp  DWORD PTR [ebp-4],0
    je   dump_ok
    mov  eax,DWORD PTR [ebp-4]
    cmp  eax,16
    jbe  dump_line_count_ready
    mov  eax,16
dump_line_count_ready:
    mov  DWORD PTR [ebp-12],eax
    mov  eax,DWORD PTR [ebp-8]
    call WriteHex
    mov  al,' '
    call WriteChar
    call WriteChar
    call WriteChar
    mov  DWORD PTR [ebp-16],0
dump_hex_loop:
    mov  eax,DWORD PTR [ebp-16]
    cmp  eax,16
    jae  dump_ascii_start
    cmp  eax,DWORD PTR [ebp-12]
    jae  dump_hex_padding
    mov  esi,DWORD PTR [ebp-20]
    movzx eax,BYTE PTR [esi+eax]
    push eax
    call PrintHexByte
    jmp  dump_hex_space
dump_hex_padding:
    mov  al,' '
    call WriteChar
    call WriteChar
dump_hex_space:
    mov  al,' '
    call WriteChar
dump_hex_advance:
    inc  DWORD PTR [ebp-16]
    jmp  dump_hex_loop
dump_ascii_start:
    mov  al,' '
    call WriteChar
    mov  al,'|'
    call WriteChar
    mov  al,' '
    call WriteChar
    mov  DWORD PTR [ebp-16],0
dump_ascii_loop:
    mov  eax,DWORD PTR [ebp-16]
    cmp  eax,DWORD PTR [ebp-12]
    jae  dump_line_done
    mov  esi,DWORD PTR [ebp-20]
    mov  al,BYTE PTR [esi+eax]
    cmp  al,20h
    jb   dump_ascii_dot
    cmp  al,7Eh
    ja   dump_ascii_dot
    call WriteChar
    jmp  dump_ascii_advance
dump_ascii_dot:
    mov  al,'.'
    call WriteChar
dump_ascii_advance:
    inc  DWORD PTR [ebp-16]
    jmp  dump_ascii_loop
dump_line_done:
    call Crlf
    mov  eax,DWORD PTR [ebp-12]
    add  DWORD PTR [ebp-20],eax
    add  DWORD PTR [ebp-8],eax
    sub  DWORD PTR [ebp-4],eax
    jmp  dump_next_line
dump_ok:
    xor  eax,eax
    jmp  dump_done
dump_bad:
    mov  eax,1
dump_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  12
DisplayHexDump ENDP

DisplayFileHexDump PROC STDCALL pFilename:PTR BYTE
    push ebp
    mov  ebp,esp
    sub  esp,12
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  edx,DWORD PTR [ebp+8]
    test edx,edx
    jz   dumpfile_bad
    call OpenInputFile
    cmp  eax,INVALID_HANDLE_VALUE
    je   dumpfile_open_error
    mov  DWORD PTR [ebp-4],eax
    mov  DWORD PTR [ebp-8],0
    mov  edx,OFFSET DumpHeader
    call WriteString
    call Crlf
    mov  edx,OFFSET DumpRule
    call WriteString
    call Crlf
dumpfile_read:
    mov  eax,DWORD PTR [ebp-4]
    mov  edx,OFFSET DumpBuffer
    mov  ecx,SIZEOF DumpBuffer
    call ReadFromFile
    jc   dumpfile_read_error
    mov  DWORD PTR [ebp-12],eax
    test eax,eax
    jz   dumpfile_success
    push DWORD PTR [ebp-8]
    push eax
    push OFFSET DumpBuffer
    call DisplayHexDump
    mov  eax,DWORD PTR [ebp-12]
    add  DWORD PTR [ebp-8],eax
    jmp  dumpfile_success
dumpfile_success:
    xor  ebx,ebx
    jmp  dumpfile_close
dumpfile_read_error:
    mov  ebx,4
dumpfile_close:
    mov  eax,DWORD PTR [ebp-4]
    call CloseFile
    mov  eax,ebx
    jmp  dumpfile_done
dumpfile_bad:
    mov  eax,1
    jmp  dumpfile_done
dumpfile_open_error:
    mov  eax,2
dumpfile_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  4
DisplayFileHexDump ENDP

END
