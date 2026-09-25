; Module A - DES shell and finite-state command parser.

.386
option casemap:none
option prologue:none
option epilogue:none

include Irvine32.inc
include des_key_schedule.inc
include module_C.inc
include displayHex_Dump.inc
include _Hisrtrogram.inc

MAX_CMD_LEN EQU 512
MAX_ARG_LEN EQU 260

.data
PromptText BYTE "DES-SHELL> ",0
WelcomeText BYTE "=== DES Command-Line Shell Initialized ===",0Dh,0Ah,0
ExitText BYTE "Exiting DES Command-Line Shell...",0Dh,0Ah,0
SyntaxText BYTE "Error: invalid syntax, unmatched quote, or token too long.",0Dh,0Ah,0
UnknownText BYTE "Error: unknown command. Use KEYGEN, ENCRYPT, DECRYPT, DUMP, STATS, CLEAR, or EXIT.",0Dh,0Ah,0
MissingText BYTE "Error: wrong number of arguments.",0Dh,0Ah,0
HexText BYTE "Error: key must contain exactly 16 hexadecimal digits (optional 0x prefix).",0Dh,0Ah,0
ParityText BYTE "Error: every DES key byte must have odd parity.",0Dh,0Ah,0
OperationText BYTE "Error: file/cryptographic operation failed; status = ",0
EncryptOkText BYTE "File encrypted successfully; output suffix is .enc",0Dh,0Ah,0
DecryptOkText BYTE "File decrypted successfully; output suffix is .dec",0Dh,0Ah,0
KeyHeaderText BYTE "DES round subkeys (PC-1, rotations, PC-2):",0Dh,0Ah,0
KeyPrefixText BYTE "K",0
KeyEqualsText BYTE " = ",0

Cmd_KEYGEN BYTE "KEYGEN",0
Cmd_ENCRYPT BYTE "ENCRYPT",0
Cmd_DECRYPT BYTE "DECRYPT",0
Cmd_DUMP BYTE "DUMP",0
Cmd_STATS BYTE "STATS",0
Cmd_CLEAR BYTE "CLEAR",0
Cmd_EXIT BYTE "EXIT",0

InputBuffer BYTE MAX_CMD_LEN DUP(0)
CmdVerb BYTE 32 DUP(0)
Arg1Buffer BYTE MAX_ARG_LEN DUP(0)
Arg2Buffer BYTE MAX_ARG_LEN DUP(0)
KeyBytes BYTE DES_KEY_BYTES DUP(0)
RoundKeys BYTE DES_SCHEDULE_BYTES DUP(0)

.code

main PROC
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    call Clrscr
    mov  edx,OFFSET WelcomeText
    call WriteString
shell_loop:
    mov  edx,OFFSET PromptText
    call WriteString
    mov  edx,OFFSET InputBuffer
    mov  ecx,MAX_CMD_LEN-1
    call ReadString
    test eax,eax
    jz   shell_loop
    push OFFSET InputBuffer
    call ParseCommandLine
    test eax,eax
    jz   shell_dispatch
    mov  edx,OFFSET SyntaxText
    call WriteString
    jmp  shell_loop
shell_dispatch:
    cmp  BYTE PTR [CmdVerb],0
    je   shell_loop
    call DispatchCommand
    cmp  eax,1
    jne  shell_loop
    mov  edx,OFFSET ExitText
    call WriteString
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    exit
main ENDP

ClearBuffer PROC STDCALL pBuffer:PTR BYTE,bufferSize:DWORD
    push ebp
    mov  ebp,esp
    push ecx
    push edi
    mov  edi,DWORD PTR [ebp+8]
    mov  ecx,DWORD PTR [ebp+12]
    test edi,edi
    jz   clear_bad
    xor  eax,eax
    rep  stosb
    xor  eax,eax
    jmp  clear_done
clear_bad:
    mov  eax,1
clear_done:
    pop  edi
    pop  ecx
    mov  esp,ebp
    pop  ebp
    ret  8
ClearBuffer ENDP

SkipSpaces PROC STDCALL pText:PTR BYTE
    push ebp
    mov  ebp,esp
    push esi
    mov  esi,DWORD PTR [ebp+8]
skip_loop:
    mov  al,BYTE PTR [esi]
    cmp  al,' '
    je   skip_one
    cmp  al,9
    jne  skip_done
skip_one:
    inc  esi
    jmp  skip_loop
skip_done:
    mov  eax,esi
    pop  esi
    mov  esp,ebp
    pop  ebp
    ret  4
SkipSpaces ENDP

; Returns EAX = address immediately after the token, or zero on syntax error.
ExtractToken PROC STDCALL pText:PTR BYTE,pDestination:PTR BYTE,capacity:DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push DWORD PTR [ebp+8]
    call SkipSpaces
    mov  esi,eax
    mov  edi,DWORD PTR [ebp+12]
    mov  edx,DWORD PTR [ebp+16]
    test edi,edi
    jz   token_error
    cmp  edx,2
    jb   token_error
    xor  ecx,ecx
    mov  al,BYTE PTR [esi]
    test al,al
    jz   token_finish
    cmp  al,'"'
    jne  token_unquoted
    inc  esi
token_quoted_loop:
    mov  al,BYTE PTR [esi]
    test al,al
    jz   token_error
    cmp  al,'"'
    je   token_quote_end
    mov  ebx,edx
    dec  ebx
    cmp  ecx,ebx
    jae  token_error
    mov  BYTE PTR [edi+ecx],al
    inc  ecx
    inc  esi
    jmp  token_quoted_loop
token_quote_end:
    inc  esi
    mov  al,BYTE PTR [esi]
    test al,al
    jz   token_finish
    cmp  al,' '
    je   token_finish
    cmp  al,9
    je   token_finish
    jmp  token_error
token_unquoted:
    mov  al,BYTE PTR [esi]
    test al,al
    jz   token_finish
    cmp  al,' '
    je   token_finish
    cmp  al,9
    je   token_finish
    mov  ebx,edx
    dec  ebx
    cmp  ecx,ebx
    jae  token_error
    mov  BYTE PTR [edi+ecx],al
    inc  ecx
    inc  esi
    jmp  token_unquoted
token_finish:
    mov  BYTE PTR [edi+ecx],0
    mov  eax,esi
    jmp  token_done
token_error:
    xor  eax,eax
token_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  12
ExtractToken ENDP

ParseCommandLine PROC STDCALL pInput:PTR BYTE
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push 32
    push OFFSET CmdVerb
    call ClearBuffer
    push MAX_ARG_LEN
    push OFFSET Arg1Buffer
    call ClearBuffer
    push MAX_ARG_LEN
    push OFFSET Arg2Buffer
    call ClearBuffer
    push 32
    push OFFSET CmdVerb
    push DWORD PTR [ebp+8]
    call ExtractToken
    test eax,eax
    jz   parse_error
    push MAX_ARG_LEN
    push OFFSET Arg1Buffer
    push eax
    call ExtractToken
    test eax,eax
    jz   parse_error
    push MAX_ARG_LEN
    push OFFSET Arg2Buffer
    push eax
    call ExtractToken
    test eax,eax
    jz   parse_error
    push eax
    call SkipSpaces
    cmp  BYTE PTR [eax],0
    jne  parse_error
    xor  eax,eax
    jmp  parse_done
parse_error:
    mov  eax,1
parse_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  4
ParseCommandLine ENDP

StringEqualsIgnoreCase PROC STDCALL pLeft:PTR BYTE,pRight:PTR BYTE
    push ebp
    mov  ebp,esp
    push ebx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,DWORD PTR [ebp+12]
compare_loop:
    mov  al,BYTE PTR [esi]
    mov  bl,BYTE PTR [edi]
    cmp  al,'a'
    jb   compare_left_ready
    cmp  al,'z'
    ja   compare_left_ready
    sub  al,20h
compare_left_ready:
    cmp  bl,'a'
    jb   compare_right_ready
    cmp  bl,'z'
    ja   compare_right_ready
    sub  bl,20h
compare_right_ready:
    cmp  al,bl
    jne  compare_no
    test al,al
    jz   compare_yes
    inc  esi
    inc  edi
    jmp  compare_loop
compare_yes:
    mov  eax,1
    jmp  compare_done
compare_no:
    xor  eax,eax
compare_done:
    pop  edi
    pop  esi
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
StringEqualsIgnoreCase ENDP

HexCharToNibble PROC STDCALL character:DWORD
    push ebp
    mov  ebp,esp
    mov  eax,DWORD PTR [ebp+8]
    and  eax,0FFh
    cmp  al,'0'
    jb   nibble_bad
    cmp  al,'9'
    jbe  nibble_digit
    cmp  al,'A'
    jb   nibble_lower_test
    cmp  al,'F'
    jbe  nibble_upper
nibble_lower_test:
    cmp  al,'a'
    jb   nibble_bad
    cmp  al,'f'
    ja   nibble_bad
    sub  al,'a'
    add  al,10
    movzx eax,al
    jmp  nibble_done
nibble_upper:
    sub  al,'A'
    add  al,10
    movzx eax,al
    jmp  nibble_done
nibble_digit:
    sub  al,'0'
    movzx eax,al
    jmp  nibble_done
nibble_bad:
    mov  eax,0FFFFFFFFh
nibble_done:
    mov  esp,ebp
    pop  ebp
    ret  4
HexCharToNibble ENDP

ParseHexKey PROC STDCALL pText:PTR BYTE,pKey:PTR BYTE
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,DWORD PTR [ebp+12]
    test esi,esi
    jz   hexkey_bad
    test edi,edi
    jz   hexkey_bad
    cmp  BYTE PTR [esi],'0'
    jne  hexkey_length
    mov  al,BYTE PTR [esi+1]
    cmp  al,'x'
    je   hexkey_skip_prefix
    cmp  al,'X'
    jne  hexkey_length
hexkey_skip_prefix:
    add  esi,2
hexkey_length:
    xor  ecx,ecx
hexkey_count:
    cmp  BYTE PTR [esi+ecx],0
    je   hexkey_count_done
    inc  ecx
    jmp  hexkey_count
hexkey_count_done:
    cmp  ecx,16
    jne  hexkey_bad
    xor  ecx,ecx
hexkey_convert:
    movzx eax,BYTE PTR [esi+ecx*2]
    push eax
    call HexCharToNibble
    cmp  eax,0FFFFFFFFh
    je   hexkey_bad
    mov  ebx,eax
    shl  ebx,4
    movzx eax,BYTE PTR [esi+ecx*2+1]
    push eax
    call HexCharToNibble
    cmp  eax,0FFFFFFFFh
    je   hexkey_bad
    or   eax,ebx
    mov  BYTE PTR [edi+ecx],al
    inc  ecx
    cmp  ecx,DES_KEY_BYTES
    jb   hexkey_convert
    xor  eax,eax
    jmp  hexkey_done
hexkey_bad:
    mov  eax,1
hexkey_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
ParseHexKey ENDP

PrintDESSubkeys PROC STDCALL pSchedule:PTR BYTE
    push ebp
    mov  ebp,esp
    sub  esp,8
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    test esi,esi
    jz   pds_bad
    mov  edx,OFFSET KeyHeaderText
    call WriteString
    mov  DWORD PTR [ebp-4],0
pds_round:
    mov  edx,OFFSET KeyPrefixText
    call WriteString
    mov  eax,DWORD PTR [ebp-4]
    inc  eax
    call WriteDec
    mov  edx,OFFSET KeyEqualsText
    call WriteString
    mov  DWORD PTR [ebp-8],0
pds_byte:
    mov  eax,DWORD PTR [ebp-4]
    imul eax,DES_SUBKEY_BYTES
    add  eax,DWORD PTR [ebp-8]
    movzx eax,BYTE PTR [esi+eax]
    push eax
    call PrintHexByte
    inc  DWORD PTR [ebp-8]
    cmp  DWORD PTR [ebp-8],DES_SUBKEY_BYTES
    jb   pds_byte
    call Crlf
    inc  DWORD PTR [ebp-4]
    cmp  DWORD PTR [ebp-4],DES_ROUNDS
    jb   pds_round
    xor  eax,eax
    jmp  pds_done
pds_bad:
    mov  eax,1
pds_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  4
PrintDESSubkeys ENDP

CheckKeyArgument PROC
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push OFFSET KeyBytes
    push OFFSET Arg2Buffer
    call ParseHexKey
    test eax,eax
    jz   checkkey_parity
    mov  edx,OFFSET HexText
    call WriteString
    mov  eax,1
    jmp  checkkey_done
checkkey_parity:
    push OFFSET KeyBytes
    call ValidateDESOddParity
    test eax,eax
    jz   checkkey_ok
    mov  edx,OFFSET ParityText
    call WriteString
    mov  eax,1
    jmp  checkkey_done
checkkey_ok:
    xor  eax,eax
checkkey_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret
CheckKeyArgument ENDP

ReportOperationStatus PROC STDCALL statusValue:DWORD
    push ebp
    mov  ebp,esp
    push edx
    cmp  DWORD PTR [ebp+8],0
    je   report_done
    mov  edx,OFFSET OperationText
    call WriteString
    mov  eax,DWORD PTR [ebp+8]
    call WriteDec
    call Crlf
report_done:
    xor  eax,eax
    pop  edx
    mov  esp,ebp
    pop  ebp
    ret  4
ReportOperationStatus ENDP

DispatchCommand PROC
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push OFFSET Cmd_KEYGEN
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_encrypt
    cmp  BYTE PTR [Arg1Buffer],0
    je   dispatch_wrong_args
    cmp  BYTE PTR [Arg2Buffer],0
    jne  dispatch_wrong_args
    push OFFSET KeyBytes
    push OFFSET Arg1Buffer
    call ParseHexKey
    test eax,eax
    jnz  dispatch_hex_error
    push OFFSET KeyBytes
    call ValidateDESOddParity
    test eax,eax
    jnz  dispatch_parity_error
    push OFFSET RoundKeys
    push OFFSET KeyBytes
    call GenerateDESSubkeys
    push OFFSET RoundKeys
    call PrintDESSubkeys
    jmp  dispatch_continue
dispatch_encrypt:
    push OFFSET Cmd_ENCRYPT
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_decrypt
    cmp  BYTE PTR [Arg1Buffer],0
    je   dispatch_wrong_args
    cmp  BYTE PTR [Arg2Buffer],0
    je   dispatch_wrong_args
    call CheckKeyArgument
    test eax,eax
    jnz  dispatch_continue
    push OFFSET KeyBytes
    push OFFSET Arg1Buffer
    call ModuleC_Encrypt
    test eax,eax
    jnz  dispatch_report_status
    mov  edx,OFFSET EncryptOkText
    call WriteString
    jmp  dispatch_continue
dispatch_decrypt:
    push OFFSET Cmd_DECRYPT
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_dump
    cmp  BYTE PTR [Arg1Buffer],0
    je   dispatch_wrong_args
    cmp  BYTE PTR [Arg2Buffer],0
    je   dispatch_wrong_args
    call CheckKeyArgument
    test eax,eax
    jnz  dispatch_continue
    push OFFSET KeyBytes
    push OFFSET Arg1Buffer
    call ModuleC_Decrypt
    test eax,eax
    jnz  dispatch_report_status
    mov  edx,OFFSET DecryptOkText
    call WriteString
    jmp  dispatch_continue
dispatch_dump:
    push OFFSET Cmd_DUMP
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_stats
    cmp  BYTE PTR [Arg1Buffer],0
    je   dispatch_wrong_args
    cmp  BYTE PTR [Arg2Buffer],0
    jne  dispatch_wrong_args
    push OFFSET Arg1Buffer
    call DisplayFileHexDump
    test eax,eax
    jnz  dispatch_report_status
    jmp  dispatch_continue
dispatch_stats:
    push OFFSET Cmd_STATS
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_clear
    cmp  BYTE PTR [Arg1Buffer],0
    je   dispatch_wrong_args
    cmp  BYTE PTR [Arg2Buffer],0
    jne  dispatch_wrong_args
    push OFFSET Arg1Buffer
    call DisplayFileStats
    test eax,eax
    jnz  dispatch_report_status
    jmp  dispatch_continue
dispatch_clear:
    push OFFSET Cmd_CLEAR
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_exit
    cmp  BYTE PTR [Arg1Buffer],0
    jne  dispatch_wrong_args
    call Clrscr
    jmp  dispatch_continue
dispatch_exit:
    push OFFSET Cmd_EXIT
    push OFFSET CmdVerb
    call StringEqualsIgnoreCase
    test eax,eax
    jz   dispatch_unknown
    cmp  BYTE PTR [Arg1Buffer],0
    jne  dispatch_wrong_args
    mov  eax,1
    jmp  dispatch_done
dispatch_wrong_args:
    mov  edx,OFFSET MissingText
    call WriteString
    jmp  dispatch_continue
dispatch_hex_error:
    mov  edx,OFFSET HexText
    call WriteString
    jmp  dispatch_continue
dispatch_parity_error:
    mov  edx,OFFSET ParityText
    call WriteString
    jmp  dispatch_continue
dispatch_report_status:
    push eax
    call ReportOperationStatus
    jmp  dispatch_continue
dispatch_unknown:
    mov  edx,OFFSET UnknownText
    call WriteString
dispatch_continue:
    xor  eax,eax
dispatch_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret
DispatchCommand ENDP

END main
