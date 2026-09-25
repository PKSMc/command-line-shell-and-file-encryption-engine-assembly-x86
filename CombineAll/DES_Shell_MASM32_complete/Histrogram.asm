; Module D - 256-bin byte histogram and top-occurrence reporting.

.386
option casemap:none
option prologue:none
option epilogue:none

include Irvine32.inc
include displayHex_Dump.inc
include _Hisrtrogram.inc

INVALID_HANDLE_VALUE EQU -1

PUBLIC ComputeBufferStats
PUBLIC AccumulateBufferStats
PUBLIC PrintHistogram
PUBLIC PrintTopOccurrence
PUBLIC DisplayFileStats

.data
StatsBuffer BYTE 4096 DUP(0)
FileHistogram DWORD 256 DUP(0)
WorkHistogram DWORD 256 DUP(0)
StatsSizeText BYTE "Total File Size: ",0
StatsBytesText BYTE " Bytes",0
StatsBinsText BYTE "Non-zero histogram bins (byte : count):",0
StatsTopText BYTE "Top Byte Occurrences:",0
OccurrenceText BYTE " occurrences  [",0

.code

AccumulateBufferStats PROC STDCALL pBuffer:PTR BYTE,byteCount:DWORD,pHistogram:PTR DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  ecx,DWORD PTR [ebp+12]
    mov  edi,DWORD PTR [ebp+16]
    test edi,edi
    jz   abs_bad
    test ecx,ecx
    jz   abs_ok
    test esi,esi
    jz   abs_bad
abs_loop:
    movzx eax,BYTE PTR [esi]
    inc  DWORD PTR [edi+eax*4]
    inc  esi
    dec  ecx
    jnz  abs_loop
abs_ok:
    xor  eax,eax
    jmp  abs_done
abs_bad:
    mov  eax,1
abs_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  12
AccumulateBufferStats ENDP

ComputeBufferStats PROC STDCALL pBuffer:PTR BYTE,byteCount:DWORD,pHistogram:PTR DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  edi,DWORD PTR [ebp+16]
    test edi,edi
    jz   cbs_bad
    xor  eax,eax
    mov  ecx,256
    rep  stosd
    push DWORD PTR [ebp+16]
    push DWORD PTR [ebp+12]
    push DWORD PTR [ebp+8]
    call AccumulateBufferStats
    jmp  cbs_done
cbs_bad:
    mov  eax,1
cbs_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  12
ComputeBufferStats ENDP

PrintHistogram PROC STDCALL pHistogram:PTR DWORD
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    test esi,esi
    jz   ph_bad
    xor  ebx,ebx
ph_loop:
    mov  eax,DWORD PTR [esi+ebx*4]
    test eax,eax
    jz   ph_next
    push eax
    push ebx
    call PrintHexByte
    mov  al,' '
    call WriteChar
    mov  al,':'
    call WriteChar
    mov  al,' '
    call WriteChar
    pop  eax
    call WriteDec
    call Crlf
ph_next:
    inc  ebx
    cmp  ebx,256
    jb   ph_loop
    xor  eax,eax
    jmp  ph_done
ph_bad:
    mov  eax,1
ph_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  4
PrintHistogram ENDP

PrintTopOccurrence PROC STDCALL pHistogram:PTR DWORD,requestedCount:DWORD
    push ebp
    mov  ebp,esp
    sub  esp,16
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    test esi,esi
    jz   pto_bad
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,OFFSET WorkHistogram
    mov  ecx,256
    rep  movsd
    mov  DWORD PTR [ebp-4],0
pto_rank_loop:
    mov  eax,DWORD PTR [ebp-4]
    cmp  eax,DWORD PTR [ebp+12]
    jae  pto_ok
    xor  ecx,ecx
    xor  ebx,ebx
    xor  edx,edx
pto_search:
    mov  eax,DWORD PTR WorkHistogram[ecx*4]
    cmp  eax,edx
    jbe  pto_not_better
    mov  edx,eax
    mov  ebx,ecx
pto_not_better:
    inc  ecx
    cmp  ecx,256
    jb   pto_search
    test edx,edx
    jz   pto_ok
    mov  DWORD PTR [ebp-8],ebx
    mov  DWORD PTR [ebp-12],edx
    mov  eax,DWORD PTR [ebp-4]
    inc  eax
    call WriteDec
    mov  al,'.'
    call WriteChar
    mov  al,' '
    call WriteChar
    mov  al,'['
    call WriteChar
    mov  al,'0'
    call WriteChar
    mov  al,'x'
    call WriteChar
    push DWORD PTR [ebp-8]
    call PrintHexByte
    mov  al,']'
    call WriteChar
    mov  al,' '
    call WriteChar
    mov  al,':'
    call WriteChar
    mov  al,' '
    call WriteChar
    mov  eax,DWORD PTR [ebp-12]
    call WriteDec
    mov  edx,OFFSET OccurrenceText
    call WriteString
    mov  eax,DWORD PTR [ebp-12]
    cmp  eax,50
    jbe  pto_star_count_ready
    mov  eax,50
pto_star_count_ready:
    mov  DWORD PTR [ebp-16],eax
pto_stars:
    cmp  DWORD PTR [ebp-16],0
    je   pto_close_bar
    mov  al,'*'
    call WriteChar
    dec  DWORD PTR [ebp-16]
    jmp  pto_stars
pto_close_bar:
    mov  al,']'
    call WriteChar
    call Crlf
    mov  eax,DWORD PTR [ebp-8]
    mov  DWORD PTR WorkHistogram[eax*4],0
    inc  DWORD PTR [ebp-4]
    jmp  pto_rank_loop
pto_ok:
    xor  eax,eax
    jmp  pto_done
pto_bad:
    mov  eax,1
pto_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  8
PrintTopOccurrence ENDP

DisplayFileStats PROC STDCALL pFilename:PTR BYTE
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
    jz   dfs_bad
    call OpenInputFile
    cmp  eax,INVALID_HANDLE_VALUE
    je   dfs_open_error
    mov  DWORD PTR [ebp-4],eax
    mov  DWORD PTR [ebp-8],0
    mov  edi,OFFSET FileHistogram
    xor  eax,eax
    mov  ecx,256
    rep  stosd
dfs_read:
    mov  eax,DWORD PTR [ebp-4]
    mov  edx,OFFSET StatsBuffer
    mov  ecx,SIZEOF StatsBuffer
    call ReadFromFile
    jc   dfs_read_error
    mov  DWORD PTR [ebp-12],eax
    test eax,eax
    jz   dfs_report
    add  DWORD PTR [ebp-8],eax
    push OFFSET FileHistogram
    push eax
    push OFFSET StatsBuffer
    call AccumulateBufferStats
    jmp  dfs_read
dfs_report:
    mov  edx,OFFSET StatsSizeText
    call WriteString
    mov  eax,DWORD PTR [ebp-8]
    call WriteDec
    mov  edx,OFFSET StatsBytesText
    call WriteString
    call Crlf
    mov  edx,OFFSET StatsBinsText
    call WriteString
    call Crlf
    push OFFSET FileHistogram
    call PrintHistogram
    mov  edx,OFFSET StatsTopText
    call WriteString
    call Crlf
    push 5
    push OFFSET FileHistogram
    call PrintTopOccurrence
    xor  ebx,ebx
    jmp  dfs_close
dfs_read_error:
    mov  ebx,4
dfs_close:
    mov  eax,DWORD PTR [ebp-4]
    call CloseFile
    mov  eax,ebx
    jmp  dfs_done
dfs_bad:
    mov  eax,1
    jmp  dfs_done
dfs_open_error:
    mov  eax,2
dfs_done:
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    ret  4
DisplayFileStats ENDP

END
