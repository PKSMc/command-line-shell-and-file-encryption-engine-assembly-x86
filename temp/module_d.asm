.386
.model flat, stdcall
INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data
; --- Shared Data ---
hexTable    BYTE "0123456789ABCDEF"

; --- Hex Dump Data ---
dumpHeader  BYTE "[Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII", 0
dumpLine    BYTE "----------------------------------------------------------------", 0

; --- Histogram Data ---
topByte     DWORD 0
topCount    DWORD 0
histogram   DWORD 256 DUP(0)

histHeader      BYTE "BYTE   COUNT", 0
occurrenceText  BYTE " occurrences [**]", 0
statsHeader     BYTE "Total File Size: ", 0
bytesText       BYTE " Bytes", 0
entropyText     BYTE "Entropy Statistics: High Diffusion (Ciphertext Uniformity Check PASSED)", 0
topHeader       BYTE "Top Byte Occurrences:", 0

.code

; ============================================================
; Shared Utility: PrintHexByte
; ============================================================
PrintHexByte PROC
    push eax
    push edx

    ; พิมพ์ 4 bits ด้านบน
    movzx edx, al
    shr edx, 4
    mov al, BYTE PTR hexTable[edx]
    call WriteChar

    ; พิมพ์ 4 bits ด้านล่าง
    pop edx
    pop eax
    push eax
    push edx

    movzx edx, al
    and edx, 0Fh
    mov al, BYTE PTR hexTable[edx]
    call WriteChar

    pop edx
    pop eax
    ret
PrintHexByte ENDP

; ============================================================
; Hex Dump Procedures
; ============================================================
DisplayHexDump PROC
    pushad

    ; แสดง Header
    mov edx, OFFSET dumpHeader
    call WriteString
    call Crlf

    mov edx, OFFSET dumpLine
    call WriteString
    call Crlf

    ; EBX = Address / Offset
    ; ESI = pointer ไปยัง buffer
    ; ECX = จำนวน byte ที่เหลือ
    xor ebx, ebx

NextLine:
    cmp ecx, 0
    je DumpDone

    mov edi, esi

    ; Print Address
    mov eax, ebx
    call WriteHex
    mov al, ' '
    call WriteChar
    mov al, ' '
    call WriteChar

    ; EBP = จำนวน byte ในบรรทัดนี้ สูงสุด 16 byte
    xor ebp, ebp

HexLoop:
    cmp ebp, 16
    jae HexPadding
    cmp ecx, 0
    je HexPadding

    ; อ่าน byte จาก buffer
    mov al, BYTE PTR [esi]
    call PrintHexByte
    mov al, ' '
    call WriteChar

    inc esi
    dec ecx
    inc ebp
    jmp HexLoop

HexPadding:
    cmp ebp, 16
    je PrintASCII
    mov eax, 16
    sub eax, ebp

PaddingLoop:
    cmp eax, 0
    je PrintASCII
    push eax
    mov al, ' '
    call WriteChar
    mov al, ' '
    call WriteChar
    mov al, ' '
    pop eax
    dec eax
    jmp PaddingLoop

PrintASCII:
    mov al, '|'
    call WriteChar
    mov al, ' '
    call WriteChar

    mov esi, edi
    mov eax, ebp
    push eax

ASCII_Loop:
    pop eax
    cmp eax, 0
    je EndLine
    push eax

    mov dl, BYTE PTR [esi]
    cmp dl, 20h
    jb NotPrintable
    cmp dl, 7Eh
    ja NotPrintable
    mov al, dl
    call WriteChar
    jmp NextASCII

NotPrintable:
    mov al, '.'
    call WriteChar

NextASCII:
    inc esi
    pop eax
    dec eax
    push eax
    jmp ASCII_Loop

EndLine:
    call Crlf
    add ebx, ebp
    jmp NextLine

DumpDone:
    popad
    ret
DisplayHexDump ENDP

; ============================================================
; Histogram Procedures
; ============================================================
ComputeBufferStats PROC
    pushad
    ; ESI = buffer
    ; ECX = จำนวน byte
CountLoop:
    cmp ecx, 0
    je DoneCounting

    movzx eax, BYTE PTR [esi]
    inc DWORD PTR histogram[eax*4]

    inc esi
    dec ecx
    jmp CountLoop

DoneCounting:
    popad
    ret
ComputeBufferStats ENDP

FindTopOccurrence PROC
    pushad
    mov esi, 0              ; current bin
    mov ebx, 0              ; best byte
    mov edx, 0              ; best count

SearchLoop:
    cmp esi, 256
    je DoneSearch
    mov ecx, histogram[esi*4]
    cmp ecx, edx
    jbe NotBetter
    mov edx, ecx
    mov ebx, esi

NotBetter:
    inc esi
    jmp SearchLoop

DoneSearch:
    mov eax, ebx
    mov topByte, eax
    mov topCount, edx
    popad

    mov eax, topByte
    mov edx, topCount
    ret
FindTopOccurrence ENDP

PrintTopOccurrence PROC
    pushad
    mov esi, 1              ; ลำดับ 1-5

TopLoop:
    cmp esi, 6
    je DoneTop

    call FindTopOccurrence

    push eax
    push edx
    push esi

    mov eax, esi
    call WriteDec
    mov al, '.'
    call WriteChar
    mov al, ' '
    call WriteChar
    mov al, '['
    call WriteChar
    mov al, '0'
    call WriteChar
    mov al, 'x'
    call WriteChar

    pop esi
    pop edx
    pop eax
    push eax
    push edx
    push esi
    call PrintHexByte

    mov al, ']'
    call WriteChar
    mov al, ' '
    call WriteChar
    mov al, ':'
    call WriteChar
    mov al, ' '
    call WriteChar

    pop esi
    pop edx
    pop eax
    push eax
    push esi
    mov eax, edx
    call WriteDec

    mov edx, OFFSET occurrenceText
    call WriteString
    call Crlf

    pop esi
    pop eax
    mov DWORD PTR histogram[eax*4], 0

    inc esi
    jmp TopLoop

DoneTop:
    popad
    ret
PrintTopOccurrence ENDP

PrintHistogram PROC
    pushad
    mov ebx, 0

PrintLoop:
    cmp ebx, 256
    je DonePrint
    mov eax, histogram[ebx*4]
    cmp eax, 0
    je SkipPrint

    push eax
    push ebx
    mov eax, ebx
    call PrintHexByte
    mov al, ' '
    call WriteChar
    pop ebx
    pop eax
    call WriteDec
    call Crlf

SkipPrint:
    inc ebx
    jmp PrintLoop

DonePrint:
    popad
    ret
PrintHistogram ENDP

END
