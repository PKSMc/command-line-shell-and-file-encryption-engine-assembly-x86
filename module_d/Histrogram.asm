.386
.model flat, stdcall
INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data

debugBuffer BYTE 01h, 23h, 45h, 67h
            BYTE 89h, 0ABh, 0CDh, 0EFh
            BYTE 01h, 23h, 45h, 67h
            BYTE 89h, 0ABh, 0CDh, 0EFh

debugLength DWORD 16
topByte  DWORD 0
topCount DWORD 0

hexTable    BYTE "0123456789ABCDEF"
histogram DWORD 256 DUP(0)

histHeader BYTE "BYTE   COUNT", 0


.code
PrintTopOccurrence PROC

    pushad

    call FindTopOccurrence

    call PrintHexByte

    mov al, ' '
    call WriteChar

    mov eax, topCount
    call WriteDec

    call Crlf

    popad
    ret

PrintTopOccurrence ENDP

FindTopOccurrence PROC

    pushad

    mov esi, 0
    mov ebx, 0
    mov edx, 0

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

    mov topByte, ebx
    mov topCount, edx

    popad

    mov eax, topByte

    ret

FindTopOccurrence ENDP

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

PrintHexByte PROC

    push eax
    push edx

    ; -------------------------
    ; พิมพ์ 4 bits ด้านบน
    ; -------------------------
    movzx edx, al
    shr edx, 4

    mov al, BYTE PTR hexTable[edx]
    call WriteChar


    ; -------------------------
    ; พิมพ์ 4 bits ด้านล่าง
    ; -------------------------
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

PrintHistogram PROC

    pushad

    mov ebx, 0

PrintLoop:

    cmp ebx, 256
    je DonePrint

    mov eax, histogram[ebx*4]

    cmp eax, 0
    je SkipPrint

    ; EBX = byte
    ; EAX = count

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

main PROC

    mov esi, OFFSET debugBuffer
    mov ecx, debugLength

    call ComputeBufferStats
    call PrintHistogram
    call PrintTopOccurrence

    exit

main ENDP
END main