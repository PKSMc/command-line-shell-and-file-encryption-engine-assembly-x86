.386
.model flat, stdcall
INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data
    format BYTE "[Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |  ASCII ", 0
    line BYTE "-------------------------------------------------------------------------", 0
    space BYTE " "
    wall BYTE "|"

.code
DisplayHexDump PROC
    pushad

    ;Print format
    mov edx, OFFSET format
    call WriteString
    mov edx, OFFSET line
    call WriteString

    ; ESI = pointer
    ; ECX = length

    mov esi, edx        ; EDX = address
    mov ecx, eax        ; EAX = length

DumpLoop:
    cmp ecx, 0
    je DumpDone

    ; แสดง offset address
    mov eax, esi
    call WriteHex
    call Crlf

    ; แสดง byte
    mov al, [esi]
    ; ดูว่าค่าเข้าข่ายตามนี้ 20h <= [esi] <= 7Eh
    cmp al, 20h
    jb NotPrintable
    cmp al, 7Eh
    ja NotPrintable
    
    ;ปริ้นค่าเป็นเลขฐาน 16 จาก al
    call WriteHex 
    
    ;ปริ้นค่าเป็น ASCII จาก dl
    mov dl, al
    call WriteChar
    jmp Continue

    NotPrintable:
    mov dl, '.'
    call WriteChar

    Continue:
    ; ไป byte ถัดไป
    inc esi
    dec ecx

    jmp DumpLoop

DumpDone:
    popad
    ret
DisplayHexDump ENDP

ComputeBufferStats PROC
    pushad

    ; ESI = input buffer
    ; ECX = buffer length

    mov esi, edx
    mov ecx, eax

CountLoop:
    cmp ecx, 0
    je CountDone

    xor ebx, ebx
    mov bl, [esi]          ; BL = byte ที่อ่านมา

    inc histogram[ebx*4]   ; histogram[byte]++

    inc esi
    dec ecx

    jmp CountLoop

CountDone:
    popad
    ret
ComputeBufferStats ENDP