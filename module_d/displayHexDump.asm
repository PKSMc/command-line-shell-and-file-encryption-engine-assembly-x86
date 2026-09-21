DisplayHexDump PROC
    pushad

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
    call WriteHex

    ; ไป byte ถัดไป
    inc esi
    dec ecx

    jmp DumpLoop

DumpDone:
    popad
    ret
DisplayHexDump ENDP