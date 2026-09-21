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