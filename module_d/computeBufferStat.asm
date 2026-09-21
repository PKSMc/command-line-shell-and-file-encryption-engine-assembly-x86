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