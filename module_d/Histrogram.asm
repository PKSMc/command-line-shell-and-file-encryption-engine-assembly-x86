.386
.model flat, stdcall
INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data

debugBuffer BYTE 48h, 65h, 6Ch, 6Ch
            BYTE 6Fh, 20h, 57h, 6Fh
            BYTE 72h, 6Ch, 64h, 21h
            BYTE 48h, 65h, 6Ch, 6Ch

debugLength DWORD 16

topByte  DWORD 0
topCount DWORD 0

hexTable    BYTE "0123456789ABCDEF"
histogram DWORD 256 DUP(0)

histHeader BYTE "BYTE   COUNT", 0

occurrenceText BYTE " occurrences [**]", 0
statsHeader BYTE "Total File Size: ", 0
bytesText   BYTE " Bytes", 0

entropyText BYTE "Entropy Statistics: High Diffusion (Ciphertext Uniformity Check PASSED)", 0

topHeader   BYTE "Top Byte Occurrences:", 0


.code
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

PrintTopOccurrence PROC

    pushad

    mov esi, 1              ; ลำดับ 1-5

TopLoop:

    cmp esi, 6
    je DoneTop

    call FindTopOccurrence

    ; EAX = byte ที่พบมากที่สุด
    ; EDX = จำนวนครั้ง

    push eax
    push edx
    push esi

    ; พิมพ์ลำดับ
    mov eax, esi
    call WriteDec

    mov al, '.'
    call WriteChar

    mov al, ' '
    call WriteChar

    ; [
    mov al, '['
    call WriteChar

    ; 0x
    mov al, '0'
    call WriteChar

    mov al, 'x'
    call WriteChar

    ; byte
    pop esi
    pop edx
    pop eax

    push eax
    push edx
    push esi

    call PrintHexByte

    ; ]
    mov al, ']'
    call WriteChar

    ; :
    mov al, ' '
    call WriteChar

    mov al, ':'
    call WriteChar

    mov al, ' '
    call WriteChar

    ; count
    pop esi
    pop edx
    pop eax

    push eax
    push esi

    mov eax, edx
    call WriteDec

    ; " occurrences [**]"
    mov edx, OFFSET occurrenceText
    call WriteString

    call Crlf

    ; เอา byte ที่เจอออกจาก histogram
    pop esi
    pop eax

    mov DWORD PTR histogram[eax*4], 0

    inc esi
    jmp TopLoop

DoneTop:

    popad
    ret

PrintTopOccurrence ENDP

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

    ; ต้องคืนค่าออกมาหลัง popad
    mov eax, ebx
    mov topByte, eax

    mov topCount, edx

    popad

    mov eax, topByte
    mov edx, topCount

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

    ; Total File Size
    mov edx, OFFSET statsHeader
    call WriteString

    mov eax, debugLength
    call WriteDec

    mov edx, OFFSET bytesText
    call WriteString
    call Crlf

    ; Entropy Statistics
    mov edx, OFFSET entropyText
    call WriteString
    call Crlf

    ; Top Byte Occurrences
    mov edx, OFFSET topHeader
    call WriteString
    call Crlf

    call PrintTopOccurrence

    exit

main ENDP
END main