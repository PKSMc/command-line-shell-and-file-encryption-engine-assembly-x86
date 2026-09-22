.386
.model flat, stdcall
INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

.data

hexTable    BYTE "0123456789ABCDEF"

dumpHeader  BYTE "[Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII", 0
dumpLine    BYTE "----------------------------------------------------------------", 0

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


DisplayHexDump PROC

    pushad

    ; --------------------------------
    ; แสดง Header
    ; --------------------------------
    mov edx, OFFSET dumpHeader
    call WriteString
    call Crlf

    mov edx, OFFSET dumpLine
    call WriteString
    call Crlf


    ; --------------------------------
    ; EBX = Address / Offset
    ; ESI = pointer ไปยัง buffer
    ; ECX = จำนวน byte ที่เหลือ
    ; --------------------------------
    xor ebx, ebx


NextLine:

    ; ไม่มีข้อมูลเหลือแล้ว
    cmp ecx, 0
    je DumpDone


    ; --------------------------------
    ; เก็บ address ของ byte ตัวแรก
    ; ของบรรทัดนี้ไว้ใน EDI
    ; --------------------------------
    mov edi, esi


    ; --------------------------------
    ; Print Address
    ; --------------------------------
    mov eax, ebx
    call WriteHex

    mov al, ' '
    call WriteChar

    mov al, ' '
    call WriteChar


    ; --------------------------------
    ; EBP = จำนวน byte ในบรรทัดนี้
    ; สูงสุด 16 byte
    ; --------------------------------
    xor ebp, ebp


HexLoop:

    ; ครบ 16 byte แล้ว
    cmp ebp, 16
    jae HexPadding

    ; ไม่มี byte เหลือ
    cmp ecx, 0
    je HexPadding


    ; --------------------------------
    ; อ่าน byte จาก buffer
    ; --------------------------------
    mov al, BYTE PTR [esi]

    ; พิมพ์ XX
    call PrintHexByte

    ; เว้นวรรค
    mov al, ' '
    call WriteChar


    inc esi
    dec ecx
    inc ebp

    jmp HexLoop


    ; --------------------------------
    ; ถ้า byte ไม่ครบ 16
    ; เติมช่องว่างให้ ASCII ตรงตำแหน่ง
    ; --------------------------------
HexPadding:

    cmp ebp, 16
    je PrintASCII

    mov eax, 16
    sub eax, ebp

PaddingLoop:

    cmp eax, 0
    je PrintASCII

    mov al, ' '
    call WriteChar

    mov al, ' '
    call WriteChar

    mov al, ' '
    call WriteChar

    dec eax

    jmp PaddingLoop


    ; --------------------------------
    ; Print ASCII
    ; --------------------------------
PrintASCII:

    mov al, '|'
    call WriteChar

    mov al, ' '
    call WriteChar


    ; ESI ตอนนี้อยู่ท้าย buffer
    ; กลับไปที่ byte แรกของบรรทัด
    mov esi, edi

    ; จำนวน byte ในบรรทัด
    mov eax, ebp


ASCII_Loop:

    cmp eax, 0
    je EndLine


    ; อ่าน byte
    mov dl, BYTE PTR [esi]

    ; ตรวจว่าเป็น printable ASCII หรือไม่
    cmp dl, 20h
    jb NotPrintable

    cmp dl, 7Eh
    ja NotPrintable


    ; Printable
    mov al, dl
    call WriteChar

    jmp NextASCII


NotPrintable:

    mov al, '.'
    call WriteChar


NextASCII:

    inc esi
    dec eax

    jmp ASCII_Loop


    ; --------------------------------
    ; จบบรรทัด
    ; --------------------------------
EndLine:

    call Crlf

    ; --------------------------------
    ; Address เพิ่มตามจำนวน byte
    ; --------------------------------
    add ebx, ebp

    jmp NextLine


DumpDone:

    popad
    ret

DisplayHexDump ENDP