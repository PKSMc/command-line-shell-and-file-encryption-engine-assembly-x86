; Official DES known-answer test from the assignment/FIPS reference.

.386
option casemap:none
option prologue:none
option epilogue:none

include Irvine32.inc
include des_key_schedule.inc
include module_C.inc

.data
TestKey BYTE 13h,34h,57h,79h,9Bh,0BCh,0DFh,0F1h
TestPlaintext BYTE 01h,23h,45h,67h,89h,0ABh,0CDh,0EFh
TestExpected BYTE 85h,0E8h,13h,54h,0Fh,0Ah,0B4h,05h
TestOutput BYTE 8 DUP(0)
TestRecovered BYTE 8 DUP(0)
TestSchedule BYTE DES_SCHEDULE_BYTES DUP(0)
PassText BYTE "DES NIST known-answer test: PASSED",0Dh,0Ah,0
FailText BYTE "DES NIST known-answer test: FAILED",0Dh,0Ah,0

.code

CompareEight PROC STDCALL pLeft:PTR BYTE,pRight:PTR BYTE
    push ebp
    mov  ebp,esp
    push ecx
    push esi
    push edi
    mov  esi,DWORD PTR [ebp+8]
    mov  edi,DWORD PTR [ebp+12]
    mov  ecx,8
compare_eight_loop:
    mov  al,BYTE PTR [esi]
    cmp  al,BYTE PTR [edi]
    jne  compare_eight_no
    inc  esi
    inc  edi
    dec  ecx
    jnz  compare_eight_loop
    mov  eax,1
    jmp  compare_eight_done
compare_eight_no:
    xor  eax,eax
compare_eight_done:
    pop  edi
    pop  esi
    pop  ecx
    mov  esp,ebp
    pop  ebp
    ret  8
CompareEight ENDP

main PROC
    push ebp
    mov  ebp,esp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push OFFSET TestSchedule
    push OFFSET TestKey
    call GenerateDESSubkeys
    test eax,eax
    jnz  selftest_fail
    push 0
    push OFFSET TestSchedule
    push OFFSET TestOutput
    push OFFSET TestPlaintext
    call DES_TransformBlock
    test eax,eax
    jnz  selftest_fail
    push OFFSET TestExpected
    push OFFSET TestOutput
    call CompareEight
    test eax,eax
    jz   selftest_fail
    push 1
    push OFFSET TestSchedule
    push OFFSET TestRecovered
    push OFFSET TestOutput
    call DES_TransformBlock
    test eax,eax
    jnz  selftest_fail
    push OFFSET TestPlaintext
    push OFFSET TestRecovered
    call CompareEight
    test eax,eax
    jz   selftest_fail
    mov  edx,OFFSET PassText
    call WriteString
    xor  ebx,ebx
    jmp  selftest_exit
selftest_fail:
    mov  edx,OFFSET FailText
    call WriteString
    mov  ebx,1
selftest_exit:
    mov  eax,ebx
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    mov  esp,ebp
    pop  ebp
    exit
main ENDP

END main
