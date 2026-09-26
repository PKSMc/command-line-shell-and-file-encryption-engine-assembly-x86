IFNDEF DISPLAY_HEX_DUMP_INC
DISPLAY_HEX_DUMP_INC EQU <1>

PrintHexByte   PROTO STDCALL :DWORD
DisplayHexDump PROTO STDCALL :PTR BYTE, :DWORD, :DWORD
; Shell preview: reads and displays at most the first 16 bytes of the file.
DisplayFileHexDump PROTO STDCALL :PTR BYTE

ENDIF
