DES_KEY_BYTES       EQU 8
DES_SUBKEY_BYTES    EQU 6
DES_ROUNDS          EQU 16
DES_SCHEDULE_BYTES  EQU (DES_SUBKEY_BYTES * DES_ROUNDS)

; Input key format:
;   Eight bytes in DES/FIPS display order (most-significant byte first).
; Output schedule format:
;   Six bytes per subkey, K1 through K16, most-significant byte first.
GenerateDESSubkeys PROTO STDCALL :PTR BYTE, :PTR BYTE
ValidateDESOddParity PROTO STDCALL :PTR BYTE

