; asmCommon.asm
; common assembly routines — RFLAGS, GDT/IDT reload

PUBLIC asm_get_rflags
PUBLIC asm_reload_gdtr
PUBLIC asm_reload_idtr
PUBLIC asm_write_cr2

.code _text


asm_get_rflags PROC
    pushfq
    pop     rax
    ret
asm_get_rflags ENDP

; asm_reload_gdtr (PVOID gdtBase /*rcx*/, UINT32 gdtLimit /*edx*/)

asm_reload_gdtr PROC
    push    rcx
    shl     rdx, 48
    push    rdx
    lgdt    fword ptr [rsp+6]
    pop     rax
    pop     rax
    ret
asm_reload_gdtr ENDP

; asm_reload_idtr (PVOID idtBase /*rcx*/, UINT32 idtLimit /*edx*/)

asm_reload_idtr PROC
    push    rcx
    shl     rdx, 48
    push    rdx
    lidt    fword ptr [rsp+6]
    pop     rax
    pop     rax
    ret
asm_reload_idtr ENDP

; asm_write_cr2 (UINT64 value /*rcx*/)
; MSVC does not provide __writecr2 — we implement it in assembly.

asm_write_cr2 PROC
    mov     cr2, rcx
    ret
asm_write_cr2 ENDP


END
