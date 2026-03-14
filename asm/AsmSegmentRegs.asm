; asmSegmentRegs.asm
; segment register accessors — zero windows API dependency

PUBLIC asm_get_cs
PUBLIC asm_get_ds
PUBLIC asm_get_es
PUBLIC asm_get_ss
PUBLIC asm_get_fs
PUBLIC asm_get_gs
PUBLIC asm_get_ldtr
PUBLIC asm_get_tr
PUBLIC asm_get_gdt_base
PUBLIC asm_get_idt_base
PUBLIC asm_get_gdt_limit
PUBLIC asm_get_idt_limit
PUBLIC asm_set_ds
PUBLIC asm_set_es
PUBLIC asm_set_ss
PUBLIC asm_set_fs

.code _text


asm_get_gdt_base PROC
    LOCAL   gdtr[10]:BYTE
    sgdt    gdtr
    mov     rax, QWORD PTR gdtr[2]
    ret
asm_get_gdt_base ENDP


asm_get_idt_base PROC
    LOCAL   idtr[10]:BYTE
    sidt    idtr
    mov     rax, QWORD PTR idtr[2]
    ret
asm_get_idt_base ENDP


asm_get_gdt_limit PROC
    LOCAL   gdtr[10]:BYTE
    sgdt    gdtr
    mov     ax, WORD PTR gdtr[0]
    ret
asm_get_gdt_limit ENDP


asm_get_idt_limit PROC
    LOCAL   idtr[10]:BYTE
    sidt    idtr
    mov     ax, WORD PTR idtr[0]
    ret
asm_get_idt_limit ENDP


asm_get_cs PROC
    mov     rax, cs
    ret
asm_get_cs ENDP


asm_get_ds PROC
    mov     rax, ds
    ret
asm_get_ds ENDP


asm_set_ds PROC
    mov     ds, cx
    ret
asm_set_ds ENDP


asm_get_es PROC
    mov     rax, es
    ret
asm_get_es ENDP


asm_set_es PROC
    mov     es, cx
    ret
asm_set_es ENDP


asm_get_ss PROC
    mov     rax, ss
    ret
asm_get_ss ENDP


asm_set_ss PROC
    mov     ss, cx
    ret
asm_set_ss ENDP


asm_get_fs PROC
    mov     rax, fs
    ret
asm_get_fs ENDP


asm_set_fs PROC
    mov     fs, cx
    ret
asm_set_fs ENDP


asm_get_gs PROC
    mov     rax, gs
    ret
asm_get_gs ENDP


asm_get_ldtr PROC
    sldt    rax
    ret
asm_get_ldtr ENDP


asm_get_tr PROC
    str     rax
    ret
asm_get_tr ENDP


END
