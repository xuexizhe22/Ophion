; asmVmxContext.asm
; save/restore guest state around VMLAUNCH

PUBLIC asm_vmx_save_state
PUBLIC asm_vmx_restore_state

EXTERN vmx_virtualize_cpu:PROC

.code _text

; asm_vmx_save_state
; called per-core via DPC. saves all GP registers + RFLAGS, then calls
; vmx_virtualize_cpu(RSP). on successful VMLAUNCH, execution
; resumes at asm_vmx_restore_state (set as guest RIP in VMCS).

asm_vmx_save_state PROC

    push    0               ; Alignment padding (ensure 16-byte aligned stack)

    pushfq

    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    sub     rsp, 0100h      ; Shadow space + scratch area

    ;
    ; first argument (rcx) = current RSP = guestStack
    ; vmx_virtualize_cpu will store this as VMCS guest RSP
    ;
    mov     rcx, rsp
    call    vmx_virtualize_cpu

    ;
    ; if we reach here, VMLAUNCH failed (rax = FALSE)
    ; fall through to asm_vmx_restore_state to unwind the stack
    ;

    jmp     asm_vmx_restore_state

asm_vmx_save_state ENDP

; asm_vmx_restore_state
; guest RIP is set to this address in the VMCS. after a successful
; VMLAUNCH, the CPU "returns" here as if vmx_virtualize_cpu
; had returned normally.

asm_vmx_restore_state PROC

    add     rsp, 0100h      ; Remove shadow space

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax

    popfq

    add     rsp, 08h        ; Remove alignment padding

    ret                     ; Return to DPC routine (broadcast_virtualize_all)

asm_vmx_restore_state ENDP


END
