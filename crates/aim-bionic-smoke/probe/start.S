/* Entry for the generated libbinder probe. argc is on the stack.
 * exit_group (94) so a returned main does not leave binder threads. */
.global _start
_start:
    ldr x0, [sp]
    add x1, sp, #8
    bl main
    mov x8, #94
    svc #0
