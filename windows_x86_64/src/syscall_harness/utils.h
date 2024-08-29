#include <stdint.h>

#define SYSCALL_REG_ARGS 4

typedef struct {
    void* stack_addr;   // New stack pointer (can be NULL)
    uint64_t id;
    uint64_t args[4];
} SyscallContext;

uint64_t syscall(const SyscallContext* ctx) {
    uint64_t ret;
    asm volatile (
        // Save the original stack pointer in r12.
        "mov %%rsp, %%r12\n\t"

        // If the new stack pointer is not NULL, switch to it.
        "test %1, %1\n\t"
        "cmovnz %%rsp, %1\n\t"

        // Perform the system call.
        "syscall\n\t"

        // Restore the original stack pointer from r12.
        "mov %%r12, %%rsp\n\t"

        : "=a" (ret)                       // Output: the result of the syscall goes into ret (using rax)
        : "r"(ctx->stack_addr),            // Input: the new stack pointer, if provided (any general-purpose register)
          "a"(ctx->id),                    // Input: syscall ID (passed in rax)
          "D"(ctx->args[0]),               // Input: first argument (passed in rdi)
          "S"(ctx->args[1]),               // Input: second argument (passed in rsi)
          "d"(ctx->args[2]),               // Input: third argument (passed in rdx)
          "c"(ctx->args[3])                // Input: fourth argument (passed in rcx)
        : "r12", "r11", "r10", "r9",       // Clobbered registers
          "memory"                         // Indicate that memory is clobbered
    );

    return ret & 0xFFFFFFFF;
}
