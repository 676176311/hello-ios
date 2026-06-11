/*
 * CSOpsBypass.dylib — MobileSubstrate tweak
 * Hooks csops() system-wide, forces flags=0x0 when ops=CS_OPS_STATUS(0).
 * Injected by MobileSubstrate when HelloApp launches → csops returns "clean".
 */
#include "fishhook.h"
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

/* Prototype */
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

static int (*original_csops)(pid_t, unsigned int, void *, size_t) = NULL;

static int hooked_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
    /* Call original first — let the real csops run */
    int ret = original_csops(pid, ops, useraddr, usersize);

    /* Only intercept ops=0 (CS_OPS_STATUS) and valid useraddr */
    if (ops == 0 && ret == 0 && useraddr && usersize >= sizeof(unsigned int)) {
        /* Overwrite flags to 0x0 — no get-task-allow, no suspicious flags */
        *(unsigned int *)useraddr = 0x0;
    }

    return ret;
}

__attribute__((constructor))
static void init_bypass(void)
{
    fprintf(stderr, "[CSOpsBypass] Loading...\n");

    struct rebinding rebind = { "csops", (void *)hooked_csops, (void **)&original_csops };
    rebind_symbols(&rebind, 1);

    fprintf(stderr, "[CSOpsBypass] csops hooked: original=%p\n", (void *)original_csops);
}
