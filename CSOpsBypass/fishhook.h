/*
 * fishhook - Facebook's Mach-O symbol rebinding, MIT license
 * Minimal version for ARM64 iOS: rebind_symbols only
 */
#ifndef FISHHOOK_H
#define FISHHOOK_H

#include <stddef.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif
