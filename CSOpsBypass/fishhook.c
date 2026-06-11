/*
 * fishhook.c — ARM64-only symbol rebinding for iOS
 * Simplified: directly iterates section arrays without pointer math.
 */
#include "fishhook.h"
#include <string.h>
#include <stdlib.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static void _find_linkedit_and_symtab(struct mach_header_64 *header,
                                       uint8_t **linkedit_base,
                                       struct symtab_command **symtab,
                                       struct dysymtab_command **dysymtab)
{
    struct segment_command_64 *linkedit_seg = NULL;
    uint8_t *ptr = (uint8_t *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        switch (lc->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__LINKEDIT") == 0)
                linkedit_seg = seg;
            break;
        }
        case LC_SYMTAB:
            *symtab = (struct symtab_command *)lc;
            break;
        case LC_DYSYMTAB:
            *dysymtab = (struct dysymtab_command *)lc;
            break;
        }
        ptr += lc->cmdsize;
    }

    if (!linkedit_seg || !*symtab || !*dysymtab) {
        *linkedit_base = NULL;
        return;
    }

    *linkedit_base = (uint8_t *)((uint64_t)linkedit_seg->vmaddr - linkedit_seg->fileoff);
}

static void _rebind_section(struct rebindings_entry *entry,
                             struct mach_header_64 *header,
                             intptr_t slide,
                             uint8_t *linkedit_base,
                             struct symtab_command *symtab_cmd,
                             struct dysymtab_command *dysymtab_cmd,
                             const char *sectname)
{
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    uint8_t *ptr = (uint8_t *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sects = (struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++) {
                struct section_64 *s = &sects[j];
                if (strcmp(s->sectname, sectname) != 0) continue;
                if (strcmp(s->segname, "__DATA") != 0) continue;

                // Found the right section — walk indirect symbol table
                uint32_t *indirect = indirect_symtab + s->reserved1;
                uint64_t nslots = s->size / sizeof(void *);
                void **slot_base = (void **)((uint8_t *)header + s->addr - (uint64_t)header + slide);

                for (uint64_t k = 0; k < nslots; k++) {
                    uint32_t symidx = indirect[k];
                    if (symidx == INDIRECT_SYMBOL_ABS || symidx == INDIRECT_SYMBOL_LOCAL)
                        continue;
                    char *name = strtab + symtab[symidx].n_un.n_strx;
                    for (size_t r = 0; r < entry->rebindings_nel; r++) {
                        if (strcmp(name, entry->rebindings[r].name) == 0) {
                            if (entry->rebindings[r].replaced)
                                *entry->rebindings[r].replaced = slot_base[k];
                            slot_base[k] = entry->rebindings[r].replacement;
                        }
                    }
                }
            }
        }
        ptr += lc->cmdsize;
    }
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel)
{
    struct rebindings_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) return -1;

    entry->rebindings = calloc(rebindings_nel, sizeof(struct rebinding));
    if (!entry->rebindings) { free(entry); return -1; }
    memcpy(entry->rebindings, rebindings, rebindings_nel * sizeof(struct rebinding));
    entry->rebindings_nel = rebindings_nel;
    entry->next = _rebindings_head;
    _rebindings_head = entry;

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr->magic != MH_MAGIC_64) continue;

        struct mach_header_64 *h64 = (struct mach_header_64 *)hdr;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        uint8_t *linkedit_base = NULL;
        struct symtab_command *symtab_cmd = NULL;
        struct dysymtab_command *dysymtab_cmd = NULL;
        _find_linkedit_and_symtab(h64, &linkedit_base, &symtab_cmd, &dysymtab_cmd);
        if (!linkedit_base) continue;

        _rebind_section(entry, h64, slide, linkedit_base,
                        symtab_cmd, dysymtab_cmd, "__la_symbol_ptr");
        _rebind_section(entry, h64, slide, linkedit_base,
                        symtab_cmd, dysymtab_cmd, "__nl_symbol_ptr");
    }

    return 0;
}
