/*
 * fishhook.c — ARM64-only symbol rebinding for iOS
 * Walks Mach-O __DATA,__la_symbol_ptr and __DATA,__nl_symbol_ptr to replace imports.
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

static void _perform_rebinding_with_section(struct rebindings_entry *entry,
                                            struct mach_header_64 *header,
                                            intptr_t slide,
                                            const char *sectname)
{
    uint8_t *linkedit_base = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    struct segment_command_64 *linkedit_seg = NULL;

    /* Walk load commands to find LINKEDIT, SYMTAB, DYSYMTAB */
    struct load_command *cmd = (struct load_command *)((uint8_t *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                linkedit_seg = seg;
            }
        } else if (cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cmd;
        } else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cmd;
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
    }

    if (!linkedit_seg || !symtab_cmd || !dysymtab_cmd) return;

    /* Base of LINKEDIT */
    uint64_t vmaddr_slide = linkedit_seg->vmaddr - linkedit_seg->fileoff;
    linkedit_base = (uint8_t *)vmaddr_slide;

    /* Symbol and string tables */
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    /* Find the section */
    cmd = (struct load_command *)((uint8_t *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            struct section_64 *sect = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (strcmp(sect[j].sectname, sectname) == 0 &&
                    strcmp(sect[j].segname, "__DATA") == 0) {
                    /* Found the section — walk its indirect symbol entries */
                    uint32_t *indirect = indirect_symtab + sect[j].reserved1;
                    void **slot = (void **)((uint8_t *)header + sect[j].addr - (uint64_t)header + slide);
                    for (uint64_t k = 0; k < sect[j].size / sizeof(void *); k++) {
                        uint32_t symidx = indirect[k];
                        if (symidx == INDIRECT_SYMBOL_ABS || symidx == INDIRECT_SYMBOL_LOCAL)
                            continue;
                        char *symname = strtab + symtab[symidx].n_un.n_strx;

                        for (size_t r = 0; r < entry->rebindings_nel; r++) {
                            if (strcmp(symname, entry->rebindings[r].name) == 0) {
                                if (entry->rebindings[r].replaced) {
                                    *entry->rebindings[r].replaced = slot[k];
                                }
                                slot[k] = entry->rebindings[r].replacement;
                            }
                        }
                    }
                }
                sect += sect[j].nsects;
            }
        }
        cmd = (struct load_command *)((uint8_t *)cmd + cmd->cmdsize);
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

    /* Rebind in current image and all loaded images */
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (hdr->magic == MH_MAGIC_64) {
            _perform_rebinding_with_section(entry, (struct mach_header_64 *)hdr, slide,
                                            "__la_symbol_ptr");
            _perform_rebinding_with_section(entry, (struct mach_header_64 *)hdr, slide,
                                            "__nl_symbol_ptr");
        }
    }
    return 0;
}
