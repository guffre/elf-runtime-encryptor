#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>     // for Dl_info, dladdr()
#include <unistd.h>    // for sysconf(), _SC_PAGESIZE
#include <sys/mman.h>  // for mprotect()


#ifdef DEBUG
    #define dprintf(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)
#else
    #define dprintf(fmt, ...)  // No-op if DEBUG is not defined
#endif


struct enc_region {
    uintptr_t start;
    uintptr_t end;
    uintptr_t faddr;
    unsigned char key;
};

// The enc_table gets filled in after compilation.
struct enc_region enc_table[512] = {{0xdead,0xbeef,0xcafebabe,0x78}};
uintptr_t base_address;

__attribute__((no_instrument_function))
void make_page_rwx(void *addr, size_t len, uint8_t rwx_or_rx) {
    size_t pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)addr & ~(pagesize - 1);
    size_t size = ((uintptr_t)addr + len) - page_start;
    size = (size + pagesize - 1) & ~(pagesize - 1);

    int prot = rwx_or_rx ? PROT_READ | PROT_WRITE | PROT_EXEC : PROT_READ | PROT_EXEC;

    if (mprotect((void*)page_start, size, prot) != 0) {
        perror("mprotect");
    }
}

__attribute__((constructor))
__attribute__((no_instrument_function))
void get_base_address(void) {
    Dl_info info;
    if (dladdr((void*)get_base_address, &info) == 0)
        return;

    base_address = (uintptr_t)info.dli_fbase;
}

__attribute__((no_instrument_function))
// __attribute__((optimize("O0")))
void __cyg_profile_func_enter(void *this_fn, void *call_site) {
    (void)call_site;
    dprintf("Enter: %p called from %p\n", this_fn, call_site);
    struct enc_region *tmp = NULL;
    uintptr_t base = base_address;
    uintptr_t addr = (uintptr_t)this_fn;
    // dprintf("load address: %p\n", base); fflush(stdout);
    // dprintf("enc_table first entry: %lx\n", enc_table[0].key); fflush(stdout);
    for (tmp = enc_table; tmp->start; ++tmp) {
        // dprintf("enc_table entry start - addr - end - faddr: %lx - %lx - %lx - %lx\n", base+tmp->start, addr, base+tmp->end, base+tmp->faddr);
        if (addr == base+tmp->faddr) {
            // dprintf("got match!\n"); fflush(stdout);
            make_page_rwx((void*)(base+tmp->start), tmp->end - tmp->start, 1);
            unsigned char *p = base+(unsigned char*)tmp->start;
            dprintf("decrypting memory at addr: %lx\n", (uintptr_t)p);

            for (; (uintptr_t)p < base+tmp->end; ++p) {
                // dprintf("xor start.\n"); fflush(stdout);
                *p ^= tmp->key;
                // dprintf("xor end.\n"); fflush(stdout);
                
            }
            make_page_rwx((void*)(base+tmp->start), tmp->end - tmp->start, 0);
            break;
        }
    }
    dprintf("done with entry.\n"); fflush(stdout);
}

__attribute__((no_instrument_function))
// __attribute__((optimize("O0")))
void __cyg_profile_func_exit(void *this_fn, void *call_site) {
    (void)call_site;
    uintptr_t base = base_address;
    dprintf("Exit: %p called from %p\n", this_fn, call_site);
    struct enc_region *tmp = NULL;
    uintptr_t addr = (uintptr_t)this_fn;
    for (tmp = enc_table; tmp->start; ++tmp) {
        dprintf("addr: %lx, menu item: %lx\n", addr, base+tmp->faddr);
        if (addr == base+tmp->faddr) {
            unsigned char *p = (unsigned char*)base+tmp->start;
            dprintf("Encrypting memory at addr: %lx\n", (uintptr_t)p);
            make_page_rwx((void*)(base+tmp->start), tmp->end - tmp->start, 1);
            for (; (uintptr_t)p < base+tmp->end; ++p) {
                *p ^= tmp->key;
            }
            make_page_rwx((void*)(base+tmp->start), tmp->end - tmp->start, 0);
            break;
        }
    }
}