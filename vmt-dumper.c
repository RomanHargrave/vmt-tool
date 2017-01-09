#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

// ELF Header (0x7F E L F)
const uint8_t ELF_MAGIC[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

#define vdump_New(x)        ((x*)  malloc(sizeof(void*)))

enum vdump_ElfWidth {
    EW_32,
    EW_64
};

/**
 * Distilled information about an ELF symbol
 */
typedef struct {
    char const* name;
    void const* address;

    enum vdump_ElfWidth width;
    union {
        Elf32_Word  size32;
        Elf64_Xword size64;
    };
} vdump_Elf_SymbolInfo;

static inline uint64_t const
vdump_Elf_SymbolInfo_get_size(vdump_Elf_SymbolInfo* sym)
{
    // compiler pls convert thx
    switch (sym->width)
    {
        case EW_32: return sym->size32;
        case EW_64: return sym->size64;
    }
}

/***************************************************************************************************************
 * VMT Information Structures and Utility Functions                                                            *                  
 ***************************************************************************************************************/

// type vdump_FunctionPointer
#if defined(__ia64__) // Disclaimer: not tested on itanium
typedef struct {
    void* function;
    void* gpoffset;
} vdump_FunctionPointer;
#else
typedef void* vdump_FunctionPointer;
#endif
// end 

// NOTE Ripped from vtable-dumper
// type vdump_VTable_C1
// type vdump_VTable_C2
// type vdump_VTable_U
struct vdump_VTable_C1 {
    uint64_t                baseoffset;
    const char*             typeinfo;
    vdump_FunctionPointer   virtualFuncs[0];
};

struct vdump_VTable_C2 {
    uint64_t                vcalloffset;
    uint64_t                baseoffset;
    const char*             typeinfo;
    vdump_FunctionPointer   virtualFuncs[0];
};

union vdump_VTable_U {
    struct vdump_VTable_C1 const cat1;
    struct vdump_VTable_C2 const cat2;
};
// end 

// type vdump_VTableInfo
typedef struct {
    /**
     * Symbol Name
     * NEVER LIVES IN ITS OWN BLOCK DON'T FREE
     * THANKS
     */
    char const* name;

    /**
     * Symbol Address (in memory)
     */
    union vdump_VTable_U const* address;

    /**
     * Symbol Size
     */
    uint64_t    size;
} vdump_VTableInfo;
// end

/**
 * Returns true when region+0 matches ELF_MAGIC
 */
static inline int const
vdump_validate_elf(void* region)
{
    return memcmp(region, ELF_MAGIC, sizeof(ELF_MAGIC)) == 0;
}

/**
 * Returns pointer to the ELFClass magic
 */
static inline uint8_t const /* needs more classifiers */
vdump_read_elf_class(void* region)
{
    return *(((uint8_t*) region) + EI_CLASS);
}

/***************************************************************************************************************
 * VMT Processing functions.                                                                                   *                  
 ***************************************************************************************************************/

static inline int
vdump_symbol_is_vtable(char const* name)
{
    return strstr(name, "_ZTV") != NULL;
}

static vdump_VTableInfo*
vdump_Symbol_to_VTableInfo(vdump_Elf_SymbolInfo* sym)
{
    vdump_VTableInfo* vmt = vdump_New(vdump_VTableInfo);
    vmt->name = sym->name;
    vmt->size = vdump_Elf_SymbolInfo_get_size(sym);
    
    return vmt;
}

static void
vdump_print_vtable(vdump_VTableInfo const* vtable)
{

}

/***************************************************************************************************************
 * VMT Collectors.                                                                                             *                  
 * One is present for both 64- and 32-bit address lengths                                                      * 
 * I should try and merge more common logic, but I fear that would turn in to macro hell                       * 
 ***************************************************************************************************************/

/**
 * 64-Bit VMT collector function
 *
 * Iterates through all named symbols and selects named symbols pointing to VMTs according 
 * to `vdump_symbol_is_vtable`
 */
static vdump_VTableInfo*
vdump_Elf64_collect_vmts(void* const region)
{
    Elf64_Ehdr const* header = region;
    Elf64_Shdr const* sec_symtab;

    /**
     * Collect sections
     * Only SHT_SYMTAB is useful
     * SHT_DYNSYM never really contains anything noteworthy
     */
    for(uint16_t _sh = 0; _sh < header->e_shnum; ++_sh)
    {
        size_t const offset = header->e_shoff + _sh * header->e_shentsize;
        Elf64_Shdr const* sectionHdr = region + offset;

        switch (sectionHdr->sh_type)
        {
            case SHT_SYMTAB:
                sec_symtab = sectionHdr; 
                break;
            default:
                break;
        }
    }
    
    /*
     * Read symbols and collect VMTs in to symbolData, terminates symbolData with a symbol 
     * that has a name pointer to zero.
     */
    vdump_VTableInfo* symbolData = NULL;
    {
        size_t const entrySize = sizeof(Elf64_Sym);
        Elf64_Shdr const* symStrTab = region + header->e_shoff + (sec_symtab->sh_link * header->e_shentsize);
        Elf64_Xword const symCount = sec_symtab->sh_size / entrySize;

        symbolData = calloc(symCount + 1, sizeof(vdump_VTableInfo));

        Elf64_Xword keptSymCount = 0; // Incremented for each symbol which is "kept"
        for (Elf64_Xword symIdx = 0; symIdx < symCount; ++symIdx)
        {
            Elf64_Sym const* sym = region + sec_symtab->sh_offset + (symIdx * sizeof(Elf64_Sym));

            // Validate symbol.
            if (sym->st_value == 0) continue;
            else if (sym->st_name  == 0) continue;

            char const* symName = region + symStrTab->sh_offset + sym->st_name;

            if (!vdump_symbol_is_vtable(symName)) continue;

            vdump_VTableInfo* sdata = &symbolData[keptSymCount++];
            sdata->name    = symName;
            sdata->address = region + sym->st_value;
            sdata->size    = sym->st_size;

            {
                uint8_t const _st_bind = ELF64_ST_BIND(sym->st_info);
                uint8_t const _st_type = ELF64_ST_TYPE(sym->st_info);
                printf("sym (%p + %x) { .st_info = %X, .st_shndx = %04X } %s\n",
                        region, sym->st_value, 
                        sym->st_info, 
                        sym->st_shndx,
                        symName);
            }
        }
        
        symbolData = realloc(symbolData, keptSymCount * sizeof(vdump_VTableInfo));
    }

    return symbolData;
}

/**
 * 32-bit variant of above
 * See 64-bit variant for documentation
 */
static vdump_VTableInfo* 
vdump_Elf32_collect_vmts(void* region)
{
    Elf32_Ehdr const* header = region;
    Elf32_Shdr const* sec_symtab;

    for(uint16_t _sh = 0; _sh < header->e_shnum; ++_sh)
    {
        size_t const offset = header->e_shoff + _sh * header->e_shentsize;
        Elf32_Shdr const* sectionHdr = region + offset;
        
        switch (sectionHdr->sh_type)
        {
            case SHT_SYMTAB:
                sec_symtab = sectionHdr;
                break;
            default:
                break;
        }
    }

    vdump_VTableInfo* symbolData = NULL;
    {
        size_t const entrySize = sizeof(Elf32_Sym);
        Elf32_Shdr const* symStrTab = region + header->e_shoff + (sec_symtab->sh_link * header->e_shentsize);
        Elf32_Word const symCount = sec_symtab->sh_size / entrySize;

        symbolData = calloc(symCount + 1, sizeof(vdump_VTableInfo));

        Elf32_Word keptSymCount = 0;
        for (Elf32_Word symIdx = 0; symIdx < symCount; ++symIdx)
        {
            Elf32_Sym* sym = region + sec_symtab->sh_offset + (symIdx * entrySize);

            if (sym->st_value == 0) continue;
            else if (sym->st_name == 0) continue;

            char const* symName = region + symStrTab->sh_offset + sym->st_name;

            if (!vdump_symbol_is_vtable(symName)) continue;

            vdump_VTableInfo* sdata = &symbolData[keptSymCount++];
            sdata->name    = symName;
            sdata->address = region + sym->st_value;
            sdata->size    = sym->st_size;
        }

        symbolData = realloc(symbolData, keptSymCount * sizeof(vdump_Elf_SymbolInfo));
    }

    return symbolData;
}

/***************************************************************************************************************
 * Runtime logic                                                                                               *                  
 ***************************************************************************************************************/

int
main (int argc, char** argv)
{
    ++argv; 
    if (argc < 1)
    {
        fprintf(stderr, "Expected a file name\n");
    }

    int fd;
    void* region;
    size_t region_size;
    {
        char* fname = *argv;
        
        // Open fd for file 
        fd = open(fname, 0);
        if (fd == -1)
        {
            perror("");
            fprintf(stderr, "Could not open file %s\n", fname);
            return errno;
        }

        // Get file size
        {
            struct stat _stat;
            if (fstat(fd, &_stat) == -1)
            {
                perror("Could not stat file\n");
                return errno;
            }

            region_size = _stat.st_size;
        }

        region = mmap(NULL, region_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (region == MAP_FAILED)
        {
            perror("Could not mmap file\n");
            return errno;
        }
    }

    // Read information about ELF file
    // ELF uses different structures and types depending on address width
    // Before we can begin processing the file, we need to determine the 
    // ELF class

    if (vdump_validate_elf(region))
    {
        uint8_t e_class = vdump_read_elf_class(region);
        vdump_VTableInfo* symData = NULL; 

        // Collect VMT symbols 

        if (e_class == ELFCLASS32)
        {
            symData = vdump_Elf32_collect_vmts(region);
        }
        else if (e_class == ELFCLASS64)
        {
            symData = vdump_Elf64_collect_vmts(region);
        }

        // Iterate thru and parse VMTs

        if (symData)
        {
            vdump_VTableInfo const* symbol = symData;

            do 
            {
                symbol += sizeof(vdump_VTableInfo);
                if (!symbol->name) break;

                struct vdump_VTable_C1 const* c1 = &symbol->address->cat1;
                struct vdump_VTable_C2 const* c2 = &symbol->address->cat2;
              
                size_t const step = sizeof(ptrdiff_t);
                size_t const count = symbol->size / step;

                /* printf("%p [size = %lu, count = %lu] (baseoffset = %X) %s\n", */
                /*         symbol->address, */
                /*         symbol->size,  */
                /*         count, */
                /*         c1->baseoffset, */
                /*         symbol->name); */
            }
            while (1);

            free(symData);
        }

    }
    else
    {
        fprintf(stderr, "Invalid ELF File\n");
    }

    munmap(region, region_size);
    close(fd);

    return 0;
}
