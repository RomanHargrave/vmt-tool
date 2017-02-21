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

typedef uint64_t ptrwidth_t;

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
typedef void* vdump_FunctionPointer;

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

// type vdump_VMTInfo
typedef struct {
    /**
     * Symbol Name
     * NEVER LIVES IN ITS OWN BLOCK DON'T FREE
     * THANKS
     */
    char const* name;

    /** 
     * Offset in file for display purposes
     */
    ptrwidth_t offset;

    /**
     * Symbol Address (in memory)
     */
    union vdump_VTable_U const* table;

    /**
     * Symbol Size
     */
    uint64_t    size;
} vdump_VMTInfo;
// end


/***************************************************************************************************************
 * ELF Tricks                                                                                                  *                  
 ***************************************************************************************************************/

/**
 * Returns true when region+0 matches ELF_MAGIC
 */
static inline int const
vdump_CheckELFHeader(void* region)
{
    return memcmp(region, ELF_MAGIC, sizeof(ELF_MAGIC)) == 0;
}

/**
 * Helpers to compute a section pointer from the section index
 */

static inline Elf64_Shdr const*
vdump_Elf64_GetShdr(Elf64_Ehdr const* ehdr, Elf64_Xword idx)
{
    // XXX DON'T LISTEN TO THE COMPILER LEAVE THIS ALONE
    return ((ptrwidth_t) ehdr) + ehdr->e_shoff + idx * ehdr->e_shentsize;
}

static inline Elf32_Shdr const* 
vdump_Elf32_GetShdr(Elf32_Ehdr const* ehdr, Elf32_Word idx)
{
    // XXX DON'T LISTEN TO THE COMPILER LEAVE THIS ALONE
    return ((ptrwidth_t) ehdr) + ehdr->e_shoff + idx * ehdr->e_shentsize;
}


/***************************************************************************************************************
 * VMT Processing functions.                                                                                   *                  
 ***************************************************************************************************************/

/**
 * strstr shortcut, returns true if a string contains _ZTV
 */
static inline int
vdump_CheckSymbolVMT(char const* name)
{
    return strstr(name, "_ZTV") != NULL;
}

/**
 * Print VMT data to fd,
 * I wrote this while reading through the source code for dump-vtable, 
 * since I don't know anything about C++ compiler internals
 */
static void
vdump_PrintVMT(FILE* fd, vdump_VMTInfo const* vtable)
{

    uint64_t    vmt_baseOffset  = vtable->table->cat1.baseoffset;
    const char* vmt_typeInfo    = vtable->table->cat1.typeinfo;
    uint64_t*   vmt_functions   = vtable->table->cat1.virtualFuncs;
    size_t      vmt_fnCount     = vtable->size / sizeof(ptrdiff_t); 

    size_t      vmt_read_offset = 0;
    size_t      vmt_read_step   = sizeof(ptrdiff_t);

    fprintf(fd, "+%s\n",                    vtable->name);
    fprintf(fd, "   ... offset:  %lX\n",    vtable->offset);
    fprintf(fd, "   ... entries: %lu\n",    vmt_fnCount);

    // Offset reads below 
    fprintf(fd, "   +%04lX (??? (*)(...)) 0x%lX\n", vmt_read_offset, vmt_baseOffset);
    fprintf(fd, "   +%04lX typeinfo = %lX\n",       vmt_read_offset, vmt_typeInfo);

    ptrwidth_t fnPtrSize = sizeof(ptrdiff_t);
    for (size_t fnIndex = 0; fnIndex < vmt_fnCount; ++fnIndex)
    {
        vmt_read_offset += vmt_read_step;
        fprintf(fd, "   +%04lX (??? (*)(...)) 0x%lX\n", vmt_read_offset, vmt_functions[fnIndex]); 
    }
        
}

/***************************************************************************************************************
 * VMT Collectors.                                                                                             *                  
 * One is present for both 64- and 32-bit address lengths                                                      * 
 * I should try and merge more common logic, but I fear that would turn in to macro hell                       * 
 ***************************************************************************************************************/

static enum vdump_VMTCollectResult 
{
    VCR_OK = 0,
    VCR_NO_SYMBOLS,
    VCR_NO_TABLES
};

/**
 * 64-Bit Relocation Assistant
 */
static inline void const*
vdump_Elf64_ComputeRelocation(Elf64_Ehdr const* header, Elf64_Sym const* symbol)
{
    switch (symbol->st_shndx)
    {
        case SHN_UNDEF:
            printf("...vmt_Elf64_ComputeRelocation: Skiping external symbol\n");
            return NULL;
        case SHN_ABS:
            // In our case, the header will not reside at +0 in virtual address space
            // So offset ABS addresses from the headers correct position
            printf("...vmt_Elf64_ComputeRelocation: Applying reloffset to SHN_ABS symbol\n");
            return ((void const*) header) + symbol->st_value;
        default:
            printf("...vmt_Elf64_ComputeRelocation: st_shndx refers to section (+%X), applying section offset to symbol value\n", symbol->st_shndx);
            return ((void const*) header) + vdump_Elf64_GetShdr(header, symbol->st_shndx)->sh_offset + symbol->st_value;
    }
}

/**
 * 64-Bit VMT collector function
 *
 * Iterates through all named symbols and selects named symbols pointing to VMTs according 
 * to `vdump_CheckSymbolVMT`
 *
 * Parameters:
 *  * region    - pointer in to mapped region to examine, +0 should be the ELF header
 *  * vtables   - pass as uninitialized, on a return of VCR_OK it will be replaced with
 *                a pointer to an allocated array containing vdump_VMTInfo structs
 *
 * Return:
 *  * Any value from enum vdump_VMTCollectResult
 */
static enum vdump_VMTCollectResult
vdump_Elf64_CollectVMTs(void* const region, vdump_VMTInfo** const vtables)
{
    ptrwidth_t base = region;
    Elf64_Ehdr const* header = region;
    Elf64_Shdr const* sec_symtab;

    /**
     * Collect sections
     * Only SHT_SYMTAB is useful
     * SHT_DYNSYM never really contains anything noteworthy
     *
     * XXX I shouldn't fail, but could if the ELF header is corrupt (e_shnum <= 0)
     */
    for(Elf64_Xword _shn = 0; _shn < header->e_shnum; ++_shn)
    {
        Elf64_Shdr const* sectionHdr = vdump_Elf64_GetShdr(header, _shn);
        switch (sectionHdr->sh_type)
        {
            case SHT_SYMTAB:
                sec_symtab = sectionHdr; 
                break;
            default:
                break;
        }
    }
   
    // Process symbols 
    {
        size_t const entrySize = sizeof(Elf64_Sym);
        Elf64_Shdr const* symStrTab = base + header->e_shoff + (sec_symtab->sh_link * header->e_shentsize);
        Elf64_Xword const symCount = sec_symtab->sh_size / entrySize;

        // Branch, process if symbols present or exit with VCR_NO_SYMBOLS
        if (symCount > 0) 
        {
            vdump_VMTInfo* const _vtable_collection = calloc(symCount + 1, sizeof(vdump_VMTInfo));

            Elf64_Xword keptSymCount = 0; // Incremented for each symbol which is "kept"
            for (Elf64_Xword symIdx = 0; symIdx < symCount; ++symIdx)
            {
                Elf64_Sym const* sym = base + sec_symtab->sh_offset + (symIdx * sizeof(Elf64_Sym));

                // Validate symbol.
                if (sym->st_value == 0) continue;
                else if (sym->st_name  == 0) continue;

                char const* symName = base + symStrTab->sh_offset + sym->st_name;

                if (!vdump_CheckSymbolVMT(symName)) continue;

                vdump_VMTInfo* sdata = &_vtable_collection[keptSymCount++];
                sdata->name    = symName;
                sdata->offset  = sym->st_value;
                sdata->table   = vdump_Elf64_ComputeRelocation(header, sym);
                sdata->size    = sym->st_size;
            }
            
            // Branch: resize kept symbols (vtables) and assign address to vtables reference, or exit with VCR_NO_TABLES
            if (keptSymCount > 0)
            {
                // XXX keptSymCount will be <kept symbols> + 1 due to design. last element is a sigil to indicate EOD
                *vtables = realloc(_vtable_collection, keptSymCount * sizeof(vdump_VMTInfo));
                return VCR_OK;
            }
            else
            {
                free(_vtable_collection);
                return VCR_NO_TABLES;
            }
        }
        else
        {
            return VCR_NO_SYMBOLS;
        }
    }
}

/**
 * 32-Bit Relocation Assistant
 */
void const*
vdump_Elf32_ComputeRelocation(Elf32_Ehdr const* header, Elf32_Sym const* symbol)
{
    switch (symbol->st_shndx)
    {
        case SHN_UNDEF:
            return NULL;
        case SHN_ABS:
            return ((void const*) header) + symbol->st_value;
        default:
            return ((void const*) header) + vdump_Elf32_GetShdr(header, symbol->st_shndx)->sh_offset + symbol->st_value;
    }
}

/**
 * 32-bit variant of above
 * See 64-bit variant for documentation
 */
static enum vdump_VMTCollectResult
vdump_Elf32_CollectVMTs(void* region, vdump_VMTInfo** vtables)
{
#if 0
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

    vdump_VMTInfo* symbolData = NULL;
    {
        size_t const entrySize = sizeof(Elf32_Sym);
        Elf32_Shdr const* symStrTab = region + header->e_shoff + (sec_symtab->sh_link * header->e_shentsize);
        Elf32_Word const symCount = sec_symtab->sh_size / entrySize;

        symbolData = calloc(symCount + 1, sizeof(vdump_VMTInfo));

        Elf32_Word keptSymCount = 0;
        for (Elf32_Word symIdx = 0; symIdx < symCount; ++symIdx)
        {
            Elf32_Sym* sym = region + sec_symtab->sh_offset + (symIdx * entrySize);

            if (sym->st_value == 0) continue;
            else if (sym->st_name == 0) continue;

            char const* symName = region + symStrTab->sh_offset + sym->st_name;

            if (!vdump_CheckSymbolVMT(symName)) continue;

            vdump_VMTInfo* sdata = &symbolData[keptSymCount++];
            sdata->name    = symName;
            sdata->address = vdump_Elf32_ComputeRelocation(header, sym);

        }

        symbolData = realloc(symbolData, keptSymCount * sizeof(vdump_Elf_SymbolInfo));
    }


    return symbolData;
#else 
    return VCR_NO_TABLES;
#endif
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
    char* fname = *argv;
    {
        
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

    if (vdump_CheckELFHeader(region))
    {
        uint8_t e_class = *((uint8_t*)(region + EI_CLASS));

        // Collect VMT symbols 
        vdump_VMTInfo* tables = NULL; 
        {
            enum vdump_VMTCollectResult collect_result = VCR_NO_TABLES;
            if (e_class == ELFCLASS32)
            {
                collect_result = vdump_Elf32_CollectVMTs(region, &tables);
            }
            else if (e_class == ELFCLASS64)
            {
                collect_result = vdump_Elf64_CollectVMTs(region, &tables);
            }

            switch (collect_result)
            {
                case VCR_NO_SYMBOLS:
                    fprintf(stderr, "Couldn't find any symbols in %s\n", fname);
                    return 5; // EIO
                case VCR_NO_TABLES:
                    fprintf(stderr, "Couldn't find any vtables in %s\n", fname);
                    return 5; // EIO
                default:
                    break;
            }
        }

        // Iterate thru and parse VMTs

        if (tables) // should be assigned, but why not 
        {
            size_t idx = 0;
            do 
            {
                vdump_VMTInfo const symbol = tables[idx];
                if (!symbol.name) break;
        
                vdump_PrintVMT(stdout, &symbol);

                ++idx;
            }
            while (1);

            free(tables);
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
