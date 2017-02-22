#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <elf_sym.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>

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
vdump_PrintVMT(FILE* fd, ESym_Handle* handle, ESym_Symbol* symbol)
{
    union vdump_VTable_U* table = (union vdump_VTable_U*) symbol->destination;

    fprintf(stderr, "table %p\n", table);

    uint64_t    vmt_baseOffset  = table->cat1.baseoffset;
    const char* vmt_typeInfo    = table->cat1.typeinfo;
    uint64_t*   vmt_functions   = (uint64_t*) table->cat1.virtualFuncs;
    size_t      vmt_fnCount     = symbol->size / sizeof(ptrdiff_t); 

    size_t      vmt_read_offset = 0;
    size_t      vmt_read_step   = sizeof(ptrdiff_t);

    fprintf(fd, "+%s\n",                    symbol->name);
    fprintf(fd, "   ... offset:  %lX\n",    symbol->definition);
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

    if (ESym_ValidateELF(region))
    {
        ESym_Handle* handle = ESym_LoadObject(region);

        // Iterate thru and parse VMTs

        if (handle)
        {
            _macro_ESym_ForEachSymbol(handle->symbols, sym)
            {
                if (vdump_CheckSymbolVMT(sym->name))
                {
                    vdump_PrintVMT(stdout, handle, sym);
                }
            }
        }
        else
        {
            fprintf(stderr, "Unable to load symbols from file\n");
        }

        /* if (tables) // should be assigned, but why not  */
        /* { */
        /*     size_t idx = 0; */
        /*     do  */
        /*     { */
        /*         vdump_VMTInfo const symbol = tables[idx]; */
        /*         if (!symbol.name) break; */
        /*  */
        /*         vdump_PrintVMT(stdout, &symbol); */
        /*  */
        /*         ++idx; */
        /*     } */
        /*     while (1); */
        /*  */
        /*     free(tables); */
        /* } */

    }
    else
    {
        fprintf(stderr, "Invalid ELF File\n");
    }

    munmap(region, region_size);
    close(fd);

    return 0;
}
