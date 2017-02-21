#include <stdlib.h>
#include <elf_sym.h>
#include <gchashmap/hashmap.h>

#include <stdio.h>

// Handle destructor

void
ESym_Handle_Destroy(ESym_Handle* toDestroy)
{
    free(toDestroy->symbols);
    
    ESym_Map_NameToSymbolDestroy(toDestroy->byName);
    free(toDestroy->byName);
    ESym_Map_AddrToSymbolDestroy(toDestroy->byAddr);
    free(toDestroy->byAddr);

    free(toDestroy);
}

// Implementation for Symbol->Address map
// XXX note about naive comparators -- we expect 1:1 for everything because that's all I've ever seen, and this hashmap isn't what I want exactly, but I'll deal with it when it becomes a problem.
static inline int
_ESym_Map_SymbolCmp_Name(ESym_Symbol* a, ESym_Symbol* b)
{
    return strcmp(a->name, b->name);
}

static inline int 
_ESym_Map_SymbolCmp_Addr(ESym_Symbol* a, ESym_Symbol* b)
{
    return (a->destination == b->destination) ? 0 : 1;
}

static inline uint64_t 
_ESym_Map_NameToSymbol_HashFN(ESym_Symbol* sym)
{
    return ESym_StringHash(sym->name);
}

DECLARE_HASHMAP(ESym_Map_NameToSymbol, _ESym_Map_SymbolCmp_Name, _ESym_Map_NameToSymbol_HashFN, free, realloc);

// Implementation for Address->Symbol map

static inline uint64_t
_ESym_Map_AddrToSymbol_HashFN(ESym_Symbol* sym)
{
    return (uint64_t) sym->destination;
}

DECLARE_HASHMAP(ESym_Map_AddrToSymbol, _ESym_Map_SymbolCmp_Addr, _ESym_Map_AddrToSymbol_HashFN, free, realloc);

// Functionality Implementation

/*
 * ELF Validator 
 *
 * Checks for ELF magic at the beginning of region
 */
static uint8_t const ELF_MAGIC[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

int 
ESym_ValidateELF(void* region)
{
    return memcmp(region, ELF_MAGIC, sizeof(ELF_MAGIC)) == 0;
}


/*
 * GetShdr Implementation
 * "Get Section Header"
 *
 * Get the section header for the section at an index
 */

// XXX DON'T LISTEN TO THE COMPILER LEAVE THIS ALONE
#define _tpl_GetShdr(ehdr, idx) \
        (((ptrwidth_t) ehdr) + ehdr->e_shoff + idx * ehdr->e_shentsize)

Elf64_Shdr const*
ESym_GetShdr_64(Elf64_Ehdr const* ehdr, Elf64_Xword idx)
{
    return (Elf64_Shdr const*) _tpl_GetShdr(ehdr, idx);
}

Elf32_Shdr const*
ESym_GetShdr_32(Elf32_Ehdr const* ehdr, Elf32_Word idx)
{
    // XXX DON'T LISTEN TO THE COMPILER LEAVE THIS ALONE
    return (Elf32_Shdr const*) _tpl_GetShdr(ehdr, idx);
}

/*
 * ComputeOffset implementation
 */
#define _tpl_ComputeOffset(ehdr, sym, getshdr) \
    switch (sym->st_shndx) \
    { \
        case SHN_UNDEF: return NULL; \
        case SHN_ABS:   return (void const*)(((ptrwidth_t) ehdr) + sym->st_value); \
        default:        return (void const*)(((ptrwidth_t) ehdr) + getshdr(ehdr, sym->st_shndx)->sh_offset + sym->st_value); \
    }
                
void const*
ESym_ComputeOffset_64(Elf64_Ehdr const* ehdr, Elf64_Sym const* sym)
{
    _tpl_ComputeOffset(ehdr, sym, ESym_GetShdr_64);
}

void const*
ESym_ComputeOffset_32(Elf32_Ehdr const* ehdr, Elf32_Sym const* sym)
{
    _tpl_ComputeOffset(ehdr, sym, ESym_GetShdr_32);
}

/*
 * LoadObject implementation
 */

// Find section "name" in "ehdr" and store in "out" after absolutizing with "getshdr" function
#define _macro_FindSection(_width_, name, ehdr, out) \
{ \
    for (uint64_t _shn = 0; _shn < ehdr->e_shnum; ++_shn) \
    { \
        Elf##_width_##_Shdr const* section = ESym_GetShdr_##_width_(ehdr, _shn); \
        switch (section->sh_type) \
        { \
            case name: \
                out = section; \
                break; \
            default: break; \
        } \
    } \
}

#define _macro_AbsolutizeSymbol(_width_, ehdr, symtab, symno) \
    ((void const*) ((ptrwidth_t) ehdr) + symtab->sh_offset + (symno * sizeof(Elf##_width_##_Sym)))

#define _macro_AbsolutizeString(ehdr, strtab, nameidx) \
    ((char const*) ((ptrwidth_t) ehdr) + strtab->sh_offset + nameidx)

#define _tpl_LoadObject__ReadSymbols(_width_, esym_array, ehdr, symtab, strtab) \
{ \
    size_t const entrySize = sizeof(Elf##_width_##_Sym); \
    uint64_t const symCount = symtab->sh_size / entrySize; \
    \
    if (symCount > 0) \
    { \
        esym_array = calloc(symCount + 1, sizeof(ESym_Symbol)); \
        \
        uint64_t keptSymCount = 0; \
        for (uint64_t symIdx = 0; symIdx < symCount; ++symIdx) \
        { \
            Elf##_width_##_Sym const* sym = _macro_AbsolutizeSymbol(_width_, ehdr, symtab, symIdx); \
            \
            if      (sym->st_value == 0)    continue; \
            else if (sym->st_name == 0)     continue; \
            \
            ESym_Symbol* abstrSym = &esym_array[keptSymCount++]; \
            abstrSym->name          = _macro_AbsolutizeString(ehdr, strtab, sym->st_name); \
            abstrSym->definition    = sym->st_value; \
            abstrSym->size          = sym->st_size; \
            abstrSym->destination   = ESym_ComputeOffset_##_width_(ehdr, sym); \
            \
            switch (_width_) /* hope the compiler spots this */ \
            /* XXX This WILL generate incompatible assignment warnings - ignore them */ \
            /* XXX They are conditional */ \
            { \
                case 32: \
                    abstrSym->elfVersion = EV_32; \
                    abstrSym->elfSym_32  = sym; \
                    break; \
                case 64: \
                    abstrSym->elfVersion = EV_64; \
                    abstrSym->elfSym_64  = sym; \
                    break; \
            } \
        } \
        if (keptSymCount > 0) \
        { \
            esym_array = realloc(esym_array, keptSymCount * sizeof(ESym_Symbol)); \
        } \
        else \
        { \
            free(esym_array); \
            esym_array = NULL; \
        } \
    } \
    else \
    { \
        esym_array = NULL; \
    } \
} 

static ESym_Symbol*
_ESym_LoadObject_64(Elf64_Ehdr* ehdr)
{
    // Find symtab
    Elf64_Shdr const* sec_symtab = NULL;
    _macro_FindSection(64, SHT_SYMTAB, ehdr, sec_symtab);
    if (sec_symtab == NULL) return NULL;

    // Get string table link from symtab
    Elf64_Shdr const* sec_symstrtab = ESym_GetShdr_64(ehdr, sec_symtab->sh_link);

    // Read symbols
    ESym_Symbol* symbols = NULL;
#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types" 
    _tpl_LoadObject__ReadSymbols(64, symbols, ehdr, sec_symtab, sec_symstrtab);
#pragma GCC diagnostic pop

    return symbols;
}

static ESym_Symbol*
_ESym_LoadObject_32(Elf32_Ehdr* ehdr)
{
    Elf32_Shdr const* sec_symtab = NULL;
    _macro_FindSection(32, SHT_SYMTAB, ehdr, sec_symtab);

    if (sec_symtab == NULL) return NULL;

    Elf32_Shdr const* sec_symstrtab = ESym_GetShdr_32(ehdr, sec_symtab->sh_link);

    ESym_Symbol* symbols = NULL;
#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types" 
    _tpl_LoadObject__ReadSymbols(32, symbols, ehdr, sec_symtab, sec_symstrtab);
#pragma GCC diagnostic pop

    return symbols;
}

ESym_Handle*
ESym_LoadObject(void* region)
{
    uint8_t elfClass = *((uint8_t*) (region + EI_CLASS));

    ESym_Symbol* symbols = NULL;
    switch (elfClass)
    {
        case EV_32:
            symbols = _ESym_LoadObject_32((Elf32_Ehdr*) region);
            break;
        case EV_64:
            symbols = _ESym_LoadObject_64((Elf64_Ehdr*) region);
            break;
    }
    
    ESym_Handle* handle = malloc(sizeof(ESym_Handle));

    handle->symbols = symbols;

    handle->byName = malloc(sizeof(ESym_Map_NameToSymbol));
    ESym_Map_NameToSymbolNew(handle->byName);

    handle->byAddr = malloc(sizeof(ESym_Map_AddrToSymbol));
    ESym_Map_AddrToSymbolNew(handle->byAddr);

    _macro_ESym_ForEachSymbol(symbols, sym) 
    {

        // Add Name->Sym 
        {
            ESym_Symbol* inserted = sym;
            switch (ESym_Map_NameToSymbolPut(handle->byName, &inserted, HMDR_FIND))
            {
                case HMPR_FOUND:
                    fprintf(stderr, "Collision! NameToSymbol sym=%p occupant=%p\n", sym, inserted);
                    goto fail;
                case HMPR_FAILED:
                    fprintf(stderr, "Unable update hashmap (HMPR_FAILED - memory?)\n");
                    goto fail;
                default:
                    break;
            }
        }

        {
            ESym_Symbol* inserted = sym;
            switch (ESym_Map_AddrToSymbolPut(handle->byAddr, &inserted, HMDR_FIND))
            {
                case HMPR_FOUND:
                    fprintf(stderr, "Collision! AddrToSymbol sym=%p occupant=%p\n", sym, inserted);
                    goto fail;
                case HMPR_FAILED:
                    fprintf(stderr, "Unable update hashmap (HMPR_FAILED - memory?)\n");
                    goto fail;
                default:
                    break;
            }
        }
    }

    return handle;

fail:
    ESym_Handle_Destroy(handle);
    return NULL;
}

ESym_Symbol*
ESym_GetSymbolByName(ESym_Handle* handle, char const* name)
{
    ESym_Symbol* mockSymbol = malloc(sizeof(ESym_Symbol));
    mockSymbol->name = name;

    ESym_Symbol* findResult = mockSymbol;

    if (!ESym_Map_NameToSymbolFind(handle->byName, &findResult))
    {
        findResult = NULL;
    }
    
    free(mockSymbol);
    return (ESym_Symbol const*) findResult;
}

ESym_Symbol const*
ESym_GetSymbolByAddr(ESym_Handle* handle, ptrwidth_t destination)
{
    ESym_Symbol* mockSymbol = malloc(sizeof(ESym_Symbol));
    mockSymbol->destination = (void*) destination;

    ESym_Symbol* findResult = mockSymbol;

    if (!ESym_Map_AddrToSymbolFind(handle->byAddr, &findResult))
    {
        findResult = NULL;
    }

    free(mockSymbol);
    return (ESym_Symbol const*) findResult;
}
