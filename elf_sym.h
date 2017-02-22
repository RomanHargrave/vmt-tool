/*
 * elf_sym.h 
 * (C) 2017 Roman Hargrave <roman@hargrave.info>
 *
 * Definitions and API for translating ELF symbols and addresses within a mapped memory region
 * for static comprehension and analysis of ELF-format libraries, PIE and non-PIE executables
 */

#include <elf.h>
#include <gchashmap/hashmap.h>

// Smallest type that can accomodate a pointer on the build (x86_64) target
typedef uint64_t ptrwidth_t;

typedef enum _e_ESym_ELFVersion {
    EV_INVALID = 0,
    EV_32,
    EV_64
}
ESym_ELFVersion;

/**
 * ElfX_Sym wrapper including computed data such as the "relocated" value (destination) and name
 */
typedef struct _s_ESym_Symbol
{
    ESym_ELFVersion elfVersion; 
    union { 
        Elf32_Sym const* elfSym_32; 
        Elf64_Sym const* elfSym_64; 
    };

    char const*     name;
    void const*     destination;
    uint64_t        definition;
    uint64_t        size;
}
ESym_Symbol;

/**
 * SDBM String Hashing Function
 * Used to convert a string to a numeric representation before retrieval from the hashmap. 
 */
static inline uint64_t 
ESym_StringHash(char const* str) { 
    uint64_t hash = 1125899906842597L; // it's a really big prime

    register char swp = 0;
    while (swp = *str++)
    {
        hash = (31 * hash) + swp;
    } 

    return hash;
}

#define _macro_ESym_ForEachSymbol(_m_symbols, _m_name) \
    for(ESym_Symbol* _m_name = _m_symbols; _m_name->elfVersion != EV_INVALID; ++_m_name)

// XXX This is terrible
#define _macro_ESym_GetElfPtr(sym) \
    (sym->elfVersion == EV_32 ? (void*) sym->elfSym_32 : (void*) sym->elfSym_64)

// XXX hack to deal with ELF disparity
#define ESym_ElfProp(sym, prop) \
    (sym->elfVersion == EV_32 ? sym->elfSym_32->prop : sym->elfSym_64->prop)

// XXX entries are pairs containing the address or name and the ELF entry pointer for the symbol 
DEFINE_HASHMAP(ESym_Map_NameToSymbol, ESym_Symbol);
DEFINE_HASHMAP(ESym_Map_AddrToSymbol, ESym_Symbol);

typedef struct _s_ESym_Handle
{
    ESym_Symbol*            symbols;
    ESym_Map_NameToSymbol*  byName;
    ESym_Map_AddrToSymbol*  byAddr;
}
ESym_Handle;

/*
 * Clean up and free the handle.
 * Deinitializes and frees the maps in the handle.
 */
void ESym_Handle_Destroy(ESym_Handle*);

/*
 * Load an ELF object.
 * This will parse and map all _named_ symbols and then their addresses
 * Symbols with empty names or addresses will not be included.
 * The address map will be generated as a revrse of the Symbol map using the same criteria
 *
 * NULL is returned when there are no symbols.
 */
ESym_Handle* ESym_LoadObject(void*); 

/*
 * Low Level ELF navigation
 */

/*
 * Check ELF magic 
 */
int ESym_ValidateELF(void*);

/*
 * GetShdr: "Get Section Header"
 *
 * Get the section header for the section at an index
 */
Elf64_Shdr const* ESym_GetShdr_64(Elf64_Ehdr const*, Elf64_Xword);
Elf32_Shdr const* ESym_GetShdr_32(Elf32_Ehdr const*, Elf32_Word);

/*
 * Compute a tangible address from an offset, relative to the starting position of the ELF region
 */
void const* ESym_ComputeOffset_64(Elf64_Ehdr const*, Elf64_Sym const*);
void const* ESym_ComputeOffset_32(Elf32_Ehdr const*, Elf32_Sym const*);

/*
 * Symbol Search
 */
ESym_Symbol const* ESym_GetSymbolByName(ESym_Handle*, char const*);
ESym_Symbol const* ESym_GetSymbolByAddr(ESym_Handle*, ptrwidth_t);
