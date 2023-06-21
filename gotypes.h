// Bootstrap types for AnalyzeGoType.java
// Please import this file into "Data Type Manager" under the "/<program-name>/go" category.

typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned long    qword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined3;
typedef unsigned int    undefined4;
typedef unsigned long    undefined5;
typedef unsigned long    undefined6;
typedef unsigned long    undefined7;
typedef unsigned long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct arraytype arraytype, *Parraytype;

typedef struct rtype rtype, *Prtype;

typedef ulong uintptr_t;

typedef uint uint32_t;

struct rtype {
    uintptr_t size;
    uintptr_t ptrdata;
    uint32_t hash;
    byte tflag;
    byte align;
    byte fieldalign;
    byte kind;
    void * * typeAlg;
    byte * gcdata;
    int str;
    int ptrToThis;
};

struct arraytype {
    struct rtype ty;
    struct rtype * elem;
    struct rtype * slice;
    uintptr_t len;
};

typedef struct arraytype_uncommon arraytype_uncommon, *Parraytype_uncommon;

typedef struct uncommontype uncommontype, *Puncommontype;

typedef ushort uint16_t;

struct uncommontype {
    int pkgpath;
    uint16_t mcount;
    uint16_t xcount;
    int moff;
    int _;
};

struct arraytype_uncommon {
    struct arraytype ty;
    struct uncommontype un;
};

typedef struct bitvector bitvector, *Pbitvector;

typedef int int32_t;

struct bitvector {
    int32_t n;
    byte * bytedata;
};

typedef struct chantype chantype, *Pchantype;

struct chantype {
    struct rtype ty;
    struct rtype * elem;
    uintptr_t dir;
};

typedef struct chantype_uncommon chantype_uncommon, *Pchantype_uncommon;

struct chantype_uncommon {
    struct chantype ty;
    struct uncommontype un;
};

typedef struct complex128 complex128, *Pcomplex128;

struct complex128 {
    double real;
    double imag;
};

typedef struct complex64 complex64, *Pcomplex64;

struct complex64 {
    float real;
    float imag;
};

typedef struct eface eface, *Peface;

struct eface {
    struct rtype * ty;
    void * data;
};

typedef struct functype functype, *Pfunctype;

struct functype {
    struct rtype ty;
    uint16_t inCount;
    uint16_t outCount;
};

typedef struct functype_uncommon functype_uncommon, *Pfunctype_uncommon;

struct functype_uncommon {
    struct functype ty;
    struct uncommontype un;
};

typedef struct iface iface, *Piface;

struct iface {
    void * itab;
    void * data;
};

typedef struct imethod imethod, *Pimethod;

struct imethod {
    int nameOff;
    int typeOff;
};

typedef struct interfacetype interfacetype, *Pinterfacetype;

typedef struct slice_imethod slice_imethod, *Pslice_imethod;

typedef ulong __darwin_size_t;

typedef __darwin_size_t size_t;

struct slice_imethod {
    struct imethod * data;
    size_t len;
    size_t cap;
};

struct interfacetype {
    struct rtype ty;
    byte * pkgPath;
    struct slice_imethod methods;
};

typedef struct interfacetype_uncommon interfacetype_uncommon, *Pinterfacetype_uncommon;

struct interfacetype_uncommon {
    struct interfacetype ty;
    struct uncommontype un;
};

typedef struct itab itab, *Pitab;

struct itab {
    struct interfacetype * iface;
    struct rtype * ty;
    uint32_t hash;
    undefined4 field3_0x14;
    void * fun[1];
};

typedef struct maptype maptype, *Pmaptype;

struct maptype {
    struct rtype ty;
    struct rtype * key;
    struct rtype * elem;
    struct rtype * bucket;
    byte keysize;
    byte valuesize;
    uint16_t bucketsize;
    uint32_t flags;
};

typedef struct maptype_uncommon maptype_uncommon, *Pmaptype_uncommon;

struct maptype_uncommon {
    struct maptype ty;
    struct uncommontype un;
};

typedef struct moduledata moduledata, *Pmoduledata;

typedef struct slice slice, *Pslice;

typedef struct slice_u32 slice_u32, *Pslice_u32;

typedef struct slice_i32 slice_i32, *Pslice_i32;

typedef struct string string, *Pstring;

struct slice_u32 {
    uint32_t * data;
    size_t len;
    size_t cap;
};

struct string {
    byte * data;
    size_t len;
};

struct slice {
    void * data;
    size_t len;
    size_t cap;
};

struct slice_i32 {
    int32_t * data;
    size_t len;
    size_t cap;
};

struct moduledata {
    struct slice pclntable;
    struct slice ftab;
    struct slice_u32 filetab;
    uintptr_t findfunctab;
    uintptr_t minpc;
    uintptr_t maxpc;
    uintptr_t text;
    uintptr_t etext;
    uintptr_t noptrdata;
    uintptr_t enoptrdata;
    uintptr_t data;
    uintptr_t edata;
    uintptr_t bss;
    uintptr_t ebss;
    uintptr_t noptrbss;
    uintptr_t enoptrbss;
    uintptr_t end;
    uintptr_t gcdata;
    uintptr_t gcbss;
    uintptr_t types;
    uintptr_t etypes;
    struct slice textsectmap;
    struct slice_i32 typelinks;
    struct slice itablinks;
    struct slice ptab;
    struct string pluginpath;
    struct slice pkghashes;
    struct string modulename;
    struct slice modulehashes;
    byte hasmain;
    undefined3 field30_0x189;
    struct bitvector gcdatamask;
    struct bitvector gcbssmask;
    void * typemap;
    bool bad;
    undefined3 field35_0x1ad;
    struct moduledata * next;
};

typedef struct ptrtype ptrtype, *Pptrtype;

struct ptrtype {
    struct rtype ty;
    struct rtype * elem;
};

typedef struct ptrtype_uncommon ptrtype_uncommon, *Pptrtype_uncommon;

struct ptrtype_uncommon {
    struct ptrtype ty;
    struct uncommontype un;
};

typedef struct rtype_uncommon rtype_uncommon, *Prtype_uncommon;

struct rtype_uncommon {
    struct rtype ty;
    struct uncommontype un;
};

typedef struct slice_byte slice_byte, *Pslice_byte;

struct slice_byte {
    byte * data;
    size_t len;
    size_t cap;
};

typedef struct slice_structfield slice_structfield, *Pslice_structfield;

typedef struct structfield structfield, *Pstructfield;

struct slice_structfield {
    struct structfield * data;
    size_t len;
    size_t cap;
};

struct structfield {
    byte * name;
    struct rtype * typ;
    uintptr_t offsetEmbed;
};

typedef struct slicetype slicetype, *Pslicetype;

struct slicetype {
    struct rtype ty;
    struct rtype * elem;
};

typedef struct slicetype_uncommon slicetype_uncommon, *Pslicetype_uncommon;

struct slicetype_uncommon {
    struct slicetype ty;
    struct uncommontype un;
};

typedef struct structtype structtype, *Pstructtype;

struct structtype {
    struct rtype ty;
    byte * pkgPath;
    struct slice_structfield fields;
};

typedef struct structtype_uncommon structtype_uncommon, *Pstructtype_uncommon;

struct structtype_uncommon {
    struct structtype ty;
    struct uncommontype un;
};

