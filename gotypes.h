// Bootstrap types for AnalyzeGoType.java
// Please import this file into "Data Type Manager" under the "/<program-name>/go" category.

// The definitions in this file is extracted from Go 1.12, you may need to modifiy for your own Go version.

typedef signed char      int8;
typedef signed short     int16;
typedef signed int       int32;
typedef signed long long int64;

typedef unsigned char      byte;
typedef unsigned char      uint8;
typedef unsigned short     uint16;
typedef unsigned int       uint32;
typedef unsigned long long uint64;
typedef unsigned long long uintptr;

struct complex64 {
    float real;
    float imag;
};

struct complex128 {
    double real;
    double imag;
};

struct bitvector {
    int    n;
    byte * bytedata;
};

struct slice {
    void *  data;
    uintptr len;
    uintptr cap;
};

struct slice_byte {
    byte *  data;
    uintptr len;
    uintptr cap;
};

struct slice_u32 {
    uint32 * data;
    uintptr  len;
    uintptr  cap;
};

struct slice_i32 {
    int *   data;
    uintptr len;
    uintptr cap;
};

struct string {
    char *  data;
    uintptr len;
};

struct rtype {
    uintptr size;
    uintptr ptrdata;
    uint32  hash;
    byte    tflag;
    byte    align;
    byte    fieldalign;
    byte    kind;
    void ** typeAlg;
    byte *  gcdata;
    int     str;
    int     ptrToThis;
};

struct uncommontype {
    int    pkgpath;
    uint16 mcount;
    uint16 xcount;
    uint32 moff;
    uint32 _;
};

struct rtype_uncommon {
    struct rtype        ty;
    struct uncommontype un;
};

struct arraytype {
    struct rtype   ty;
    struct rtype * elem;
    struct rtype * slice;
    uintptr        len;
};

struct arraytype_uncommon {
    struct arraytype    ty;
    struct uncommontype un;
};

struct chantype {
    struct rtype   ty;
    struct rtype * elem;
    uintptr        dir;
};

struct chantype_uncommon {
    struct chantype     ty;
    struct uncommontype un;
};

struct functype {
    struct rtype ty;
    uint16       inCount;
    uint16       outCount;
};

struct functype_uncommon {
    struct functype     ty;
    struct uncommontype un;
};

struct imethod {
    int nameOff;
    int typeOff;
};

struct slice_imethod {
    struct imethod * data;
    uintptr          len;
    uintptr          cap;
};

struct interfacetype {
    struct rtype         ty;
    byte *               pkgPath;
    struct slice_imethod methods;
};

struct interfacetype_uncommon {
    struct interfacetype ty;
    struct uncommontype  un;
};

struct itab {
    struct interfacetype * iface;
    struct rtype *         ty;
    uint32                 hash;
    uint32                 _;
    void *                 fun[1];
};

struct iface {
    struct itab * itab;
    void *        data;
};

struct eface {
    struct rtype * ty;
    void *         data;
};

struct maptype {
    struct rtype   ty;
    struct rtype * key;
    struct rtype * elem;
    struct rtype * bucket;
    byte           keysize;
    byte           valuesize;
    uint16         bucketsize;
    uint32         flags;
};

struct maptype_uncommon {
    struct maptype      ty;
    struct uncommontype un;
};

struct ptrtype {
    struct rtype   ty;
    struct rtype * elem;
};

struct ptrtype_uncommon {
    struct ptrtype      ty;
    struct uncommontype un;
};

struct slicetype {
    struct rtype   ty;
    struct rtype * elem;
};

struct slicetype_uncommon {
    struct slicetype    ty;
    struct uncommontype un;
};

struct structfield {
    byte *         name;
    struct rtype * typ;
    uintptr        offsetEmbed;
};

struct slice_structfield {
    struct structfield * data;
    uintptr              len;
    uintptr              cap;
};

struct structtype {
    struct rtype             ty;
    byte *                   pkgPath;
    struct slice_structfield fields;
};

struct structtype_uncommon {
    struct structtype ty;
    struct uncommontype un;
};

struct moduledata {
    struct slice        pclntable;
    struct slice        ftab;
    struct slice_u32    filetab;
    uintptr             findfunctab;
    uintptr             minpc;
    uintptr             maxpc;
    uintptr             text;
    uintptr             etext;
    uintptr             noptrdata;
    uintptr             enoptrdata;
    uintptr             data;
    uintptr             edata;
    uintptr             bss;
    uintptr             ebss;
    uintptr             noptrbss;
    uintptr             enoptrbss;
    uintptr             end;
    uintptr             gcdata;
    uintptr             gcbss;
    uintptr             types;
    uintptr             etypes;
    struct slice        textsectmap;
    struct slice_i32    typelinks;
    struct slice        itablinks;
    struct slice        ptab;
    struct string       pluginpath;
    struct slice        pkghashes;
    struct string       modulename;
    struct slice        modulehashes;
    byte                hasmain;
    byte                _padding1[3];
    struct bitvector    gcdatamask;
    struct bitvector    gcbssmask;
    void *              typemap;
    bool                bad;
    byte                _padding2[3];
    struct moduledata * next;
};
