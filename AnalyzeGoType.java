// Analyze Go type information and create type.
//@author
//@category Go
//@keybinding F9
//@menupath
//@toolbar

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.stream.Stream;

import org.apache.commons.lang3.StringUtils;

import aQute.bnd.unmodifiable.Lists;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

final class Kind {
    public static final int Invalid       = 0;
    public static final int Bool          = 1;
    public static final int Int           = 2;
    public static final int Int8          = 3;
    public static final int Int16         = 4;
    public static final int Int32         = 5;
    public static final int Int64         = 6;
    public static final int Uint          = 7;
    public static final int Uint8         = 8;
    public static final int Uint16        = 9;
    public static final int Uint32        = 10;
    public static final int Uint64        = 11;
    public static final int Uintptr       = 12;
    public static final int Float32       = 13;
    public static final int Float64       = 14;
    public static final int Complex64     = 15;
    public static final int Complex128    = 16;
    public static final int Array         = 17;
    public static final int Chan          = 18;
    public static final int Func          = 19;
    public static final int Interface     = 20;
    public static final int Map           = 21;
    public static final int Ptr           = 22;
    public static final int Slice         = 23;
    public static final int String        = 24;
    public static final int Struct        = 25;
    public static final int UnsafePointer = 26;
}

final class TFlags {
    public static final int Uncommon  = 1 << 0;
    public static final int ExtraStar = 1 << 1;

    public static boolean isUncommon(int tflag)   { return (tflag & Uncommon) != 0; }
    public static boolean hasExtraStar(int tflag) { return (tflag & ExtraStar) != 0; }
}

final class AnalyzeException extends Exception {
    AnalyzeException(String msg) {
        super(msg);
    }
}

final class TypeInfo {
    public final int               kind;
    public final long              size;
    public final String            name;
    public final String            path;
    public final Address           mkey;
    public final Address           elem;
    public final DataType          type;
    public final List<StructField> fields;

    private TypeInfo keyType = null;
    private TypeInfo elemType = null;

    private TypeInfo(
        DataType                type,
        String                  name,
        String                  path,
        int                     kind,
        long                    size,
        Address                 mkey,
        Address                 elem,
        Collection<StructField> fields
    ) {
        this.kind   = kind;
        this.size   = size;
        this.name   = name;
        this.path   = path;
        this.mkey   = mkey;
        this.elem   = elem;
        this.type   = type;
        this.fields = fields == null ? null : Lists.copyOf(fields);
    }

    private String prefix(String name, boolean withPath) {
        if (!withPath || path.isEmpty()) {
            return name;
        } else {
            return path + "/" + name;
        }
    }

    private String chandir() {
        var sb = new StringBuilder(2);
        if ((size & 1) != 0) sb.append('r');
        if ((size & 2) != 0) sb.append('w');
        return sb.toString();
    }

    private String keyString(boolean withPath) {
        return keyType.deriveTypeName(mkey, withPath);
    }

    private String elemString(boolean withPath) {
        return elemType.deriveTypeName(elem, withPath);
    }

    public void setKeyType(TypeInfo type) {
        this.keyType = Objects.requireNonNull(type, "key type is null");
    }

    public void setElemType(TypeInfo type) {
        this.elemType = Objects.requireNonNull(type, "elem type is null");
    }

    public String deriveTypeName(Address addr, boolean withPath) {
        return name.matches("[._\\w\\d]+") ? prefix(name, withPath) : switch (kind) {
            case Kind.Array     -> "array<%d,%s>".formatted(size, elemString(withPath));
            case Kind.Chan      -> "chan<%s,%s>".formatted(chandir(), elemString(withPath));
            case Kind.Func      -> addr.toString("anonfunc_");
            case Kind.Interface -> name.equals("interface {}") ? "eface" : addr.toString("anoniface_");
            case Kind.Map       -> "map<%s,%s>".formatted(keyString(withPath), elemString(withPath));
            case Kind.Ptr       -> "*" + elemString(withPath);
            case Kind.Slice     -> "slice<%s>".formatted(elemString(withPath));
            case Kind.Struct    -> name.equals("struct {}") ? "estruct" : addr.toString("anonstruct_");
            default             -> prefix(name, withPath);
        };
    }

    public static TypeInfo map(DataType type, String name, String path, Address key, Address elem) {
        return new TypeInfo(type, name, path, Kind.Map, -1, key, elem, null);
    }

    public static TypeInfo chan(DataType type, String name, String path, Address elem, long dir) {
        return new TypeInfo(type, name, path, Kind.Chan, dir, null, elem, null);
    }

    public static TypeInfo basic(DataType type, String name, String path, int kind) {
        return new TypeInfo(type, name, path, kind, -1, null, null, null);
    }

    public static TypeInfo array(DataType type, String name, String path, Address elem, long size) {
        return new TypeInfo(type, name, path, Kind.Array, size, null, elem, null);
    }

    public static TypeInfo struct(DataType type, String name, String path, long size, Collection<StructField> fields) {
        return new TypeInfo(type, name, path, Kind.Struct, size, null, null, fields);
    }

    public static TypeInfo indirect(DataType type, String name, String path, int kind, Address elem) {
        return new TypeInfo(type, name, path, kind, -1, null, elem, null);
    }
}

final class StructField {
    public final int     offs;
    public final String  name;
    public final String  tags;
    public final Address type;
    public final Address self;
    public final Address refs;

    public StructField(String name, String tags, Address type, Address self, Address refs, int offs) {
        this.name = name;
        this.tags = tags;
        this.type = type;
        this.offs = offs;
        this.self = self;
        this.refs = refs;
    }
}


public class AnalyzeGoType extends GhidraScript {
    private final class Analyzer {
        private final class Types {
            public final DataType i8  = sized("/char", 1);
            public final DataType i16 = sized("/short", 2);
            public final DataType i32 = sized("/int", 4);
            public final DataType i64 = sized("/long", 8);

            public final DataType u8  = sized("/byte", 1);
            public final DataType u16 = sized("/ushort", 2);
            public final DataType u32 = sized("/uint", 4);
            public final DataType u64 = sized("/ulong", 8);

            public final DataType f32 = sized("/float", 4);
            public final DataType f64 = sized("/double", 8);

            public final DataType bool    = sized("/bool", 1);
            public final DataType void_p  = sized("/void *", 8);
            public final DataType uintptr = sized("/_uintptr_t.h/uintptr_t", 8);

            public final Structure rtype         = struct("/go/rtype");
            public final Structure maptype       = struct("/go/maptype");
            public final Structure ptrtype       = struct("/go/ptrtype");
            public final Structure chantype      = struct("/go/chantype");
            public final Structure functype      = struct("/go/functype");
            public final Structure arraytype     = struct("/go/arraytype");
            public final Structure slicetype     = struct("/go/slicetype");
            public final Structure structtype    = struct("/go/structtype");
            public final Structure uncommontype  = struct("/go/uncommontype");
            public final Structure interfacetype = struct("/go/interfacetype");

            public final Structure rtype_uncommon         = struct("/go/rtype_uncommon");
            public final Structure maptype_uncommon       = struct("/go/maptype_uncommon");
            public final Structure ptrtype_uncommon       = struct("/go/ptrtype_uncommon");
            public final Structure chantype_uncommon      = struct("/go/chantype_uncommon");
            public final Structure functype_uncommon      = struct("/go/functype_uncommon");
            public final Structure arraytype_uncommon     = struct("/go/arraytype_uncommon");
            public final Structure slicetype_uncommon     = struct("/go/slicetype_uncommon");
            public final Structure structtype_uncommon    = struct("/go/structtype_uncommon");
            public final Structure interfacetype_uncommon = struct("/go/interfacetype_uncommon");

            public final Structure iface       = struct("/go/iface");
            public final Structure slice       = struct("/go/slice");
            public final Structure string      = struct("/go/string");
            public final Structure complex64   = struct("/go/complex64");
            public final Structure complex128  = struct("/go/complex128");
            public final Structure moduledata  = struct("/go/moduledata");
            public final Structure structfield = struct("/go/structfield");

            public DataType of(String path) {
                var dtm = currentProgram.getDataTypeManager();
                var ref = dtm.getDataType(path);

                /* must exist */
                if (ref == null) {
                    throw new RuntimeException("missing data type '%s'".formatted(path));
                } else {
                    return ref;
                }
            }

            public DataType sized(String path, int size) {
                var ty = of(path);
                var nb = ty.getLength();

                /* validate type size */
                if (nb != size) {
                    throw new RuntimeException("invalid size for type " + path);
                } else {
                    return ty;
                }
            }

            public Structure struct(String path) {
                return (Structure)of(path);
            }
        }

        private final class Offsets {
            private final class rtype {
                public final int str       = of(Types.rtype, "str");
                public final int kind      = of(Types.rtype, "kind");
                public final int size      = of(Types.rtype, "size");
                public final int tflag     = of(Types.rtype, "tflag");
                public final int ptrToThis = of(Types.rtype, "ptrToThis");
            }

            private final class maptype {
                public final int key    = of(Types.maptype, "key");
                public final int elem   = of(Types.maptype, "elem");
                public final int bucket = of(Types.maptype, "bucket");
            }

            private final class ptrtype {
                public final int elem = of(Types.ptrtype, "elem");
            }

            private final class chantype {
                public final int dir  = of(Types.chantype, "dir");
                public final int elem = of(Types.chantype, "elem");
            }

            private final class arraytype {
                public final int len   = of(Types.arraytype, "len");
                public final int elem  = of(Types.arraytype, "elem");
                public final int slice = of(Types.arraytype, "slice");
            }

            private final class slicetype {
                public final int elem = of(Types.slicetype, "elem");
            }

            private final class structtype {
                public final int fields = of(Types.structtype, "fields");
            }

            private final class uncommontype {
                public final int pkgpath = of(Types.uncommontype, "pkgpath");
            }

            private final class rtype_uncommon {
                public final int un = of(Types.rtype_uncommon, "un");
            }

            private final class maptype_uncommon {
                public final int un = of(Types.maptype_uncommon, "un");
            }

            private final class ptrtype_uncommon {
                public final int un = of(Types.ptrtype_uncommon, "un");
            }

            private final class chantype_uncommon {
                public final int un = of(Types.chantype_uncommon, "un");
            }

            private final class functype_uncommon {
                public final int un = of(Types.functype_uncommon, "un");
            }

            private final class arraytype_uncommon {
                public final int un = of(Types.arraytype_uncommon, "un");
            }

            private final class slicetype_uncommon {
                public final int un = of(Types.slicetype_uncommon, "un");
            }

            private final class structtype_uncommon {
                public final int ty = of(Types.structtype_uncommon, "ty");
                public final int un = of(Types.structtype_uncommon, "un");
            }

            private final class interfacetype_uncommon {
                public final int un = of(Types.interfacetype_uncommon, "un");
            }

            private final class slice {
                public final int len  = of(Types.slice, "len");
                public final int data = of(Types.slice, "data");
            }

            private final class moduledata {
                public final int next      = of(Types.moduledata, "next");
                public final int types     = of(Types.moduledata, "types");
                public final int etypes    = of(Types.moduledata, "etypes");
                public final int typelinks = of(Types.moduledata, "typelinks");
            }

            private final class structfield {
                public final int typ         = of(Types.structfield, "typ");
                public final int name        = of(Types.structfield, "name");
                public final int offsetEmbed = of(Types.structfield, "offsetEmbed");
            }

            public final rtype        rtype        = new rtype();
            public final maptype      maptype      = new maptype();
            public final ptrtype      ptrtype      = new ptrtype();
            public final chantype     chantype     = new chantype();
            public final arraytype    arraytype    = new arraytype();
            public final slicetype    slicetype    = new slicetype();
            public final structtype   structtype   = new structtype();
            public final uncommontype uncommontype = new uncommontype();

            public final rtype_uncommon         rtype_uncommon         = new rtype_uncommon();
            public final maptype_uncommon       maptype_uncommon       = new maptype_uncommon();
            public final ptrtype_uncommon       ptrtype_uncommon       = new ptrtype_uncommon();
            public final chantype_uncommon      chantype_uncommon      = new chantype_uncommon();
            public final functype_uncommon      functype_uncommon      = new functype_uncommon();
            public final arraytype_uncommon     arraytype_uncommon     = new arraytype_uncommon();
            public final slicetype_uncommon     slicetype_uncommon     = new slicetype_uncommon();
            public final structtype_uncommon    structtype_uncommon    = new structtype_uncommon();
            public final interfacetype_uncommon interfacetype_uncommon = new interfacetype_uncommon();

            public final slice       slice       = new slice();
            public final moduledata  moduledata  = new moduledata();
            public final structfield structfield = new structfield();

            public int of(Structure ty, String name) {
                return Stream
                    .of        (ty.getComponents())
                    .filter    (v -> name.equals(v.getFieldName()))
                    .findAny   ()
                    .get       ()
                    .getOffset ();
            }
        }

        private final class Symbols {
            private final class runtime {
                public final Symbol firstmoduledata = of("runtime.firstmoduledata");
            }

            public runtime runtime = new runtime();

            public Symbol of(String name) {
                return getSymbols(name, null).iterator().next();
            }
        }

        private final Types   Types   = new Types();
        private final Offsets Offsets = new Offsets();
        private final Symbols Symbols = new Symbols();

        private final Map<Integer, DataType> TypeMap = Map.ofEntries(
            Map.entry(Kind.Bool         , Types.rtype),
            Map.entry(Kind.Int          , Types.rtype),
            Map.entry(Kind.Int8         , Types.rtype),
            Map.entry(Kind.Int16        , Types.rtype),
            Map.entry(Kind.Int32        , Types.rtype),
            Map.entry(Kind.Int64        , Types.rtype),
            Map.entry(Kind.Uint         , Types.rtype),
            Map.entry(Kind.Uint8        , Types.rtype),
            Map.entry(Kind.Uint16       , Types.rtype),
            Map.entry(Kind.Uint32       , Types.rtype),
            Map.entry(Kind.Uint64       , Types.rtype),
            Map.entry(Kind.Uintptr      , Types.rtype),
            Map.entry(Kind.Float32      , Types.rtype),
            Map.entry(Kind.Float64      , Types.rtype),
            Map.entry(Kind.Complex64    , Types.rtype),
            Map.entry(Kind.Complex128   , Types.rtype),
            Map.entry(Kind.Array        , Types.arraytype),
            Map.entry(Kind.Chan         , Types.chantype),
            Map.entry(Kind.Func         , Types.functype),
            Map.entry(Kind.Interface    , Types.interfacetype),
            Map.entry(Kind.Map          , Types.maptype),
            Map.entry(Kind.Ptr          , Types.ptrtype),
            Map.entry(Kind.Slice        , Types.slicetype),
            Map.entry(Kind.String       , Types.rtype),
            Map.entry(Kind.Struct       , Types.structtype),
            Map.entry(Kind.UnsafePointer, Types.rtype)
        );

        private final Map<Integer, DataType> UncommonTypeMap = Map.ofEntries(
            Map.entry(Kind.Bool         , Types.rtype_uncommon),
            Map.entry(Kind.Int          , Types.rtype_uncommon),
            Map.entry(Kind.Int8         , Types.rtype_uncommon),
            Map.entry(Kind.Int16        , Types.rtype_uncommon),
            Map.entry(Kind.Int32        , Types.rtype_uncommon),
            Map.entry(Kind.Int64        , Types.rtype_uncommon),
            Map.entry(Kind.Uint         , Types.rtype_uncommon),
            Map.entry(Kind.Uint8        , Types.rtype_uncommon),
            Map.entry(Kind.Uint16       , Types.rtype_uncommon),
            Map.entry(Kind.Uint32       , Types.rtype_uncommon),
            Map.entry(Kind.Uint64       , Types.rtype_uncommon),
            Map.entry(Kind.Uintptr      , Types.rtype_uncommon),
            Map.entry(Kind.Float32      , Types.rtype_uncommon),
            Map.entry(Kind.Float64      , Types.rtype_uncommon),
            Map.entry(Kind.Complex64    , Types.rtype_uncommon),
            Map.entry(Kind.Complex128   , Types.rtype_uncommon),
            Map.entry(Kind.Array        , Types.arraytype_uncommon),
            Map.entry(Kind.Chan         , Types.chantype_uncommon),
            Map.entry(Kind.Func         , Types.functype_uncommon),
            Map.entry(Kind.Interface    , Types.interfacetype_uncommon),
            Map.entry(Kind.Map          , Types.maptype_uncommon),
            Map.entry(Kind.Ptr          , Types.ptrtype_uncommon),
            Map.entry(Kind.Slice        , Types.slicetype_uncommon),
            Map.entry(Kind.String       , Types.rtype_uncommon),
            Map.entry(Kind.Struct       , Types.structtype_uncommon),
            Map.entry(Kind.UnsafePointer, Types.rtype_uncommon)
        );

        private final Map<Integer, Integer> UncommonOffsetMap = Map.ofEntries(
            Map.entry(Kind.Bool          , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Int           , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Int8          , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Int16         , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Int32         , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Int64         , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Uint          , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Uint8         , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Uint16        , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Uint32        , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Uint64        , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Uintptr       , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Float32       , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Float64       , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Complex64     , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Complex128    , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Array         , Offsets.arraytype_uncommon.un),
            Map.entry(Kind.Chan          , Offsets.chantype_uncommon.un),
            Map.entry(Kind.Func          , Offsets.functype_uncommon.un),
            Map.entry(Kind.Interface     , Offsets.interfacetype_uncommon.un),
            Map.entry(Kind.Map           , Offsets.maptype_uncommon.un),
            Map.entry(Kind.Ptr           , Offsets.ptrtype_uncommon.un),
            Map.entry(Kind.Slice         , Offsets.slicetype_uncommon.un),
            Map.entry(Kind.String        , Offsets.rtype_uncommon.un),
            Map.entry(Kind.Struct        , Offsets.structtype_uncommon.un),
            Map.entry(Kind.UnsafePointer , Offsets.rtype_uncommon.un)
        );

        private String parseTagAt(Address addr) throws Exception {
            int len;
            var flag = getByte(addr);

            /* no tags */
            if ((flag & (1 << 1)) == 0) {
                return null;
            }

            /* skip flags and name */
            len = Short.reverseBytes(getShort(addr.add(1)));
            len = Short.reverseBytes(getShort(addr.add(len + 3)));
            return new String(getBytes(addr.add(len + 5), len));
        }

        private String parseNameAt(Address addr) throws Exception {
            return new String(getBytes(
                addr.add(3),
                Short.reverseBytes(getShort(addr.add(1)))
            ));
        }

        private Address resolveOffset(Address base, int offs) throws Exception {
            Address ptr = null;
            Address mod = Symbols.runtime.firstmoduledata.getAddress();

            /* iterate over all modules */
            while (mod.getOffset() != 0) {
                var types  = toAddr(getLong(mod.add(Offsets.moduledata.types)));
                var etypes = toAddr(getLong(mod.add(Offsets.moduledata.etypes)));

                /* base range check */
                if (base.compareTo(types) < 0 || base.compareTo(etypes) >= 0) {
                    mod = toAddr(getLong(mod.add(Offsets.moduledata.next)));
                    continue;
                }

                /* offset range check */
                if ((ptr = types.add(offs)).compareTo(etypes) > 0) {
                    throw new AnalyzeException("name offset out of range: %#x".formatted(offs));
                } else {
                    break;
                }
            }

            /* check if it exists */
            if (ptr == null) {
                throw new AnalyzeException("name offset base pointer out of range: %s".formatted(base.toString()));
            } else {
                return ptr;
            }
        }

        private void scanTypes(Address addr, Queue<Address> queue, Map<Address, TypeInfo> types) throws Exception {
            var name  = "";
            var path  = "";
            var size  = getLong(addr.add(Offsets.rtype.size));
            var kind  = getByte(addr.add(Offsets.rtype.kind)) & 0x1f;
            var tflag = getByte(addr.add(Offsets.rtype.tflag));

            /* select new basic type */
            var type = TFlags.isUncommon(tflag)
                ? UncommonTypeMap.get(kind)
                : TypeMap.get(kind);

            /* the type must exist */
            if (type == null) {
                throw new AnalyzeException("invalid type kind %d".formatted(kind));
            }

            /* add pointer element to the buffer */
            if (kind == Kind.Ptr) {
                queue.add(toAddr(getLong(addr.add(Offsets.ptrtype.elem))));
            }

            /* some relative offsets */
            var str = getInt(addr.add(Offsets.rtype.str));
            var ptr = getInt(addr.add(Offsets.rtype.ptrToThis));

            /* add pointer type if any */
            if (ptr != 0) {
                queue.add(resolveOffset(addr, ptr));
            }

            /* set the name if any */
            if (str != 0) {
                name = parseNameAt(resolveOffset(addr, str));
            }

            /* remove the star if needed */
            if (str != 0 && TFlags.hasExtraStar(tflag)) {
                name = name.substring(1);
            }

            /* update monitor */
            if (!name.isEmpty()) {
                monitor.setMessage("Scan: " + name);
            } else {
                monitor.setMessage("Scan: <unnamed>." + addr.toString());
            }

            /* add package path for uncommon types */
            if (TFlags.isUncommon(tflag)) {
                var rpos = 0;
                var offs = getInt(addr.add(UncommonOffsetMap.get(kind) + Offsets.uncommontype.pkgpath));
                var vals = StringUtils.split(parseNameAt(resolveOffset(addr, offs)), '/');

                /* check if the package path is valid */
                if (vals == null || vals.length == 0) {
                    vals = new String[] { "" };
                }

                /* remove program name prefix if any */
                if (vals[rpos].equals(currentProgram.getName())) {
                    rpos++;
                }

                /* remove vendor prefixes if any */
                if (vals[rpos].equals("vendor")) {
                    rpos++;
                }

                /* remove the last part (which is almost wrong) */
                if (vals.length - rpos >= 2) {
                    vals = Arrays.copyOfRange(vals, rpos, vals.length - 1);
                    path = StringUtils.join(vals, '/');
                }
            }

            /* construct type info */
            var rtti = switch (kind) {
                default -> {
                    throw new AnalyzeException("invalid type kind %d".formatted(kind));
                }

                /* simple types, we treat all funcs as `void *` and all ifaces as `iface`
                 * for structs, we use a dummy basic struct just for deriving type name */
                case Kind.Bool          -> TypeInfo.basic(type, name, path, Kind.Bool);
                case Kind.Int           -> TypeInfo.basic(type, name, path, Kind.Int);
                case Kind.Int8          -> TypeInfo.basic(type, name, path, Kind.Int8);
                case Kind.Int16         -> TypeInfo.basic(type, name, path, Kind.Int16);
                case Kind.Int32         -> TypeInfo.basic(type, name, path, Kind.Int32);
                case Kind.Int64         -> TypeInfo.basic(type, name, path, Kind.Int64);
                case Kind.Uint          -> TypeInfo.basic(type, name, path, Kind.Uint);
                case Kind.Uint8         -> TypeInfo.basic(type, name, path, Kind.Uint8);
                case Kind.Uint16        -> TypeInfo.basic(type, name, path, Kind.Uint16);
                case Kind.Uint32        -> TypeInfo.basic(type, name, path, Kind.Uint32);
                case Kind.Uint64        -> TypeInfo.basic(type, name, path, Kind.Uint64);
                case Kind.Uintptr       -> TypeInfo.basic(type, name, path, Kind.Uintptr);
                case Kind.Float32       -> TypeInfo.basic(type, name, path, Kind.Float32);
                case Kind.Float64       -> TypeInfo.basic(type, name, path, Kind.Float64);
                case Kind.Complex64     -> TypeInfo.basic(type, name, path, Kind.Complex64);
                case Kind.Complex128    -> TypeInfo.basic(type, name, path, Kind.Complex128);
                case Kind.Func          -> TypeInfo.basic(type, name, path, Kind.Func);
                case Kind.Interface     -> TypeInfo.basic(type, name, path, Kind.Interface);
                case Kind.String        -> TypeInfo.basic(type, name, path, Kind.String);
                case Kind.Struct        -> TypeInfo.basic(type, name, path, Kind.Struct);
                case Kind.UnsafePointer -> TypeInfo.basic(type, name, path, Kind.UnsafePointer);

                /* pointers */
                case Kind.Ptr -> {
                    var elem = toAddr(getLong(addr.add(Offsets.ptrtype.elem)));
                    queue.add(elem);
                    yield TypeInfo.indirect(type, name, path, Kind.Ptr, elem);
                }

                /* channels */
                case Kind.Chan -> {
                    var dir = getLong(addr.add(Offsets.chantype.dir));
                    var elem = toAddr(getLong(addr.add(Offsets.chantype.elem)));
                    queue.add(elem);
                    yield TypeInfo.chan(type, name, path, elem, dir);
                }

                /* slices */
                case Kind.Slice -> {
                    var elem = toAddr(getLong(addr.add(Offsets.slicetype.elem)));
                    queue.add(elem);
                    yield TypeInfo.indirect(type, name, path, Kind.Slice, elem);
                }

                /* fixed arrays */
                case Kind.Array -> {
                    var elem = toAddr(getLong(addr.add(Offsets.arraytype.elem)));
                    var slice = toAddr(getLong(addr.add(Offsets.arraytype.slice)));
                    queue.add(elem);
                    queue.add(slice);
                    yield TypeInfo.array(type, name, path, elem, getLong(addr.add(Offsets.arraytype.len)));
                }

                /* maps */
                case Kind.Map -> {
                    var key = toAddr(getLong(addr.add(Offsets.maptype.key)));
                    var elem = toAddr(getLong(addr.add(Offsets.maptype.elem)));
                    var bucket = toAddr(getLong(addr.add(Offsets.maptype.bucket)));
                    queue.add(key);
                    queue.add(elem);
                    queue.add(bucket);
                    yield TypeInfo.map(type, name, path, key, elem);
                }
            };

            /* add the type info */
            if (kind != Kind.Struct) {
                types.put(addr, rtti);
                setToolStatusMessage("Found type at %s: %s".formatted(addr, name), false);
                return;
            }

            /* offset for struct field slice */
            var fields = TFlags.isUncommon(tflag)
                ? Offsets.structtype_uncommon.ty + Offsets.structtype.fields
                : Offsets.structtype.fields;

            /* field table address and size */
            var fieldSeq = new ArrayList<StructField>();
            var fieldLen = getLong(addr.add(fields + Offsets.slice.len));
            var fieldTab = toAddr(getLong(addr.add(fields + Offsets.slice.data)));

            /* check field length */
            if (fieldLen < 0 || fieldLen > Integer.MAX_VALUE) {
                throw new AnalyzeException("field length out of bounds: %d".formatted(fieldLen));
            }

            /* process each field */
            for (int i = 0; i < fieldLen; i++) {
                var bp = i * Types.structfield.getLength();
                var tp = fieldTab.add(bp + Offsets.structfield.typ);
                var fp = fieldTab.add(bp + Offsets.structfield.name);
                var dp = fieldTab.add(bp + Offsets.structfield.offsetEmbed);

                /* resolve name, type and offset */
                var dx = getLong(dp) >>> 1;
                var ty = toAddr(getLong(tp));
                var ss = toAddr(getLong(fp));

                /* add to registry */
                queue.add(ty);
                fieldSeq.add(new StructField(parseNameAt(ss), parseTagAt(ss), ty, fp, ss, (int)dx));
            }

            /* add the struct */
            types.put(addr, TypeInfo.struct(type, name, path, size, fieldSeq));
            setToolStatusMessage("Found type at %s: %s".formatted(addr, name), false);
        }

        private void defineLabelAt(Address addr, String name) throws Exception {
            var as = new AddressSet(addr);
            var st = currentProgram.getSymbolTable();

            /* remove old lables before creating new one */
            st.getSymbols(as, SymbolType.LABEL, true).forEach(Symbol::delete);
            st.createLabel(addr, name, SourceType.ANALYSIS).setPrimary();
        }

        private void defineTypeLabel(Address addr, TypeInfo ti) throws Exception {
            var type = ti.type;
            var name = ti.deriveTypeName(addr, true);

            /* update monitor */
            monitor.setMessage("Define: " + name);
            monitor.incrementProgress(1);

            /* set type for the address range */
            DataUtilities.createData(
                currentProgram,
                addr,
                type,
                type.getLength(),
                ClearDataMode.CLEAR_ALL_CONFLICT_DATA
            );

            /* prepend with "type:" to identify that this is a type */
            if (!name.isEmpty()) {
                defineLabelAt(addr, "type:" + name);
            }

            /* add fields for structs */
            if (ti.kind != Kind.Struct) {
                return;
            }

            /* field table address and size */
            var fieldTy  = new ArrayDataType(Types.structfield, ti.fields.size(), Types.structfield.getLength());
            var fieldTab = toAddr(getLong(addr.add(Offsets.structtype.fields + Offsets.slice.data)));

            /* set type for the address range */
            DataUtilities.createData(
                currentProgram,
                fieldTab,
                fieldTy,
                fieldTy.getLength(),
                ClearDataMode.CLEAR_ALL_CONFLICT_DATA
            );

            /* mark the field table location */
            if (!name.isEmpty()) {
                defineLabelAt(fieldTab, "fields:" + name);
            }

            /* mark field names */
            for (var fv : ti.fields) {
                setEOLComment(fv.self, fv.name);
                defineLabelAt(fv.refs, "name:" + fv.name);
            }
        }

        private StructureDataType defineStruct(
            DataTypeManager        dtm,
            Map<Address, DataType> cache,
            Address                addr,
            String                 path,
            String                 name,
            long                   size
        ) throws Exception {
            var base = name;
            var lead = new ArrayList<>(Arrays.asList(StringUtils.split(path, '/')));

            // FIXME: this is essentially a hack, find a better way to do this.
            /* common slice types */
            if (name.startsWith("slice<")) {
                if (!path.isEmpty()) {
                    throw new AnalyzeException("slice types with package path");
                }
            }

            /* normal types with package name */
            else if (StringUtils.contains(name, '.')) {
                var pos = name.indexOf('.');
                var str = name.substring(0, pos);

                /* must be a valid name */
                if (!str.matches("[._\\w\\d]+")) {
                    throw new AnalyzeException("invalid type name: " + name);
                }

                /* move the package part into paths */
                base = name.substring(pos + 1);
                lead.add(str);
            }

            /* insert the fixed prefix */
            lead.add(0, "");
            lead.add(1, "auto_structs");
            lead.add(2, "go");

            /* create the type */
            var dest = new CategoryPath(StringUtils.join(lead, "/"));
            var type = new StructureDataType(dest, base, (int)size, dtm);

            /* put into cache right away */
            cache.put(addr, type);
            return type;
        }

        private void autoCreateTypes(
            DataTypeManager        dtm,
            Map<Address, TypeInfo> types,
            Map<Address, DataType> cache
        ) throws Exception {
            for (var k : types.keySet()) {
                autoCreateOneType(dtm, types, cache, k);
            }
        }

        private DataType autoCreateOneType(
            DataTypeManager        dtm,
            Map<Address, TypeInfo> types,
            Map<Address, DataType> cache,
            Address                addr
        ) throws Exception {
            var ty = cache.get(addr);
            var ti = types.get(addr);

            /* try cache lookups */
            if (ty != null) {
                return ty;
            }

            /* update monitor */
            monitor.setMessage("Create: " + ti.name);
            monitor.incrementProgress(1);

            /* select basic types */
            return switch (ti.kind) {
                default -> {
                    throw new AnalyzeException("invalid type kind %d".formatted(ti.kind));
                }

                /* simple types */
                case Kind.Bool          -> Types.bool;
                case Kind.Int           -> Types.i64;
                case Kind.Int8          -> Types.i8;
                case Kind.Int16         -> Types.i16;
                case Kind.Int32         -> Types.i32;
                case Kind.Int64         -> Types.i64;
                case Kind.Uint          -> Types.u64;
                case Kind.Uint8         -> Types.u8;
                case Kind.Uint16        -> Types.u16;
                case Kind.Uint32        -> Types.u32;
                case Kind.Uint64        -> Types.u64;
                case Kind.Uintptr       -> Types.uintptr;
                case Kind.Float32       -> Types.f32;
                case Kind.Float64       -> Types.f64;
                case Kind.Complex64     -> Types.complex64;
                case Kind.Complex128    -> Types.complex128;
                case Kind.String        -> Types.string;
                case Kind.UnsafePointer -> Types.void_p;

                /* implement these types as opaque pointers */
                case Kind.Chan      -> Types.void_p;
                case Kind.Func      -> Types.void_p;
                case Kind.Interface -> Types.iface;
                case Kind.Map       -> Types.void_p;

                /* structs */
                case Kind.Struct -> {
                    var zero = false;
                    var name = ti.deriveTypeName(addr, false);
                    var type = defineStruct(dtm, cache, addr, ti.path, name, ti.size);

                    /* special case of zero-sized struct with zero-sized fields */
                    if (ti.size == 0 && !ti.fields.isEmpty()) {
                        zero = true;
                        type.add(Types.u8, "_", null);
                    }

                    /* parse every field */
                    for (var fv : ti.fields) {
                        var ptr = fv.type;
                        var ret = autoCreateOneType(dtm, types, cache, ptr);

                        /* don't set fields for zero-sized structs */
                        if (!zero) {
                            type.replaceAtOffset(fv.offs, ret, ret.getLength(), fv.name, fv.tags);
                        }
                    }

                    /* add to data type manager */
                    dtm.addDataType(type, DataTypeConflictHandler.REPLACE_HANDLER);
                    yield type;
                }

                /* basic indirect types */
                case Kind.Ptr -> {
                    ty = autoCreateOneType(dtm, types, cache, ti.elem);
                    ty = new PointerDataType(ty, Types.void_p.getLength(), dtm);
                    cache.put(addr, ty);
                    yield ty;
                }

                /* slices */
                case Kind.Slice -> {
                    var name = ti.deriveTypeName(addr, false);
                    var type = defineStruct(dtm, cache, addr, ti.path, name, Types.slice.getLength());

                    /* parse element type */
                    ty = autoCreateOneType(dtm, types, cache, ti.elem);
                    ty = new PointerDataType(ty, Types.void_p.getLength(), dtm);

                    /* define the slice fields */
                    type.replace(0, ty, ty.getLength(), "data", null);
                    type.replace(1, Types.uintptr, Types.uintptr.getLength(), "len", null);
                    type.replace(2, Types.uintptr, Types.uintptr.getLength(), "cap", null);

                    /* add to data type manager */
                    dtm.addDataType(type, DataTypeConflictHandler.REPLACE_HANDLER);
                    yield type;
                }

                /* fixed arrays */
                case Kind.Array -> {
                    ty = autoCreateOneType(dtm, types, cache, ti.elem);
                    ty = new ArrayDataType(ty, (int)ti.size, ty.getLength(), dtm);
                    cache.put(addr, ty);
                    yield ty;
                }
            };
        }

        public void run() throws Exception {
            var buf = new ArrayList<Address>();
            var mod = Symbols.runtime.firstmoduledata.getAddress();

            /* iterate over all modules */
            while (mod.getOffset() != 0) {
                var ptr = toAddr(getLong(mod.add(Offsets.moduledata.types)));
                var tlp = toAddr(getLong(mod.add(Offsets.moduledata.typelinks + Offsets.slice.data)));
                var len = getInt(mod.add(Offsets.moduledata.typelinks + Offsets.slice.len));

                /* iterate over every type */
                for (int i = 0; i < len; i++) {
                    buf.add(ptr.add(getInt(tlp.add(i * 4))));
                }

                /* move to next module */
                setToolStatusMessage("Found %d types in module %s".formatted(len, mod), false);
                mod = toAddr(getLong(mod.add(Offsets.moduledata.next)));
            }

            /* set the monitor */
            monitor.initialize(buf.size());
            monitor.setMessage("Analyzing ...");
            monitor.setProgress(0);
            monitor.setShowProgressValue(true);

            /* bfs queue */
            var p = Address.NO_ADDRESS;
            var t = new HashMap<Address, TypeInfo>();
            var q = new ArrayDeque<Address>();

            /* scan all the types */
            for (int i = 0; i < buf.size() && !monitor.isCancelled(); i++) {
                q.add(buf.get(i));
                monitor.setProgress(i);

                /* bfs the reference tree */
                while (!q.isEmpty() && !monitor.isCancelled()) {
                    if (!t.containsKey((p = q.removeFirst()))) {
                        scanTypes(p, q, t);
                    }
                }
            }

            /* check for cancellation */
            if (monitor.isCancelled()) {
                return;
            }

            /* link all type references */
            for (var v : t.values()) {
                if (monitor.isCancelled()) break;
                if (v.mkey != null)        v.setKeyType(t.get(v.mkey));
                if (v.elem != null)        v.setElemType(t.get(v.elem));
            }

            /* check for cancellation */
            if (monitor.isCancelled()) {
                return;
            }

            /* reset monitor */
            monitor.initialize(t.size());
            monitor.setMessage("Defining ...");
            monitor.setProgress(0);
            monitor.setShowProgressValue(true);

            /* define lables for every type */
            for (var v : t.entrySet()) {
                if (!monitor.isCancelled()) {
                    defineTypeLabel(v.getKey(), v.getValue());
                } else {
                    break;
                }
            }

            /* check for cancellation or no structure creation */
            if (monitor.isCancelled() || !askYesNo("Go", "Create types for this program?")) {
                return;
            }

            /* start a DTM transaction */
            var dtc = new HashMap<Address, DataType>();
            var dtm = currentProgram.getDataTypeManager();
            var dtx = dtm.startTransaction("Auto create types");

            /* reset monitor */
            monitor.initialize(t.size());
            monitor.setMessage("Creating ...");
            monitor.setProgress(0);
            monitor.setShowProgressValue(true);

            /* create all types */
            try {
                autoCreateTypes(dtm, t, dtc);
                dtm.endTransaction(dtx, !monitor.isCancelled());
            } catch (Exception e) {
                dtm.endTransaction(dtx, false);
                throw e;
            }
        }
    }

    public void run() throws Exception {
        new Analyzer().run();
        setToolStatusMessage("Analyze completed.", true);
    }
}
