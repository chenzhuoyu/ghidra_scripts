// Analyze Go type information and create type.
//@author
//@category Go
//@keybinding F9
//@menupath
//@toolbar

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.stream.Stream;

import aQute.bnd.unmodifiable.Lists;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
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
    public final Address           elem;
    public final Address           mkey;
    public final List<StructField> fields;

    private TypeInfo(String name, int kind, long size, Address mkey, Address elem, Collection<StructField> fields) {
        this.kind   = kind;
        this.size   = size;
        this.name   = name;
        this.elem   = elem;
        this.mkey   = mkey;
        this.fields = fields == null ? null : Lists.copyOf(fields);
    }

    public static TypeInfo map(String name, Address key, Address elem) {
        return new TypeInfo(name, Kind.Map, -1, key, elem, null);
    }

    public static TypeInfo basic(String name, int kind) {
        return new TypeInfo(name, kind, -1, null, null, null);
    }

    public static TypeInfo array(String name, Address elem, long size) {
        return new TypeInfo(name, Kind.Array, size, null, elem, null);
    }

    public static TypeInfo struct(String name, long size, Collection<StructField> fields) {
        return new TypeInfo(name, Kind.Struct, size, null, null, fields);
    }

    public static TypeInfo indirect(String name, int kind, Address elem) {
        return new TypeInfo(name, kind, -1, null, elem, null);
    }
}

final class StructField {
    public final int     offs;
    public final String  name;
    public final Address type;

    public StructField(String name, Address type, int offs) {
        this.name = name;
        this.type = type;
        this.offs = offs;
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

        private void runAtAddress(Address addr, Queue<Address> queue, Map<Address, TypeInfo> types) throws Exception {
            var name  = "";
            var orig  = "";
            var size  = getLong(addr.add(Offsets.rtype.size));
            var kind  = getByte(addr.add(Offsets.rtype.kind)) & 0x1f;
            var tflag = getByte(addr.add(Offsets.rtype.tflag));

            /* select new block type */
            var type = switch (kind) {
                case Kind.Bool          -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Int           -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Int8          -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Int16         -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Int32         -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Int64         -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Uint          -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Uint8         -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Uint16        -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Uint32        -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Uint64        -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Uintptr       -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Float32       -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Float64       -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Complex64     -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Complex128    -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Array         -> TFlags.isUncommon(tflag) ? Types.arraytype_uncommon     : Types.arraytype;
                case Kind.Chan          -> TFlags.isUncommon(tflag) ? Types.chantype_uncommon      : Types.chantype;
                case Kind.Func          -> TFlags.isUncommon(tflag) ? Types.functype_uncommon      : Types.functype;
                case Kind.Interface     -> TFlags.isUncommon(tflag) ? Types.interfacetype_uncommon : Types.interfacetype;
                case Kind.Map           -> TFlags.isUncommon(tflag) ? Types.maptype_uncommon       : Types.maptype;
                case Kind.Ptr           -> TFlags.isUncommon(tflag) ? Types.ptrtype_uncommon       : Types.ptrtype;
                case Kind.Slice         -> TFlags.isUncommon(tflag) ? Types.slicetype_uncommon     : Types.slicetype;
                case Kind.String        -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                case Kind.Struct        -> TFlags.isUncommon(tflag) ? Types.structtype_uncommon    : Types.structtype;
                case Kind.UnsafePointer -> TFlags.isUncommon(tflag) ? Types.rtype_uncommon         : Types.rtype;
                default                 -> throw new AnalyzeException("invalid type kind %d".formatted(kind));
            };

            /* select uncommon offset, if any */
            var uncommon = switch (kind) {
                case Kind.Bool          -> Offsets.rtype_uncommon.un;
                case Kind.Int           -> Offsets.rtype_uncommon.un;
                case Kind.Int8          -> Offsets.rtype_uncommon.un;
                case Kind.Int16         -> Offsets.rtype_uncommon.un;
                case Kind.Int32         -> Offsets.rtype_uncommon.un;
                case Kind.Int64         -> Offsets.rtype_uncommon.un;
                case Kind.Uint          -> Offsets.rtype_uncommon.un;
                case Kind.Uint8         -> Offsets.rtype_uncommon.un;
                case Kind.Uint16        -> Offsets.rtype_uncommon.un;
                case Kind.Uint32        -> Offsets.rtype_uncommon.un;
                case Kind.Uint64        -> Offsets.rtype_uncommon.un;
                case Kind.Uintptr       -> Offsets.rtype_uncommon.un;
                case Kind.Float32       -> Offsets.rtype_uncommon.un;
                case Kind.Float64       -> Offsets.rtype_uncommon.un;
                case Kind.Complex64     -> Offsets.rtype_uncommon.un;
                case Kind.Complex128    -> Offsets.rtype_uncommon.un;
                case Kind.Array         -> Offsets.arraytype_uncommon.un;
                case Kind.Chan          -> Offsets.chantype_uncommon.un;
                case Kind.Func          -> Offsets.functype_uncommon.un;
                case Kind.Interface     -> Offsets.interfacetype_uncommon.un;
                case Kind.Map           -> Offsets.maptype_uncommon.un;
                case Kind.Ptr           -> Offsets.ptrtype_uncommon.un;
                case Kind.Slice         -> Offsets.slicetype_uncommon.un;
                case Kind.String        -> Offsets.rtype_uncommon.un;
                case Kind.Struct        -> Offsets.structtype_uncommon.un;
                case Kind.UnsafePointer -> Offsets.rtype_uncommon.un;
                default                 -> throw new AnalyzeException("invalid type kind %d".formatted(kind));
            };

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

            /* add package path for uncommon types */
            if (TFlags.isUncommon(tflag)) {
                var prog = currentProgram.getName() + "/";
                var offs = getInt(addr.add(uncommon + Offsets.uncommontype.pkgpath));
                var path = parseNameAt(resolveOffset(addr, offs));

                /* remove leading slash if any */
                if (path.startsWith("/")) {
                    path = path.substring(1);
                }

                /* remove program name prefix if any */
                if (path.startsWith(prog)) {
                    path = path.substring(prog.length());
                }

                /* remove vendor prefixes if any */
                if (path.startsWith("vendor/")) {
                    path = path.substring(7);
                }

                /* don't add empty or single-level package path */
                if (path.contains("/")) {
                    name = path + ":" + name;
                }
            }

            /* spaces are invalid symbol characters */
            orig = name;
            name = name.replaceAll(" ", "_");

            /* set type for the address range */
            monitor.setMessage("Metadata: " + orig);
            DataUtilities.createData(currentProgram, addr, type, type.getLength(), ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

            /* prepend with "type:" to identify that this is a type */
            if (str != 0) {
                createLabel(addr, "type:" + name, true, SourceType.ANALYSIS);
            }

            /* construct type info */
            var rtti = switch (kind) {
                default -> {
                    throw new AnalyzeException("invalid type kind %d".formatted(kind));
                }

                /* simple types, we treat all funcs as `void *` and all ifaces as `iface` */
                case Kind.Bool          -> TypeInfo.basic(name, Kind.Bool);
                case Kind.Int           -> TypeInfo.basic(name, Kind.Int);
                case Kind.Int8          -> TypeInfo.basic(name, Kind.Int8);
                case Kind.Int16         -> TypeInfo.basic(name, Kind.Int16);
                case Kind.Int32         -> TypeInfo.basic(name, Kind.Int32);
                case Kind.Int64         -> TypeInfo.basic(name, Kind.Int64);
                case Kind.Uint          -> TypeInfo.basic(name, Kind.Uint);
                case Kind.Uint8         -> TypeInfo.basic(name, Kind.Uint8);
                case Kind.Uint16        -> TypeInfo.basic(name, Kind.Uint16);
                case Kind.Uint32        -> TypeInfo.basic(name, Kind.Uint32);
                case Kind.Uint64        -> TypeInfo.basic(name, Kind.Uint64);
                case Kind.Uintptr       -> TypeInfo.basic(name, Kind.Uintptr);
                case Kind.Float32       -> TypeInfo.basic(name, Kind.Float32);
                case Kind.Float64       -> TypeInfo.basic(name, Kind.Float64);
                case Kind.Complex64     -> TypeInfo.basic(name, Kind.Complex64);
                case Kind.Complex128    -> TypeInfo.basic(name, Kind.Complex128);
                case Kind.Func          -> TypeInfo.basic(name, Kind.Func);
                case Kind.Interface     -> TypeInfo.basic(name, Kind.Interface);
                case Kind.String        -> TypeInfo.basic(name, Kind.String);
                case Kind.UnsafePointer -> TypeInfo.basic(name, Kind.UnsafePointer);
                case Kind.Struct        -> null;

                /* pointers */
                case Kind.Ptr -> {
                    var elem = toAddr(getLong(addr.add(Offsets.ptrtype.elem)));
                    queue.add(elem);
                    yield TypeInfo.indirect(name, Kind.Ptr, elem);
                }

                /* channels */
                case Kind.Chan -> {
                    var elem = toAddr(getLong(addr.add(Offsets.chantype.elem)));
                    queue.add(elem);
                    yield TypeInfo.indirect(name, Kind.Chan, elem);
                }

                /* slices */
                case Kind.Slice -> {
                    var elem = toAddr(getLong(addr.add(Offsets.slicetype.elem)));
                    queue.add(elem);
                    yield TypeInfo.indirect(name, Kind.Slice, elem);
                }

                /* fixed arrays */
                case Kind.Array -> {
                    var elem = toAddr(getLong(addr.add(Offsets.arraytype.elem)));
                    var slice = toAddr(getLong(addr.add(Offsets.arraytype.slice)));
                    queue.add(elem);
                    queue.add(slice);
                    yield TypeInfo.array(name, elem, getLong(addr.add(Offsets.arraytype.len)));
                }

                /* maps */
                case Kind.Map -> {
                    var key = toAddr(getLong(addr.add(Offsets.maptype.key)));
                    var elem = toAddr(getLong(addr.add(Offsets.maptype.elem)));
                    var bucket = toAddr(getLong(addr.add(Offsets.maptype.bucket)));
                    queue.add(key);
                    queue.add(elem);
                    queue.add(bucket);
                    yield TypeInfo.map(name, key, elem);
                }
            };

            /* add the type info */
            if (kind != Kind.Struct) {
                types.put(addr, rtti);
                setToolStatusMessage("Found type at %s: %s".formatted(addr, orig), false);
                return;
            }

            /* offset for struct field slice */
            var fields = TFlags.isUncommon(tflag)
                ? Offsets.structtype_uncommon.ty + Offsets.structtype.fields
                : Offsets.structtype.fields;

            /* field table address and size */
            var fieldLen = getLong(addr.add(fields + Offsets.slice.len));
            var fieldTab = toAddr(getLong(addr.add(fields + Offsets.slice.data)));

            /* check field length */
            if (fieldLen < 0 || fieldLen > Integer.MAX_VALUE) {
                throw new AnalyzeException("field length out of bounds: %d".formatted(fieldLen));
            }

            /* create the array type */
            var typed = new ArrayList<StructField>();
            var itemLen = Types.structfield.getLength();
            var fieldsTy = new ArrayDataType(Types.structfield, (int)fieldLen, itemLen);

            /* set type for the address range */
            DataUtilities.createData(
                currentProgram,
                fieldTab,
                fieldsTy,
                fieldsTy.getLength(),
                ClearDataMode.CLEAR_ALL_CONFLICT_DATA
            );

            /* mark the field table location */
            if (str != 0) {
                createLabel(fieldTab, "fields:" + name, true, SourceType.ANALYSIS);
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
                var fn = parseNameAt(ss);

                /* add field type and name */
                createLabel(ss, "name:" + fn, true, SourceType.ANALYSIS);
                setEOLComment(fp, fn);

                /* add to registry */
                queue.add(ty);
                typed.add(new StructField(fn, ty, (int)dx));
            }

            /* add the struct */
            types.put(addr, TypeInfo.struct(name, size, typed));
            setToolStatusMessage("Found type at %s: %s".formatted(addr, orig), false);
        }

        private StructureDataType addStruct(
            DataTypeManager        dtm,
            Map<Address, DataType> cache,
            Address                addr,
            String                 name,
            long                   size
        ) {
            var path = new CategoryPath("/auto_structs/go");
            var type = new StructureDataType(path, name, (int)size, dtm);
            cache.put(addr, type);
            return type;
        }

        private void autoCreateTypes(
            DataTypeManager        dtm,
            Map<Address, TypeInfo> types,
            Map<Address, DataType> cache
        ) throws Exception {
            monitor.initialize(types.size());
            monitor.setMessage("Creating ...");
            monitor.setShowProgressValue(true);

            /* create every type */
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
                    var type = addStruct(dtm, cache, addr, ti.name, ti.size);

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
                            type.replaceAtOffset(fv.offs, ret, ret.getLength(), fv.name, null);
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
                    var size = Types.slice.getLength();
                    var type = addStruct(dtm, cache, addr, ti.name, size);

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

            /* set the monitor bar */
            monitor.initialize(buf.size());
            monitor.setMessage("Analyzing ...");
            monitor.setShowProgressValue(true);

            /* bfs queue */
            var p = Address.NO_ADDRESS;
            var t = new HashMap<Address, TypeInfo>();
            var q = new ArrayDeque<Address>();

            /* process every type */
            for (int i = 0; i < buf.size() && !monitor.isCancelled(); i++) {
                q.add(buf.get(i));
                monitor.setProgress(i);

                /* bfs the reference tree */
                while (!q.isEmpty() && !monitor.isCancelled()) {
                    if (!t.containsKey((p = q.removeFirst()))) {
                        runAtAddress(p, q, t);
                    }
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
