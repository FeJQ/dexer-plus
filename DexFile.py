import io
import mmap
import struct
from enum import Enum

import leb128

DEX_MAGIC = bytes("dex\n", "utf-8")
DEX_MAGIC_VERS_API_13 = bytes("035\0", "utf-8")
DEX_MAGIC_VERS = bytes("036\0", "utf-8")
DEX_MAGIC_VERS_37 = bytes("037\0", "utf-8")
#
# 160-bit SHA-1 digest
#
class SHA1Digest(Enum):
    kSHA1DigestLen = 20
    kSHA1DigestOutputLen = kSHA1DigestLen * 2 + 1

#
# general constants
#
class General(Enum):
    kDexEndianConstant = 0x1234567     # the endianness indicator
    kDexNoIndex = 0xffffffff           # not a valid index value



class PrimitiveType(Enum):
    PRIM_NOT = 0 #value is a reference type, not a primitive type
    PRIM_VOID = 1
    PRIM_BOOLEAN = 2
    PRIM_BYTE = 3
    PRIM_SHORT = 4
    PRIM_CHAR = 5
    PRIM_INT = 6
    PRIM_LONG = 7
    PRIM_FLOAT = 8
    PRIM_DOUBLE = 9

#
# access flags and masks; the "standard" ones are all <= 0x4000
#
# Note: There are related declarations in vm/oo/Object.h in the ClassFlags
# enum.
#
class AccessFlags(Enum):
    ACC_PUBLIC = 0x00000001       # class, field, method, ic
    ACC_PRIVATE = 0x00000002      # field, method, ic
    ACC_PROTECTED = 0x00000004      # field, method, ic
    ACC_STATIC = 0x00000008      # field, method, ic
    ACC_FINAL = 0x00000010       # class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020       # method (only allowed on natives)
    ACC_SUPER = 0x00000020       # class (not used in Dalvik)
    ACC_VOLATILE = 0x00000040       # field
    ACC_BRIDGE = 0x00000040       # method (1.5)
    ACC_TRANSIENT = 0x00000080       # field
    ACC_VARARGS = 0x00000080      # method (1.5)
    ACC_NATIVE = 0x00000100       # method
    ACC_INTERFACE = 0x00000200       # class, ic
    ACC_ABSTRACT = 0x00000400       # class, method, ic
    ACC_STRICT = 0x00000800       # method
    ACC_SYNTHETIC = 0x00001000       # field, method, ic
    ACC_ANNOTATION = 0x00002000       # class, ic (1.5)
    ACC_ENUM = 0x00004000       # class, field, ic (1.5)
    ACC_CONSTRUCTOR = 0x00010000       # method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED = 0x00020000       # method (Dalvik only)
    ACC_CLASS_MASK = (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM)
    ACC_INNER_CLASS_MASK = (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC)
    ACC_FIELD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM)
    ACC_METHOD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR | ACC_DECLARED_SYNCHRONIZED)

#
# annotation constants
#
class Annotation(Enum):
    kDexVisibilityBuild = 0x00     # annotation visibility
    kDexVisibilityRuntime = 0x01
    kDexVisibilitySystem = 0x02
    kDexAnnotationByte = 0x00
    kDexAnnotationShort = 0x02
    kDexAnnotationChar = 0x03
    kDexAnnotationInt = 0x04
    kDexAnnotationLong = 0x06
    kDexAnnotationFloat = 0x10
    kDexAnnotationDouble = 0x11
    kDexAnnotationMethodType = 0x15
    kDexAnnotationMethodHandle = 0x16
    kDexAnnotationString = 0x17
    kDexAnnotationType = 0x18
    kDexAnnotationField = 0x19
    kDexAnnotationMethod = 0x1a
    kDexAnnotationEnum = 0x1b
    kDexAnnotationArray = 0x1c
    kDexAnnotationAnnotation = 0x1d
    kDexAnnotationNull = 0x1e
    kDexAnnotationBoolean = 0x1f
    kDexAnnotationValueTypeMask = 0x1f     # low 5 bits
    kDexAnnotationValueArgShift = 5

#
# map item type codes
#
class ItemType(Enum):
    kDexTypeHeaderItem = 0x0000
    kDexTypeStringIdItem = 0x0001
    kDexTypeTypeIdItem = 0x0002
    kDexTypeProtoIdItem = 0x0003
    kDexTypeFieldIdItem = 0x0004
    kDexTypeMethodIdItem = 0x0005
    kDexTypeClassDefItem = 0x0006
    kDexTypeCallSiteIdItem = 0x0007
    kDexTypeMethodHandleItem = 0x0008
    kDexTypeMapList = 0x1000
    kDexTypeTypeList = 0x1001
    kDexTypeAnnotationSetRefList = 0x1002
    kDexTypeAnnotationSetItem = 0x1003
    kDexTypeClassDataItem = 0x2000
    kDexTypeCodeItem = 0x2001
    kDexTypeStringDataItem = 0x2002
    kDexTypeDebugInfoItem = 0x2003
    kDexTypeAnnotationItem = 0x2004
    kDexTypeEncodedArrayItem = 0x2005
    kDexTypeAnnotationsDirectoryItem = 0x2006

class ChunkCodes(Enum):
    kDexChunkClassLookup = 0x434c4b50 #CLKP
    kDexChunkRegisterMaps = 0x524d4150 #RMAP
    kDexChunkEnd = 0x41454e44 #AEND

class DebugInfoOpCodes(Enum):
    DBG_END_SEQUENCE = 0x00
    DBG_ADVANCE_PC = 0x01
    DBG_ADVANCE_LINE = 0x02
    DBG_START_LOCAL = 0x03
    DBG_START_LOCAL_EXTENDED = 0x04
    DBG_END_LOCAL = 0x05
    DBG_RESTART_LOCAL = 0x06
    DBG_SET_PROLOGUE_END = 0x07
    DBG_SET_EPILOGUE_BEGIN = 0x08
    DBG_SET_FILE = 0x09
    DBG_FIRST_SPECIAL = 0x0a
    DBG_LINE_BASE = -4
    DBG_LINE_RANGE = 15




class FileReader:
    def __init__(self, file):
        self.file_stream = file

    def read_bytes(self, size):
        value = self.file_stream[0: size]
        self.file_stream = self.file_stream[size:]
        return value

    def read_int8(self):
        value = struct.unpack("c", self.file_stream[0])[0]
        self.file_stream = self.file_stream[1:]
        return value

    def read_dword(self):
        value = struct.unpack("<L", self.file_stream[0:4])[0]
        self.file_stream = self.file_stream[4:]
        return value

    def read_word(self):
        value = struct.unpack("<h", self.file_stream[0:2])[0]
        self.file_stream = self.file_stream[2:]
        return value

    def read_cstring(self):
        string_size = 0
        for i in range(len(self.file_stream)):
            if self.file_stream[i] != 0:
                string_size += 1
            else:
                break
        return self.file_stream[0:string_size].decode()


class DexFile:
    pass

class DexString:
    def __init__(self, dex_file:DexFile, string_idx:int):
        if string_idx < 0 or string_idx >= dex_file.string_ids_size:
            raise Exception("string idx is out of range:" + string_idx)
        self.dex_file = dex_file
        self.string_idx = string_idx

    def get_string(self) -> str:
        string_off = FileReader(self.dex_file.data[self.dex_file.string_ids_off + self.string_idx * 4:]).read_dword()
        string_ptr = self.dex_file.data[string_off:]
        string_info = leb128.u.decode_reader(io.BytesIO(string_ptr))
        # MUTF-8编码的 "你好" 对应在这里是 "02 e4 bd a0 e5 a5 bd 00"
        # 02 是uleb128编码的数, 代表字符个数, 在本例中,"你好" 的字符个数是2

        # uleb128_char_count 代表字符个数,上面"你好"的例子中为 2
        uleb128_char_count = string_info[0]

        # uleb128_byte_size 代表这个uleb128数所占的字节数, 上面"你好"的例子中为 1
        uleb128_byte_size = string_info[1]

        return FileReader(string_ptr[uleb128_byte_size:]).read_cstring()

class DexType:
    def __init__(self, dex_file:DexFile, type_idx:int):
        if type_idx < 0 or type_idx >= dex_file.type_ids_size:
            raise Exception("type_idx is out of range:" + type_idx)
        self.dex_file = dex_file
        reader = FileReader(dex_file.data[dex_file.type_ids_off + type_idx * 4:])
        self.type_name_idx = reader.read_dword()

    def get_name(self) -> DexString:
        return DexString(self.dex_file).get_string(self.type_name_idx)

class DexProto:
    def __init__(self, dex_file:DexFile, proto_idx :int):
        if proto_idx <0 or proto_idx >= dex_file.proto_ids_size:
            raise Exception("proto_idx is out of range:" + proto_idx)
        self.dex_file = dex_file
        reader = FileReader(dex_file.data[dex_file.proto_ids_off + proto_idx * 4:])
        self.shorty_idx = reader.read_dword()
        self.return_type_idx = reader.read_dword()
        self.parameters_off = reader.read_dword()

    def get_shorty(self) -> DexString:
        return DexString(self.dex_file, self.shorty_idx)

    def get_return_type(self):
        return DexString(self.dex_file, self.return_type_idx)

    def get_parameter_list(self)->list:
        params = []
        reader = FileReader(self.dex_file.data[self.parameters_off:])
        parameter_count = reader.read_dword()
        for i in range(parameter_count):
            params.append(DexType(self.dex_file, reader.read_word()))
        return params

class DexField:
    def __int__(self, dex_file: DexFile, field_id:int):
        if field_id < 0 or field_id >= dex_file.field_ids_size:
            raise Exception("field_id is out of range")
        self.dex_file = dex_file
        reader = FileReader(dex_file.data[dex_file.field_ids_off + field_id*8:])
        self.class_idx = reader.read_word()
        self.type_idx = reader.read_word()
        self.name_idx = reader.read_dword()

    def get_class(self):
        pass

    def get_type(self):
        return DexType(self.dex_file, self.type_idx)

    def get_name(self):
        return DexString(self.dex_file, self.name_idx)


class DexClass:
    class DexClassData:
        def __init__(self,dex_file,  class_data_off:int):
            if class_data_off <0 or class_data_off>=dex_file.file_size:
                raise Exception("class_data_off is out of range")
            self.class_data_off = class_data_off

            reader = FileReader(dex_file.data[class_data_off:])
            static_fields_size = reader.read_bytes(1)

        def get_static_fields_size(self):
            pass

        def get_instance_fields_size(self):
            pass

        def get_direct_methods_size(self):
            pass

        def get_virtual_methods_size(self):
            pass




    def __init__(self,dex_file:DexFile, class_idx:int):
        if class_idx < 0 or class_idx >= dex_file.field_ids_size:
            raise Exception("class_idx is out of range")
        self.dex_file = dex_file
        reader = FileReader(dex_file.data[dex_file.class_defs_off + class_idx * 32:])
        self.class_type_idx = reader.read_dword()
        self.access_flags = reader.read_dword()
        self.super_class_idx = reader.read_dword()
        self.interfaces_off = reader.read_dword()
        self.source_file_idx = reader.read_dword()
        self.annotations_off = reader.read_dword()
        self.class_data_off = reader.read_dword()
        self.static_values_off = reader.read_dword()



class DexMethod:
    def __init__(self, dex_file:DexFile, method_idx:int):
        self.dex_file = dex_file
        self.class_idx = 0
        self.proto_idx = 0
        self.name_idx = 0

    def get_class(self) -> DexClass:
        pass

    def get_proto(self) -> DexProto:
        return DexProto(self.dex_file, self.proto_idx)

    def get_name(self) -> DexString:
        return DexString(self.dex_file, self.name_idx)

class




class DexFile:
    def __init__(self, dex_path: str):
        with open(dex_path, 'rb') as f:
            self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        self.reader = FileReader(self.data)

        # parse dex header
        self.magic = self.reader.read_bytes(8)
        self.checksum = self.reader.read_dword()
        self.signature = self.reader.read_bytes(SHA1Digest.kSHA1DigestLen.value)
        self.file_size = self.reader.read_dword()
        self.header_size = self.reader.read_dword()
        self.endian_tag = self.reader.read_dword()
        self.link_size = self.reader.read_dword()
        self.link_off = self.reader.read_dword()
        self.map_off = self.reader.read_dword()
        self.string_ids_size = self.reader.read_dword()
        self.string_ids_off = self.reader.read_dword()
        self.type_ids_size = self.reader.read_dword()
        self.type_ids_off = self.reader.read_dword()
        self.proto_ids_size = self.reader.read_dword()
        self.proto_ids_off = self.reader.read_dword()
        self.field_ids_size = self.reader.read_dword()
        self.field_ids_off = self.reader.read_dword()
        self.method_ids_size = self.reader.read_dword()
        self.method_ids_off = self.reader.read_dword()
        self.class_defs_size = self.reader.read_dword()
        self.class_defs_off = self.reader.read_dword()
        self.data_size = self.reader.read_dword()
        self.data_off = self.reader.read_dword()

        if self.is_validity():
            self.get_string(0)
            a = self.get_string(self.get_type(1))
            b = 1

    def is_validity(self):
        if self.magic[0:4] != DEX_MAGIC:
            return False
        if self.magic[4:8] != DEX_MAGIC_VERS and self.magic[4:8] != DEX_MAGIC_VERS_API_13 and self.magic[4:8] != DEX_MAGIC_VERS_37:
            return False
        return True


    def get_method(self, method_idx):
        if method_idx < 0 or method_idx >= self.method_ids_size:
            return None
        reader = FileReader(self.data[self.method_ids_off + method_idx * 8:])
        method = DexMethod(self)
        method.class_idx = reader.read_word()
        method.proto_idx = reader.read_word()
        method.name_idx = reader.read_dword()
        return method


    def get_type(self, type_idx):
        """
        获取索引为 type_idx 的type描述, 如I LHello; Ljava/io/PrintStream等, 返回string_idx
        :param type_idx:类型索引
        :return:string_idx
        """
        if type_idx < 0 or type_idx >= self.type_ids_size:
            return None
        reader = FileReader(self.data[self.type_ids_off + type_idx * 4:])
        return reader.read_dword()

    def get_proto(self, proto_idx):
        if proto_idx < 0 or proto_idx >= self.proto_ids_size:
            return None
        reader = FileReader(self.data[self.proto_ids_off + proto_idx * 12:])
        proto = []
        proto["shorty_idx"] = reader.read_dword()
        proto["return_type_idx"] = reader.read_dword()
        proto["parameters_off"] = reader.read_dword()
        return proto




f = DexFile(R"D:\Users\Desktop\Hello.dex")


