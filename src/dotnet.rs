// Read AssemblyRef / ModuleRef from CLI (.NET) metadata.
// Derived from the "-assemblyrefs" / "-modulerefs" options of Dependencies.exe.
// An IL-only assembly has no native import table, so this is the only path that
// shows its dependencies. Walks the #~ stream following the ECMA-335 II.22
// table layouts.

use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct AssemblyRef {
    pub name: String,
    pub version: String,
    pub culture: Option<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct ClrInfo {
    pub assembly_refs: Vec<AssemblyRef>,
    pub module_refs: Vec<String>,
}

struct Tables<'a> {
    data: &'a [u8],
    pos: usize,
    rows: [u32; 64],
    str_wide: bool,
    guid_wide: bool,
    blob_wide: bool,
    strings: &'a [u8],
}

const TABLE_MODULE: usize = 0x00;
const TABLE_TYPE_REF: usize = 0x01;
const TABLE_TYPE_DEF: usize = 0x02;
const TABLE_FIELD: usize = 0x04;
const TABLE_METHOD_DEF: usize = 0x06;
const TABLE_PARAM: usize = 0x08;
const TABLE_MEMBER_REF: usize = 0x0a;
const TABLE_DECL_SECURITY: usize = 0x0e;
const TABLE_STANDALONE_SIG: usize = 0x11;
const TABLE_EVENT: usize = 0x14;
const TABLE_PROPERTY: usize = 0x17;
const TABLE_MODULE_REF: usize = 0x1a;
const TABLE_TYPE_SPEC: usize = 0x1b;
const TABLE_ASSEMBLY: usize = 0x20;
const TABLE_ASSEMBLY_REF: usize = 0x23;
const TABLE_FILE: usize = 0x26;
const TABLE_EXPORTED_TYPE: usize = 0x27;
const TABLE_MANIFEST_RESOURCE: usize = 0x28;
const TABLE_GENERIC_PARAM: usize = 0x2a;
const TABLE_METHOD_SPEC: usize = 0x2b;
const TABLE_GENERIC_PARAM_CONSTRAINT: usize = 0x2c;

impl<'a> Tables<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = self
            .data
            .get(self.pos..self.pos + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .unwrap_or(0);
        self.pos += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = self
            .data
            .get(self.pos..self.pos + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0);
        self.pos += 4;
        v
    }

    fn index(&mut self, wide: bool) -> u32 {
        if wide {
            self.u32()
        } else {
            self.u16() as u32
        }
    }

    fn string(&mut self) -> String {
        let off = self.index(self.str_wide) as usize;
        let rest = match self.strings.get(off..) {
            Some(r) => r,
            None => return String::new(),
        };
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(&rest[..end]).into_owned()
    }

    fn skip_string(&mut self) {
        self.index(self.str_wide);
    }
    fn skip_guid(&mut self) {
        self.index(self.guid_wide);
    }
    fn skip_blob(&mut self) {
        self.index(self.blob_wide);
    }

    /// Simple table index width (4 bytes once a table holds more than 65535 rows)
    fn simple_wide(&self, table: usize) -> bool {
        self.rows[table] >= 0x10000
    }
    fn skip_simple(&mut self, table: usize) {
        let wide = self.simple_wide(table);
        self.index(wide);
    }

    /// Coded index width: 4 bytes when a referenced table reaches (1 << (16 - tag_bits)) rows
    fn coded_wide(&self, tag_bits: u32, tables: &[usize]) -> bool {
        let limit = 1u32 << (16 - tag_bits);
        tables.iter().any(|&t| self.rows[t] >= limit)
    }
    fn skip_coded(&mut self, tag_bits: u32, tables: &[usize]) {
        let wide = self.coded_wide(tag_bits, tables);
        self.index(wide);
    }
}

const TYPE_DEF_OR_REF: &[usize] = &[TABLE_TYPE_DEF, TABLE_TYPE_REF, TABLE_TYPE_SPEC];
const HAS_CONSTANT: &[usize] = &[TABLE_FIELD, TABLE_PARAM, TABLE_PROPERTY];
const HAS_CUSTOM_ATTRIBUTE: &[usize] = &[
    TABLE_METHOD_DEF,
    TABLE_FIELD,
    TABLE_TYPE_REF,
    TABLE_TYPE_DEF,
    TABLE_PARAM,
    0x09,
    TABLE_MEMBER_REF,
    TABLE_MODULE,
    TABLE_DECL_SECURITY,
    TABLE_PROPERTY,
    TABLE_EVENT,
    TABLE_STANDALONE_SIG,
    TABLE_MODULE_REF,
    TABLE_TYPE_SPEC,
    TABLE_ASSEMBLY,
    TABLE_ASSEMBLY_REF,
    TABLE_FILE,
    TABLE_EXPORTED_TYPE,
    TABLE_MANIFEST_RESOURCE,
    TABLE_GENERIC_PARAM,
    TABLE_GENERIC_PARAM_CONSTRAINT,
    TABLE_METHOD_SPEC,
];
const HAS_FIELD_MARSHAL: &[usize] = &[TABLE_FIELD, TABLE_PARAM];
const HAS_DECL_SECURITY: &[usize] = &[TABLE_TYPE_DEF, TABLE_METHOD_DEF, TABLE_ASSEMBLY];
const MEMBER_REF_PARENT: &[usize] = &[
    TABLE_TYPE_DEF,
    TABLE_TYPE_REF,
    TABLE_MODULE_REF,
    TABLE_METHOD_DEF,
    TABLE_TYPE_SPEC,
];
const HAS_SEMANTICS: &[usize] = &[TABLE_EVENT, TABLE_PROPERTY];
const METHOD_DEF_OR_REF: &[usize] = &[TABLE_METHOD_DEF, TABLE_MEMBER_REF];
const MEMBER_FORWARDED: &[usize] = &[TABLE_FIELD, TABLE_METHOD_DEF];
const CUSTOM_ATTRIBUTE_TYPE: &[usize] = &[TABLE_METHOD_DEF, TABLE_MEMBER_REF];
const RESOLUTION_SCOPE: &[usize] = &[
    TABLE_MODULE,
    TABLE_MODULE_REF,
    TABLE_ASSEMBLY_REF,
    TABLE_TYPE_REF,
];

/// Read assembly and module references from PE bytes that carry a CLI header.
pub fn read(bytes: &[u8], file: &crate::pe::PeFile) -> Option<ClrInfo> {
    let meta_rva = file.clr_metadata_rva;
    if meta_rva == 0 {
        return None;
    }
    let meta_off = file.rva_to_offset(meta_rva)?;
    let meta = bytes.get(meta_off..)?;

    if meta.get(0..4)? != [0x42, 0x53, 0x4a, 0x42] {
        return None; // "BSJB"
    }
    let version_len = u32::from_le_bytes(meta.get(12..16)?.try_into().ok()?) as usize;
    let mut p = 16 + version_len;
    p += 2; // Flags
    let stream_count = u16::from_le_bytes(meta.get(p..p + 2)?.try_into().ok()?) as usize;
    p += 2;

    let mut tables_stream = None;
    let mut strings_stream = None;
    for _ in 0..stream_count {
        let offset = u32::from_le_bytes(meta.get(p..p + 4)?.try_into().ok()?) as usize;
        let size = u32::from_le_bytes(meta.get(p + 4..p + 8)?.try_into().ok()?) as usize;
        p += 8;
        let name_start = p;
        let name_end = meta.get(name_start..)?.iter().position(|&c| c == 0)? + name_start;
        let name = std::str::from_utf8(meta.get(name_start..name_end)?).ok()?;
        p = name_end + 1;
        p = (p + 3) & !3; // 4-byte alignment

        match name {
            "#~" | "#-" => tables_stream = meta.get(offset..offset + size),
            "#Strings" => strings_stream = meta.get(offset..offset + size),
            _ => {}
        }
    }

    let (tables, strings) = (tables_stream?, strings_stream?);
    Some(walk(tables, strings))
}

fn walk(stream: &[u8], strings: &[u8]) -> ClrInfo {
    let heap_sizes = stream.get(6).copied().unwrap_or(0);
    let valid = u64::from_le_bytes(stream.get(8..16).unwrap_or(&[0; 8]).try_into().unwrap());
    let sorted_len = 8;

    let mut t = Tables {
        data: stream,
        pos: 16 + sorted_len,
        rows: [0; 64],
        str_wide: heap_sizes & 1 != 0,
        guid_wide: heap_sizes & 2 != 0,
        blob_wide: heap_sizes & 4 != 0,
        strings,
    };

    for i in 0..64 {
        if valid & (1u64 << i) != 0 {
            t.rows[i] = t.u32();
        }
    }

    let mut out = ClrInfo::default();

    for table in 0..64usize {
        let count = t.rows[table];
        if count == 0 {
            continue;
        }
        match table {
            TABLE_MODULE_REF => {
                for _ in 0..count {
                    out.module_refs.push(t.string());
                }
            }
            TABLE_ASSEMBLY_REF => {
                for _ in 0..count {
                    let major = t.u16();
                    let minor = t.u16();
                    let build = t.u16();
                    let revision = t.u16();
                    t.u32(); // Flags
                    t.skip_blob(); // PublicKeyOrToken
                    let name = t.string();
                    let culture = t.string();
                    t.skip_blob(); // HashValue
                    out.assembly_refs.push(AssemblyRef {
                        name,
                        version: format!("{major}.{minor}.{build}.{revision}"),
                        culture: if culture.is_empty() {
                            None
                        } else {
                            Some(culture)
                        },
                    });
                }
            }
            _ => {
                for _ in 0..count {
                    if !skip_row(&mut t, table) {
                        return out; // An unknown table layout stops the walk.
                    }
                }
            }
        }
    }
    out
}

/// Skip one row. Returns false when the table layout is unknown.
fn skip_row(t: &mut Tables, table: usize) -> bool {
    match table {
        TABLE_MODULE => {
            t.u16();
            t.skip_string();
            t.skip_guid();
            t.skip_guid();
            t.skip_guid();
        }
        TABLE_TYPE_REF => {
            t.skip_coded(2, RESOLUTION_SCOPE);
            t.skip_string();
            t.skip_string();
        }
        TABLE_TYPE_DEF => {
            t.u32();
            t.skip_string();
            t.skip_string();
            t.skip_coded(2, TYPE_DEF_OR_REF);
            t.skip_simple(TABLE_FIELD);
            t.skip_simple(TABLE_METHOD_DEF);
        }
        TABLE_FIELD => {
            t.u16();
            t.skip_string();
            t.skip_blob();
        }
        TABLE_METHOD_DEF => {
            t.u32();
            t.u16();
            t.u16();
            t.skip_string();
            t.skip_blob();
            t.skip_simple(TABLE_PARAM);
        }
        TABLE_PARAM => {
            t.u16();
            t.u16();
            t.skip_string();
        }
        0x09 => {
            // InterfaceImpl
            t.skip_simple(TABLE_TYPE_DEF);
            t.skip_coded(2, TYPE_DEF_OR_REF);
        }
        TABLE_MEMBER_REF => {
            t.skip_coded(3, MEMBER_REF_PARENT);
            t.skip_string();
            t.skip_blob();
        }
        0x0b => {
            // Constant
            t.u8();
            t.u8();
            t.skip_coded(2, HAS_CONSTANT);
            t.skip_blob();
        }
        0x0c => {
            // CustomAttribute
            t.skip_coded(5, HAS_CUSTOM_ATTRIBUTE);
            t.skip_coded(3, CUSTOM_ATTRIBUTE_TYPE);
            t.skip_blob();
        }
        0x0d => {
            // FieldMarshal
            t.skip_coded(1, HAS_FIELD_MARSHAL);
            t.skip_blob();
        }
        TABLE_DECL_SECURITY => {
            t.u16();
            t.skip_coded(2, HAS_DECL_SECURITY);
            t.skip_blob();
        }
        0x0f => {
            // ClassLayout
            t.u16();
            t.u32();
            t.skip_simple(TABLE_TYPE_DEF);
        }
        0x10 => {
            // FieldLayout
            t.u32();
            t.skip_simple(TABLE_FIELD);
        }
        TABLE_STANDALONE_SIG => t.skip_blob(),
        0x12 => {
            // EventMap
            t.skip_simple(TABLE_TYPE_DEF);
            t.skip_simple(TABLE_EVENT);
        }
        TABLE_EVENT => {
            t.u16();
            t.skip_string();
            t.skip_coded(2, TYPE_DEF_OR_REF);
        }
        0x15 => {
            // PropertyMap
            t.skip_simple(TABLE_TYPE_DEF);
            t.skip_simple(TABLE_PROPERTY);
        }
        TABLE_PROPERTY => {
            t.u16();
            t.skip_string();
            t.skip_blob();
        }
        0x18 => {
            // MethodSemantics
            t.u16();
            t.skip_simple(TABLE_METHOD_DEF);
            t.skip_coded(1, HAS_SEMANTICS);
        }
        0x19 => {
            // MethodImpl
            t.skip_simple(TABLE_TYPE_DEF);
            t.skip_coded(1, METHOD_DEF_OR_REF);
            t.skip_coded(1, METHOD_DEF_OR_REF);
        }
        TABLE_TYPE_SPEC => t.skip_blob(),
        0x1c => {
            // ImplMap
            t.u16();
            t.skip_coded(1, MEMBER_FORWARDED);
            t.skip_string();
            t.skip_simple(TABLE_MODULE_REF);
        }
        0x1d => {
            // FieldRVA
            t.u32();
            t.skip_simple(TABLE_FIELD);
        }
        TABLE_ASSEMBLY => {
            t.u32();
            t.u16();
            t.u16();
            t.u16();
            t.u16();
            t.u32();
            t.skip_blob();
            t.skip_string();
            t.skip_string();
        }
        0x21 => {
            t.u32();
        } // AssemblyProcessor
        0x22 => {
            t.u32();
            t.u32();
            t.u32();
        } // AssemblyOS
        _ => return false,
    }
    true
}
