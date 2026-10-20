// PE parser. The feature set was pinned down from the output formats of
// (imports / exports / delay import / forwarded name / embedded manifest).
// Reads the bytes directly instead of pulling in an existing PE crate.

use serde::Serialize;

pub const MACHINE_I386: u16 = 0x014c;
pub const MACHINE_AMD64: u16 = 0x8664;
pub const MACHINE_ARM64: u16 = 0xaa64;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_DELAY_IMPORT: usize = 13;

const RT_MANIFEST: u32 = 24;

#[derive(Debug, Serialize, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Serialize, Clone)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub delay_import: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct ImportModule {
    pub name: String,
    pub delay_import: bool,
    pub functions: Vec<ImportFunction>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ExportFunction {
    pub ordinal: u32,
    pub name: Option<String>,
    pub virtual_address: u32,
    pub forwarded_name: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PeFile {
    pub path: String,
    pub file_size: u64,
    pub machine: u16,
    pub machine_name: String,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub image_base: u64,
    pub entry_point: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub subsystem_version: String,
    pub size_of_image: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub sections: Vec<Section>,
    pub imports: Vec<ImportModule>,
    pub exports: Vec<ExportFunction>,
    pub export_module_name: Option<String>,
    pub manifest: Option<String>,
    pub clr_metadata_rva: u32,
    pub clr: Option<crate::dotnet::ClrInfo>,
}

impl PeFile {
    /// Convert an RVA to a file offset. None when it falls outside every section.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let size = if s.virtual_size == 0 {
                s.raw_size
            } else {
                s.virtual_size.max(s.raw_size)
            };
            if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(size) {
                let delta = rva - s.virtual_address;
                if delta >= s.raw_size {
                    return None;
                }
                return Some((s.raw_pointer + delta) as usize);
            }
        }
        None
    }
}

pub type PeResult<T> = Result<T, String>;

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u16(&self, off: usize) -> PeResult<u16> {
        let b = self.buf.get(off..off + 2).ok_or_else(|| oob(off))?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&self, off: usize) -> PeResult<u32> {
        let b = self.buf.get(off..off + 4).ok_or_else(|| oob(off))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&self, off: usize) -> PeResult<u64> {
        let b = self.buf.get(off..off + 8).ok_or_else(|| oob(off))?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    fn cstr(&self, off: usize) -> PeResult<String> {
        let rest = self.buf.get(off..).ok_or_else(|| oob(off))?;
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
    }
}

fn oob(off: usize) -> String {
    format!("offset {off:#x} is outside the file")
}

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        MACHINE_I386 => "x86",
        MACHINE_AMD64 => "x64",
        MACHINE_ARM64 => "ARM64",
        0x01c0 | 0x01c4 => "ARM",
        _ => "unknown",
    }
}

/// Entry point behind the "could not load file as a PE" error.
pub fn parse(path: &str) -> PeResult<PeFile> {
    let buf = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    parse_bytes(path, &buf)
}

pub fn parse_bytes(path: &str, buf: &[u8]) -> PeResult<PeFile> {
    let r = Reader { buf };

    if r.u16(0)? != 0x5a4d {
        return Err("not a PE file: missing MZ signature".into());
    }
    let pe_off = r.u32(0x3c)? as usize;
    if r.u32(pe_off)? != 0x0000_4550 {
        return Err("not a PE file: missing PE\\0\\0 signature".into());
    }

    let coff = pe_off + 4;
    let machine = r.u16(coff)?;
    let section_count = r.u16(coff + 2)? as usize;
    let timestamp = r.u32(coff + 4)?;
    let opt_size = r.u16(coff + 16)? as usize;
    let characteristics = r.u16(coff + 18)?;

    let opt = coff + 20;
    let magic = r.u16(opt)?;
    let is_64bit = match magic {
        0x20b => true,
        0x10b => false,
        other => return Err(format!("unsupported optional header magic {other:#x}")),
    };

    let entry_point = r.u32(opt + 16)?;
    let (image_base, dir_off) = if is_64bit {
        (r.u64(opt + 24)?, opt + 112)
    } else {
        (r.u32(opt + 28)? as u64, opt + 96)
    };
    // Subsystem / SizeOfImage / CheckSum sit at the same offset in PE32 and PE32+.
    let subsystem = r.u16(opt + 68)?;
    let dll_characteristics = r.u16(opt + 70)?;
    let size_of_image = r.u32(opt + 56)?;
    let checksum = r.u32(opt + 64)?;
    let subsystem_version = format!("{}.{}", r.u16(opt + 48)?, r.u16(opt + 50)?);
    let dir_count = r.u32(dir_off - 4)? as usize;

    let sec_off = opt + opt_size;
    let mut sections = Vec::with_capacity(section_count);
    for i in 0..section_count {
        let s = sec_off + i * 40;
        let raw_name = buf.get(s..s + 8).ok_or_else(|| oob(s))?;
        let end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
            virtual_size: r.u32(s + 8)?,
            virtual_address: r.u32(s + 12)?,
            raw_size: r.u32(s + 16)?,
            raw_pointer: r.u32(s + 20)?,
            characteristics: r.u32(s + 36)?,
        });
    }

    let dir = |index: usize| -> (u32, u32) {
        if index >= dir_count {
            return (0, 0);
        }
        let o = dir_off + index * 8;
        (r.u32(o).unwrap_or(0), r.u32(o + 4).unwrap_or(0))
    };

    // A .NET assembly is identified by the COM descriptor directory (14).
    let cli_rva = dir(14).0;
    let is_dotnet = cli_rva != 0;

    let ctx = Ctx {
        r: Reader { buf },
        sections: &sections,
        is_64bit,
        image_base,
    };

    let mut imports = read_imports(&ctx, dir(DIR_IMPORT).0)?;
    imports.extend(read_delay_imports(&ctx, dir(DIR_DELAY_IMPORT).0)?);

    let (exports, export_module_name) = read_exports(&ctx, dir(DIR_EXPORT))?;
    let manifest = read_manifest(&ctx, dir(DIR_RESOURCE).0);

    // MetaData directory RVA inside the CLI header (at header offset 8)
    let clr_metadata_rva = ctx
        .offset(cli_rva)
        .and_then(|o| ctx.r.u32(o + 8).ok())
        .unwrap_or(0);

    let mut file = PeFile {
        path: path.to_string(),
        file_size: buf.len() as u64,
        machine,
        machine_name: machine_name(machine).to_string(),
        is_64bit,
        is_dll: characteristics & 0x2000 != 0,
        is_dotnet,
        image_base,
        entry_point,
        subsystem,
        dll_characteristics,
        subsystem_version,
        size_of_image,
        checksum,
        timestamp,
        sections,
        imports,
        exports,
        export_module_name,
        manifest,
        clr_metadata_rva,
        clr: None,
    };
    if is_dotnet {
        file.clr = crate::dotnet::read(buf, &file);
    }
    Ok(file)
}

struct Ctx<'a> {
    r: Reader<'a>,
    sections: &'a [Section],
    is_64bit: bool,
    image_base: u64,
}

impl<'a> Ctx<'a> {
    fn offset(&self, rva: u32) -> Option<usize> {
        if rva == 0 {
            return None;
        }
        for s in self.sections {
            let size = if s.virtual_size == 0 {
                s.raw_size
            } else {
                s.virtual_size.max(s.raw_size)
            };
            if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(size) {
                let delta = rva - s.virtual_address;
                if delta >= s.raw_size {
                    return None; // uninitialised region
                }
                return Some((s.raw_pointer + delta) as usize);
            }
        }
        None
    }

    fn cstr_at_rva(&self, rva: u32) -> Option<String> {
        self.offset(rva).and_then(|o| self.r.cstr(o).ok())
    }
}

fn read_thunks(ctx: &Ctx, thunk_rva: u32, delay: bool) -> PeResult<Vec<ImportFunction>> {
    let mut out = Vec::new();
    let Some(mut off) = ctx.offset(thunk_rva) else {
        return Ok(out);
    };
    let step = if ctx.is_64bit { 8 } else { 4 };
    let ordinal_flag: u64 = if ctx.is_64bit {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    loop {
        let value = if ctx.is_64bit {
            ctx.r.u64(off)?
        } else {
            ctx.r.u32(off)? as u64
        };
        if value == 0 {
            break;
        }
        if value & ordinal_flag != 0 {
            out.push(ImportFunction {
                name: None,
                ordinal: Some((value & 0xffff) as u16),
                hint: None,
                delay_import: delay,
            });
        } else {
            let rva = (value & 0x7fff_ffff) as u32;
            match ctx.offset(rva) {
                Some(o) => out.push(ImportFunction {
                    name: ctx.r.cstr(o + 2).ok(),
                    ordinal: None,
                    hint: ctx.r.u16(o).ok(),
                    delay_import: delay,
                }),
                None => out.push(ImportFunction {
                    name: None,
                    ordinal: None,
                    hint: None,
                    delay_import: delay,
                }),
            }
        }
        off += step;
        if out.len() > 65535 {
            break;
        }
    }
    Ok(out)
}

fn read_imports(ctx: &Ctx, rva: u32) -> PeResult<Vec<ImportModule>> {
    let mut out = Vec::new();
    let Some(base) = ctx.offset(rva) else {
        return Ok(out);
    };

    let mut i = 0usize;
    loop {
        let d = base + i * 20;
        let original_first_thunk = ctx.r.u32(d)?;
        let name_rva = ctx.r.u32(d + 12)?;
        let first_thunk = ctx.r.u32(d + 16)?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let name = ctx
            .cstr_at_rva(name_rva)
            .unwrap_or_else(|| "???".to_string());
        let thunk = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        out.push(ImportModule {
            name,
            delay_import: false,
            functions: read_thunks(ctx, thunk, false)?,
        });
        i += 1;
        if i > 4096 {
            break;
        }
    }
    Ok(out)
}

fn read_delay_imports(ctx: &Ctx, rva: u32) -> PeResult<Vec<ImportModule>> {
    let mut out = Vec::new();
    let Some(base) = ctx.offset(rva) else {
        return Ok(out);
    };

    let mut i = 0usize;
    loop {
        let d = base + i * 32;
        let attributes = ctx.r.u32(d)?;
        let name_field = ctx.r.u32(d + 4)?;
        let int_field = ctx.r.u32(d + 16)?;
        if name_field == 0 && int_field == 0 {
            break;
        }
        // With attribute bit 0 clear the fields hold VAs, not RVAs (older format).
        let to_rva = |v: u32| -> u32 {
            if attributes & 1 != 0 {
                v
            } else {
                (v as u64).saturating_sub(ctx.image_base) as u32
            }
        };
        let name = ctx
            .cstr_at_rva(to_rva(name_field))
            .unwrap_or_else(|| "???".to_string());
        out.push(ImportModule {
            name,
            delay_import: true,
            functions: read_thunks(ctx, to_rva(int_field), true)?,
        });
        i += 1;
        if i > 4096 {
            break;
        }
    }
    Ok(out)
}

fn read_exports(ctx: &Ctx, dir: (u32, u32)) -> PeResult<(Vec<ExportFunction>, Option<String>)> {
    let (rva, size) = dir;
    let Some(base) = ctx.offset(rva) else {
        return Ok((Vec::new(), None));
    };

    let module_name = ctx.cstr_at_rva(ctx.r.u32(base + 12)?);
    let ordinal_base = ctx.r.u32(base + 16)?;
    let func_count = ctx.r.u32(base + 20)? as usize;
    let name_count = ctx.r.u32(base + 24)? as usize;
    let func_rva = ctx.r.u32(base + 28)?;
    let name_rva = ctx.r.u32(base + 32)?;
    let ord_rva = ctx.r.u32(base + 36)?;

    let (Some(func_off), Some(name_off), Some(ord_off)) = (
        ctx.offset(func_rva),
        ctx.offset(name_rva),
        ctx.offset(ord_rva),
    ) else {
        return Ok((Vec::new(), module_name));
    };

    // ordinal -> name reverse index
    let mut names: Vec<Option<String>> = vec![None; func_count];
    for i in 0..name_count.min(65535) {
        let n = ctx.r.u32(name_off + i * 4)?;
        let ord = ctx.r.u16(ord_off + i * 2)? as usize;
        if ord < names.len() {
            names[ord] = ctx.cstr_at_rva(n);
        }
    }

    let mut out = Vec::with_capacity(func_count);
    for i in 0..func_count.min(65535) {
        let addr = ctx.r.u32(func_off + i * 4)?;
        if addr == 0 {
            continue;
        }
        // An address inside the export directory range is a forwarder string.
        let forwarded = if addr >= rva && addr < rva + size {
            ctx.cstr_at_rva(addr)
        } else {
            None
        };
        out.push(ExportFunction {
            ordinal: ordinal_base + i as u32,
            name: names[i].clone(),
            virtual_address: addr,
            forwarded_name: forwarded,
        });
    }
    Ok((out, module_name))
}

/// Find the RT_MANIFEST(24) resource and return it as a string.
fn read_manifest(ctx: &Ctx, rva: u32) -> Option<String> {
    let root = ctx.offset(rva)?;
    let type_entry = find_resource_entry(ctx, root, root, Some(RT_MANIFEST))?;
    let name_dir = type_entry.1?;
    let name_entry = find_resource_entry(ctx, root, name_dir, None)?;
    let lang_dir = name_entry.1?;
    let lang_entry = find_resource_entry(ctx, root, lang_dir, None)?;
    let data_off = lang_entry.0?;

    let data_rva = ctx.r.u32(data_off).ok()?;
    let size = ctx.r.u32(data_off + 4).ok()? as usize;
    let off = ctx.offset(data_rva)?;
    let bytes = ctx.r.buf.get(off..off + size)?;
    Some(String::from_utf8_lossy(bytes).trim().to_string())
}

/// (data entry offset, subdirectory offset)
type ResEntry = (Option<usize>, Option<usize>);

fn find_resource_entry(
    ctx: &Ctx,
    root: usize,
    dir: usize,
    want_id: Option<u32>,
) -> Option<ResEntry> {
    let named = ctx.r.u16(dir + 12).ok()? as usize;
    let id_count = ctx.r.u16(dir + 14).ok()? as usize;
    let total = named + id_count;

    for i in 0..total {
        let e = dir + 16 + i * 8;
        let id = ctx.r.u32(e).ok()?;
        let offset = ctx.r.u32(e + 4).ok()?;
        if let Some(want) = want_id {
            // Name entries (high bit set) are not compared against IDs.
            if id & 0x8000_0000 != 0 || id != want {
                continue;
            }
        }
        return Some(if offset & 0x8000_0000 != 0 {
            (None, Some(root + (offset & 0x7fff_ffff) as usize))
        } else {
            (Some(root + offset as usize), None)
        });
    }
    None
}
