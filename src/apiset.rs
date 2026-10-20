// ApiSet schema resolution.
// Derived from the "api-" / "ext-" prefix branch in DependenciesLib's #US literals
// and from the "-apisets" / "-apisetsdll" options of Dependencies.exe.
// The schema is the API_SET_NAMESPACE (version 6) structure in the .apiset
// section of apisetschema.dll.

use std::collections::HashMap;
use std::path::Path;

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn utf16_at(buf: &[u8], off: usize, byte_len: usize) -> Option<String> {
    let b = buf.get(off..off + byte_len)?;
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// apiset name (lowercase, without .dll) -> host DLL name
pub type ApiSetMap = HashMap<String, String>;

pub fn load(system_folder: &Path) -> ApiSetMap {
    let mut map = HashMap::new();
    let path = system_folder.join("apisetschema.dll");
    let Ok(bytes) = std::fs::read(&path) else {
        return map;
    };
    let Ok(file) = crate::pe::parse_bytes(&path.to_string_lossy(), &bytes) else {
        return map;
    };
    let Some(section) = file.sections.iter().find(|s| s.name == ".apiset") else {
        return map;
    };
    let start = section.raw_pointer as usize;
    let end = start + section.raw_size as usize;
    let Some(ns) = bytes.get(start..end.min(bytes.len())) else {
        return map;
    };

    let Some(version) = u32_at(ns, 0) else {
        return map;
    };
    if version != 6 {
        return map; // Version 2 and 4 layouts are not handled.
    }
    let (Some(count), Some(entry_offset)) = (u32_at(ns, 12), u32_at(ns, 16)) else {
        return map;
    };

    for i in 0..count as usize {
        let e = entry_offset as usize + i * 24;
        let (Some(name_offset), Some(name_length)) = (u32_at(ns, e + 4), u32_at(ns, e + 8)) else {
            continue;
        };
        let (Some(value_offset), Some(value_count)) = (u32_at(ns, e + 16), u32_at(ns, e + 20))
        else {
            continue;
        };
        let Some(name) = utf16_at(ns, name_offset as usize, name_length as usize) else {
            continue;
        };
        if value_count == 0 {
            continue;
        }

        // The default host is the first value with an empty importing-module name.
        let mut host = None;
        for v in 0..value_count as usize {
            let vo = value_offset as usize + v * 20;
            let (Some(src_len), Some(val_off), Some(val_len)) =
                (u32_at(ns, vo + 8), u32_at(ns, vo + 12), u32_at(ns, vo + 16))
            else {
                continue;
            };
            let value = utf16_at(ns, val_off as usize, val_len as usize);
            if src_len == 0 {
                host = value;
                break;
            }
            if host.is_none() {
                host = value;
            }
        }

        if let Some(host) = host {
            if !host.is_empty() {
                // The schema stores a single version per family
                // (e.g. errorhandling-l1-1-3). The loader matches on the name
                // without the trailing "-N", so index that key too.
                let lower = name.to_lowercase();
                if let Some((head, _)) = lower.rsplit_once('-') {
                    map.entry(head.to_string()).or_insert_with(|| host.clone());
                }
                map.insert(lower, host);
            }
        }
    }
    map
}

/// "api-ms-win-core-heap-l1-1-0.dll" -> schema lookup key
pub fn lookup<'a>(map: &'a ApiSetMap, import_name: &str) -> Option<&'a String> {
    let lower = import_name.to_lowercase();
    let stem = lower.strip_suffix(".dll").unwrap_or(&lower);
    if let Some(host) = map.get(stem) {
        return Some(host);
    }
    // Some names are registered without the trailing "-N" segment.
    let trimmed = stem.rsplit_once('-').map(|(head, _)| head)?;
    map.get(trimmed)
}
