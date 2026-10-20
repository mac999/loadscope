// Module search strategies and the dependency chain.
// The strategy list and its order are taken verbatim from the
// Dependencies.ModuleSearchStrategy enum of DependenciesLib.dll
// (field tokens 0x0400000a..0x04000017). FindPe.FindPeFromDefault returns
// Tuple<ModuleSearchStrategy,string>, so results stay (strategy, path) pairs.

use crate::apiset::{self, ApiSetMap};
use crate::pe::{self, PeFile};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ModuleSearchStrategy {
    ROOT,
    SxS,
    ApiSetSchema,
    WellKnownDlls,
    ApplicationDirectory,
    System32Folder,
    WindowsFolder,
    WorkingDirectory,
    Environment,
    AppInitDLL,
    Fullpath,
    ClrAssembly,
    UserDefined,
    NOT_FOUND,
}

impl ModuleSearchStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ROOT => "ROOT",
            Self::SxS => "SxS",
            Self::ApiSetSchema => "ApiSetSchema",
            Self::WellKnownDlls => "WellKnownDlls",
            Self::ApplicationDirectory => "ApplicationDirectory",
            Self::System32Folder => "System32Folder",
            Self::WindowsFolder => "WindowsFolder",
            Self::WorkingDirectory => "WorkingDirectory",
            Self::Environment => "Environment",
            Self::AppInitDLL => "AppInitDLL",
            Self::Fullpath => "Fullpath",
            Self::ClrAssembly => "ClrAssembly",
            Self::UserDefined => "UserDefined",
            Self::NOT_FOUND => "NOT_FOUND",
        }
    }
}

pub struct SearchContext {
    pub application_directory: PathBuf,
    pub working_directory: PathBuf,
    pub system_folder: PathBuf,
    pub windows_folder: PathBuf,
    pub path_entries: Vec<PathBuf>,
    pub known_dlls: HashSet<String>,
    pub user_directories: Vec<PathBuf>,
    pub api_sets: ApiSetMap,
}

impl SearchContext {
    /// A 32-bit root uses SysWOW64 as its system folder, a 64-bit root uses System32.
    pub fn new(root: &PeFile, user_directories: Vec<PathBuf>) -> Self {
        let windows = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let windows_folder = PathBuf::from(&windows);
        let system_folder = if root.machine == pe::MACHINE_I386 {
            windows_folder.join("SysWOW64")
        } else {
            windows_folder.join("System32")
        };

        let application_directory = Path::new(&root.path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        let path_entries = std::env::var("PATH")
            .unwrap_or_default()
            .split(';')
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .collect();

        SearchContext {
            application_directory,
            working_directory: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            api_sets: apiset::load(&system_folder),
            system_folder,
            windows_folder,
            path_entries,
            known_dlls: read_known_dlls(root.machine != pe::MACHINE_I386),
            user_directories,
        }
    }
}

/// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
/// Backs the KnownDLLs listing.
pub fn read_known_dlls(_is_64bit: bool) -> HashSet<String> {
    let mut out = HashSet::new();
    let output = std::process::Command::new("reg")
        .args([
            "query",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
        ])
        .output();
    let Ok(output) = output else { return out };
    let text = String::from_utf8_lossy(&output.stdout);

    // Take the value out of the "    <name>    REG_SZ    <value>" format.
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(kind)) = (parts.next(), parts.next()) else {
            continue;
        };
        if kind != "REG_SZ" {
            continue;
        }
        if name.eq_ignore_ascii_case("DllDirectory") || name.eq_ignore_ascii_case("DllDirectory32")
        {
            continue;
        }
        let value = parts.collect::<Vec<_>>().join(" ");
        if !value.is_empty() {
            out.insert(value.to_lowercase());
        }
    }
    out
}

fn exists_in(dir: &Path, name: &str) -> Option<String> {
    let candidate = dir.join(name);
    if candidate.is_file() {
        Some(candidate.to_string_lossy().into_owned())
    } else {
        None
    }
}

/// Resolve one name to (strategy, path), trying the strategies in declaration order.
/// SxS / AppInitDLL / ClrAssembly lack enough evidence to implement and are skipped.
pub fn find_pe_from_default(
    ctx: &SearchContext,
    name: &str,
) -> (ModuleSearchStrategy, Option<String>) {
    let lower = name.to_lowercase();

    // ApiSetSchema: names starting with api- or ext-.
    if lower.starts_with("api-") || lower.starts_with("ext-") {
        // Try the host DLL the schema points at first.
        if let Some(host) = apiset::lookup(&ctx.api_sets, name) {
            if let Some(p) = exists_in(&ctx.system_folder, host) {
                return (ModuleSearchStrategy::ApiSetSchema, Some(p));
            }
        }
        if let Some(p) = exists_in(&ctx.system_folder, name) {
            return (ModuleSearchStrategy::ApiSetSchema, Some(p));
        }
        return (ModuleSearchStrategy::ApiSetSchema, None);
    }

    if ctx.known_dlls.contains(&lower) {
        if let Some(p) = exists_in(&ctx.system_folder, name) {
            return (ModuleSearchStrategy::WellKnownDlls, Some(p));
        }
    }

    if let Some(p) = exists_in(&ctx.application_directory, name) {
        return (ModuleSearchStrategy::ApplicationDirectory, Some(p));
    }
    if let Some(p) = exists_in(&ctx.system_folder, name) {
        return (ModuleSearchStrategy::System32Folder, Some(p));
    }
    if let Some(p) = exists_in(&ctx.windows_folder, name) {
        return (ModuleSearchStrategy::WindowsFolder, Some(p));
    }
    if let Some(p) = exists_in(&ctx.working_directory, name) {
        return (ModuleSearchStrategy::WorkingDirectory, Some(p));
    }
    for dir in &ctx.path_entries {
        if let Some(p) = exists_in(dir, name) {
            return (ModuleSearchStrategy::Environment, Some(p));
        }
    }

    // Fullpath: the name is itself a path.
    if name.contains('\\') || name.contains('/') {
        if Path::new(name).is_file() {
            return (ModuleSearchStrategy::Fullpath, Some(name.to_string()));
        }
    }

    for dir in &ctx.user_directories {
        if let Some(p) = exists_in(dir, name) {
            return (ModuleSearchStrategy::UserDefined, Some(p));
        }
    }

    (ModuleSearchStrategy::NOT_FOUND, None)
}

/// Resolve a CLR assembly reference: application directory -> GAC -> framework directory.
/// Reported under the ClrAssembly strategy.
pub fn find_clr_assembly(
    ctx: &SearchContext,
    name: &str,
) -> (ModuleSearchStrategy, Option<String>) {
    for ext in [".dll", ".exe"] {
        let file = format!("{name}{ext}");
        if let Some(p) = exists_in(&ctx.application_directory, &file) {
            return (ModuleSearchStrategy::ApplicationDirectory, Some(p));
        }
    }

    let dotnet_root = ctx.windows_folder.join("Microsoft.NET");
    for gac in [
        dotnet_root.join("assembly").join("GAC_MSIL"),
        dotnet_root.join("assembly").join("GAC_64"),
        dotnet_root.join("assembly").join("GAC_32"),
        ctx.windows_folder.join("assembly").join("GAC_MSIL"),
    ] {
        let family = gac.join(name);
        let Ok(entries) = std::fs::read_dir(&family) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Some(p) = exists_in(&entry.path(), &format!("{name}.dll")) {
                return (ModuleSearchStrategy::ClrAssembly, Some(p));
            }
        }
    }

    for framework in ["Framework64", "Framework"] {
        let dir = dotnet_root.join(framework);
        let Ok(versions) = std::fs::read_dir(&dir) else {
            continue;
        };
        for version in versions.flatten() {
            if let Some(p) = exists_in(&version.path(), &format!("{name}.dll")) {
                return (ModuleSearchStrategy::ClrAssembly, Some(p));
            }
        }
    }

    (ModuleSearchStrategy::NOT_FOUND, None)
}

/// One entry of the dependency tree.
#[derive(Debug, Serialize)]
pub struct ChainNode {
    pub name: String,
    pub strategy: String,
    pub resolved_path: Option<String>,
    /// Key into the modules map. Set only when the module resolved and parsed.
    pub module_key: Option<String>,
    pub delay_import: bool,
    /// "native" (import table) or "assembly" (CLR AssemblyRef)
    pub kind: String,
    pub version: Option<String>,
    pub duplicate: bool,
    pub error: Option<String>,
    pub children: Vec<ChainNode>,
}

/// A single dependency required by a module.
struct Dependency {
    name: String,
    delay_import: bool,
    assembly: bool,
    version: Option<String>,
}

fn dependencies_of(file: &PeFile) -> Vec<Dependency> {
    let mut out: Vec<Dependency> = file
        .imports
        .iter()
        .map(|m| Dependency {
            name: m.name.clone(),
            delay_import: m.delay_import,
            assembly: false,
            version: None,
        })
        .collect();

    if let Some(clr) = &file.clr {
        for r in &clr.assembly_refs {
            out.push(Dependency {
                name: r.name.clone(),
                delay_import: false,
                assembly: true,
                version: Some(r.version.clone()),
            });
        }
    }
    out
}

/// One group of the imports table. The Module column holds the resolved full path.
#[derive(Debug, Serialize)]
pub struct ImportView {
    pub name: String,
    pub resolved_path: Option<String>,
    pub strategy: String,
    pub delay_import: bool,
    pub functions: Vec<pe::ImportFunction>,
}

/// One row of the modules list, plus the imports/exports shown when it is selected.
#[derive(Debug, Serialize)]
pub struct ModuleInfo {
    pub key: String,
    pub path: String,
    pub name: String,
    pub machine_name: String,
    pub type_label: String,
    pub file_size: u64,
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub subsystem_version: String,
    pub checksum: u32,
    pub is_dotnet: bool,
    pub strategy: String,
    pub sections: Vec<pe::Section>,
    pub imports: Vec<ImportView>,
    pub exports: Vec<pe::ExportFunction>,
    pub export_module_name: Option<String>,
    pub manifest: Option<String>,
    pub assembly_refs: Vec<crate::dotnet::AssemblyRef>,
    pub module_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub total_modules: usize,
    pub resolved: usize,
    pub not_found: usize,
    pub delay_imported: usize,
    pub by_strategy: Vec<(String, usize)>,
    pub max_depth_reached: usize,
}

#[derive(Debug, Serialize)]
pub struct AnalysisResult {
    pub root_key: String,
    pub chain: Vec<ChainNode>,
    pub modules: BTreeMap<String, ModuleInfo>,
    pub missing: Vec<String>,
    pub stats: Stats,
    pub dashboard: crate::dashboard::Dashboard,
}

struct Walker<'a> {
    ctx: &'a SearchContext,
    modules: BTreeMap<String, ModuleInfo>,
    parsed: HashMap<String, Result<PeFile, String>>,
    expanded: HashSet<String>,
    missing: Vec<String>,
    by_strategy: HashMap<String, usize>,
    seen_names: HashSet<String>,
    resolved: usize,
    not_found: usize,
    delay_imported: usize,
    max_depth_reached: usize,
}

fn key_of(path: &str) -> String {
    path.to_lowercase()
}

impl<'a> Walker<'a> {
    fn parse(&mut self, path: &str) -> Result<PeFile, String> {
        self.parsed
            .entry(key_of(path))
            .or_insert_with(|| pe::parse(path))
            .clone()
    }

    /// Register a module in the modules map. Existing entries are left alone.
    fn register(&mut self, file: &PeFile, strategy: ModuleSearchStrategy) -> String {
        let key = key_of(&file.path);
        if self.modules.contains_key(&key) {
            return key;
        }

        let imports = file
            .imports
            .iter()
            .map(|m| {
                let (s, p) = find_pe_from_default(self.ctx, &m.name);
                ImportView {
                    name: m.name.clone(),
                    resolved_path: p,
                    strategy: s.as_str().to_string(),
                    delay_import: m.delay_import,
                    functions: m.functions.clone(),
                }
            })
            .collect();

        let name = Path::new(&file.path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.path.clone());

        let type_label = if file.is_dll {
            "Dll; Executable"
        } else {
            "Executable"
        };

        self.modules.insert(
            key.clone(),
            ModuleInfo {
                key: key.clone(),
                path: file.path.clone(),
                name,
                machine_name: file.machine_name.clone(),
                type_label: type_label.to_string(),
                file_size: file.file_size,
                image_base: file.image_base,
                size_of_image: file.size_of_image,
                entry_point: file.entry_point,
                subsystem: file.subsystem,
                dll_characteristics: file.dll_characteristics,
                subsystem_version: file.subsystem_version.clone(),
                checksum: file.checksum,
                is_dotnet: file.is_dotnet,
                strategy: strategy.as_str().to_string(),
                sections: file.sections.clone(),
                imports,
                exports: file.exports.clone(),
                export_module_name: file.export_module_name.clone(),
                manifest: file.manifest.clone(),
                assembly_refs: file
                    .clr
                    .as_ref()
                    .map(|c| c.assembly_refs.clone())
                    .unwrap_or_default(),
                module_refs: file
                    .clr
                    .as_ref()
                    .map(|c| c.module_refs.clone())
                    .unwrap_or_default(),
            },
        );
        key
    }

    fn walk(&mut self, deps: &[Dependency], depth: usize, max_depth: usize) -> Vec<ChainNode> {
        self.max_depth_reached = self.max_depth_reached.max(depth);
        let mut out = Vec::new();

        for module in deps {
            let (strategy, resolved_path) = if module.assembly {
                find_clr_assembly(self.ctx, &module.name)
            } else {
                find_pe_from_default(self.ctx, &module.name)
            };
            *self
                .by_strategy
                .entry(strategy.as_str().to_string())
                .or_insert(0) += 1;
            if module.delay_import {
                self.delay_imported += 1;
            }

            let name_key = module.name.to_lowercase();
            let first_time = self.seen_names.insert(name_key);
            if first_time {
                match resolved_path {
                    Some(_) => self.resolved += 1,
                    None => {
                        self.not_found += 1;
                        self.missing.push(module.name.clone());
                    }
                }
            }

            let mut node = ChainNode {
                name: module.name.clone(),
                strategy: strategy.as_str().to_string(),
                resolved_path: resolved_path.clone(),
                module_key: None,
                delay_import: module.delay_import,
                kind: if module.assembly { "assembly" } else { "native" }.to_string(),
                version: module.version.clone(),
                duplicate: false,
                error: None,
                children: Vec::new(),
            };

            if let Some(path) = resolved_path {
                match self.parse(&path) {
                    Ok(child) => {
                        let key = self.register(&child, strategy);
                        node.module_key = Some(key.clone());
                        // Never expand the same module twice (cycle guard).
                        if self.expanded.contains(&key) {
                            node.duplicate = true;
                        } else if depth + 1 < max_depth {
                            self.expanded.insert(key);
                            let deps = dependencies_of(&child);
                            node.children = self.walk(&deps, depth + 1, max_depth);
                        }
                    }
                    Err(e) => node.error = Some(e),
                }
            }
            out.push(node);
        }
        out
    }
}

pub fn analyze(
    path: &str,
    max_depth: usize,
    user_directories: Vec<PathBuf>,
) -> Result<AnalysisResult, String> {
    let root = pe::parse(path)?;
    let ctx = SearchContext::new(&root, user_directories);

    let mut walker = Walker {
        ctx: &ctx,
        modules: BTreeMap::new(),
        parsed: HashMap::new(),
        expanded: HashSet::new(),
        missing: Vec::new(),
        by_strategy: HashMap::new(),
        seen_names: HashSet::new(),
        resolved: 0,
        not_found: 0,
        delay_imported: 0,
        max_depth_reached: 0,
    };

    let root_key = walker.register(&root, ModuleSearchStrategy::ROOT);
    walker.expanded.insert(root_key.clone());
    let deps = dependencies_of(&root);
    let chain = walker.walk(&deps, 0, max_depth.max(1));

    let mut by_strategy: Vec<(String, usize)> = walker.by_strategy.into_iter().collect();
    by_strategy.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let dashboard = crate::dashboard::build(&root_key, &walker.modules, &chain);

    Ok(AnalysisResult {
        dashboard,
        stats: Stats {
            total_modules: walker.modules.len(),
            resolved: walker.resolved,
            not_found: walker.not_found,
            delay_imported: walker.delay_imported,
            by_strategy,
            max_depth_reached: walker.max_depth_reached + 1,
        },
        root_key,
        chain,
        modules: walker.modules,
        missing: walker.missing,
    })
}
