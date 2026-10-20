// Metrics that give insight into the dependency graph.
//
// Why these metrics:
// - The search strategy distribution, and in particular modules resolved from
//   the application directory, working directory or PATH, is the DLL search
//   order hijacking surface itself (MITRE ATT&CK T1574.001).
// - An unresolved import is a phantom DLL hijacking candidate. Delay imports
//   are counted separately because they load only when actually called.
// - fan-in / fan-out are the standard dependency graph metrics. A widely
//   referenced module has a wide blast radius; one that references many
//   modules is tightly coupled.
// - ASLR / DEP / CFG are read straight from the PE optional header
//   DllCharacteristics. A module missing any of them lowers the mitigation
//   level of the process it loads into.

use crate::resolve::{ChainNode, ModuleInfo};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const DYNAMIC_BASE: u16 = 0x0040; // ASLR
pub const NX_COMPAT: u16 = 0x0100; // DEP
pub const GUARD_CF: u16 = 0x4000; // Control Flow Guard
pub const HIGH_ENTROPY_VA: u16 = 0x0020;

#[derive(Debug, Serialize)]
pub struct Totals {
    pub modules: usize,
    pub resolved: usize,
    pub missing: usize,
    pub edges: usize,
    pub max_depth: usize,
    pub import_functions: usize,
    pub ordinal_imports: usize,
    pub delay_import_modules: usize,
}

#[derive(Debug, Serialize)]
pub struct RiskItem {
    pub name: String,
    pub path: String,
    pub strategy: String,
}

#[derive(Debug, Serialize)]
pub struct MitigationItem {
    pub name: String,
    pub path: String,
    pub aslr: bool,
    pub dep: bool,
    pub cfg: bool,
    pub high_entropy: bool,
}

#[derive(Debug, Serialize)]
pub struct Dashboard {
    pub totals: Totals,
    /// Search strategy distribution by module count (distinct modules, not references)
    pub strategies: Vec<(String, usize)>,
    /// Search order hijacking surface: modules resolved from writable locations
    pub hijack_surface: Vec<RiskItem>,
    /// Unresolved names. A missing required import fails the load; delay imports are conditional.
    pub missing_required: Vec<String>,
    pub missing_delayed: Vec<String>,
    pub architectures: Vec<(String, usize)>,
    /// Modules whose architecture differs from the root (cannot share one process)
    pub architecture_mismatch: Vec<RiskItem>,
    pub dotnet_modules: usize,
    pub native_modules: usize,
    /// Modules missing at least one mitigation
    pub weak_mitigations: Vec<MitigationItem>,
    pub mitigation_counts: Vec<(String, usize)>,
    pub top_fan_in: Vec<(String, usize)>,
    pub top_fan_out: Vec<(String, usize)>,
    pub depth_histogram: Vec<(usize, usize)>,
}

fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_string()
}

/// Walk the chain collecting (parent, child) edges and the minimum depth per module.
fn collect_graph(
    nodes: &[ChainNode],
    parent: &str,
    depth: usize,
    edges: &mut HashSet<(String, String)>,
    depths: &mut HashMap<String, usize>,
    missing_required: &mut Vec<String>,
    missing_delayed: &mut Vec<String>,
    seen_missing: &mut HashSet<String>,
) {
    for n in nodes {
        match &n.module_key {
            Some(key) => {
                edges.insert((parent.to_string(), key.clone()));
                let entry = depths.entry(key.clone()).or_insert(depth);
                *entry = (*entry).min(depth);
            }
            None => {
                let lower = n.name.to_lowercase();
                if seen_missing.insert(lower) {
                    if n.delay_import {
                        missing_delayed.push(n.name.clone());
                    } else {
                        missing_required.push(n.name.clone());
                    }
                }
            }
        }
        if !n.children.is_empty() {
            let next_parent = n.module_key.clone().unwrap_or_else(|| parent.to_string());
            collect_graph(
                &n.children,
                &next_parent,
                depth + 1,
                edges,
                depths,
                missing_required,
                missing_delayed,
                seen_missing,
            );
        }
    }
}

pub fn build(
    root_key: &str,
    modules: &BTreeMap<String, ModuleInfo>,
    chain: &[ChainNode],
) -> Dashboard {
    let mut edges = HashSet::new();
    let mut depths: HashMap<String, usize> = HashMap::new();
    let mut missing_required = Vec::new();
    let mut missing_delayed = Vec::new();
    let mut seen_missing = HashSet::new();

    depths.insert(root_key.to_string(), 0);
    collect_graph(
        chain,
        root_key,
        1,
        &mut edges,
        &mut depths,
        &mut missing_required,
        &mut missing_delayed,
        &mut seen_missing,
    );

    let mut fan_in: HashMap<&str, usize> = HashMap::new();
    let mut fan_out: HashMap<&str, usize> = HashMap::new();
    for (from, to) in &edges {
        *fan_out.entry(from.as_str()).or_insert(0) += 1;
        *fan_in.entry(to.as_str()).or_insert(0) += 1;
    }

    let mut strategies: HashMap<&str, usize> = HashMap::new();
    let mut architectures: HashMap<&str, usize> = HashMap::new();
    let mut hijack_surface = Vec::new();
    let mut architecture_mismatch = Vec::new();
    let mut weak_mitigations = Vec::new();
    let mut mitigation_counts: HashMap<&str, usize> = HashMap::new();
    let mut import_functions = 0usize;
    let mut ordinal_imports = 0usize;
    let mut delay_import_modules = 0usize;
    let mut dotnet_modules = 0usize;

    let root_machine = modules.get(root_key).map(|m| m.machine_name.as_str());

    for m in modules.values() {
        *strategies.entry(m.strategy.as_str()).or_insert(0) += 1;
        *architectures.entry(m.machine_name.as_str()).or_insert(0) += 1;
        if m.is_dotnet {
            dotnet_modules += 1;
        }

        for imp in &m.imports {
            import_functions += imp.functions.len();
            ordinal_imports += imp.functions.iter().filter(|f| f.name.is_none()).count();
            if imp.delay_import {
                delay_import_modules += 1;
            }
        }

        // Resolved from a writable location = search order hijacking surface
        if matches!(
            m.strategy.as_str(),
            "ApplicationDirectory" | "WorkingDirectory" | "Environment" | "UserDefined"
        ) && m.key != root_key
        {
            hijack_surface.push(RiskItem {
                name: m.name.clone(),
                path: m.path.clone(),
                strategy: m.strategy.clone(),
            });
        }

        if let Some(root_arch) = root_machine {
            // MSIL assemblies load under both architectures, so skip them.
            if m.machine_name != root_arch && !m.is_dotnet {
                architecture_mismatch.push(RiskItem {
                    name: m.name.clone(),
                    path: m.path.clone(),
                    strategy: m.machine_name.clone(),
                });
            }
        }

        let d = m.dll_characteristics;
        let item = MitigationItem {
            name: m.name.clone(),
            path: m.path.clone(),
            aslr: d & DYNAMIC_BASE != 0,
            dep: d & NX_COMPAT != 0,
            cfg: d & GUARD_CF != 0,
            high_entropy: d & HIGH_ENTROPY_VA != 0,
        };
        if item.aslr {
            *mitigation_counts.entry("ASLR").or_insert(0) += 1;
        }
        if item.dep {
            *mitigation_counts.entry("DEP").or_insert(0) += 1;
        }
        if item.cfg {
            *mitigation_counts.entry("CFG").or_insert(0) += 1;
        }
        if item.high_entropy {
            *mitigation_counts.entry("HighEntropyVA").or_insert(0) += 1;
        }
        if !(item.aslr && item.dep && item.cfg) {
            weak_mitigations.push(item);
        }
    }

    let mut depth_histogram: BTreeMap<usize, usize> = BTreeMap::new();
    for d in depths.values() {
        *depth_histogram.entry(*d).or_insert(0) += 1;
    }

    let name_of = |key: &str| modules.get(key).map(|m| m.name.clone()).unwrap_or_else(|| file_name(key));

    let mut top_fan_in: Vec<(String, usize)> =
        fan_in.iter().map(|(k, v)| (name_of(k), *v)).collect();
    top_fan_in.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top_fan_in.truncate(12);

    let mut top_fan_out: Vec<(String, usize)> =
        fan_out.iter().map(|(k, v)| (name_of(k), *v)).collect();
    top_fan_out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top_fan_out.truncate(12);

    let sort_pairs = |map: HashMap<&str, usize>| {
        let mut v: Vec<(String, usize)> =
            map.into_iter().map(|(k, c)| (k.to_string(), c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    };

    hijack_surface.sort_by(|a, b| a.name.cmp(&b.name));
    architecture_mismatch.sort_by(|a, b| a.name.cmp(&b.name));
    weak_mitigations.sort_by(|a, b| a.name.cmp(&b.name));
    missing_required.sort();
    missing_delayed.sort();

    Dashboard {
        totals: Totals {
            modules: modules.len(),
            resolved: modules.len(),
            missing: missing_required.len() + missing_delayed.len(),
            edges: edges.len(),
            max_depth: depths.values().copied().max().unwrap_or(0),
            import_functions,
            ordinal_imports,
            delay_import_modules,
        },
        strategies: sort_pairs(strategies),
        hijack_surface,
        missing_required,
        missing_delayed,
        architectures: sort_pairs(architectures),
        architecture_mismatch,
        dotnet_modules,
        native_modules: modules.len() - dotnet_modules,
        weak_mitigations,
        mitigation_counts: sort_pairs(mitigation_counts),
        top_fan_in,
        top_fan_out,
        depth_histogram: depth_histogram.into_iter().collect(),
    }
}
