# LoadScope

A Windows PE dependency viewer written in Rust, served as a local web app.

Point it at an `.exe` or `.dll` and it walks the dependency chain the way the
Windows loader would, showing where every module was resolved from, what it
imports and exports, and a dashboard of what the graph says about the binary.

The dependency resolution policy was reconstructed from the shipped binaries of
[Dependencies](https://github.com/lucasg/Dependencies) through static analysis.
The PE parser, the ApiSet schema reader and the CLI metadata reader are new
implementations written against the published formats.

## Features

### Explorer

- **Dependency tree** showing the resolved path and the search strategy for
  every module, with delay imports and duplicates marked
- **Imports** with ordinal, hint, function name and the resolved module path;
  IL-only assemblies show their `AssemblyRef` table instead
- **Exports** with ordinal, virtual address and forwarder target
- **Module list** with machine type, file size, image base, virtual size,
  entry point, subsystem, checksum and search strategy
- Native file picker, resizable panels, dark theme, English and Korean

### Dashboard

| Card | What it answers |
| --- | --- |
| Overview | Module and edge counts, depth, unresolved names, imported functions, ordinal imports |
| Search order hijacking surface | Which modules were resolved from writable locations (MITRE ATT&CK T1574.001) |
| Unresolved modules | Required versus delay-imported names that did not resolve |
| Where modules come from | Search strategy distribution, writable locations highlighted |
| Mitigation coverage | ASLR / DEP / CFG / HighEntropyVA from `DllCharacteristics`, plus the modules missing one |
| Fan-in / fan-out | Most depended upon and most dependent modules |
| Architecture | Machine type mix and modules that cannot share the root's process |
| Depth distribution | How far from the root each module first appears |

## What it resolves

Module names are resolved in the order the original tool declares its
`ModuleSearchStrategy` values:

```
ROOT, SxS, ApiSetSchema, WellKnownDlls, ApplicationDirectory, System32Folder,
WindowsFolder, WorkingDirectory, Environment, AppInitDLL, Fullpath,
ClrAssembly, UserDefined, NOT_FOUND
```

Implemented: ApiSet schema (parsed from `apisetschema.dll`), KnownDLLs from the
registry, application and system directories, `PATH`, full paths, and CLR
assemblies through the GAC and the framework directories.

Not implemented: WinSxS matching, `AppInitDLL`. Those strategies still exist as
labels. See [docs/verification.md](docs/verification.md) for the exact boundary.

## Requirements

- Windows
- Rust 1.70 or newer

Only `serde` and `serde_json` are pulled in. The HTTP server is written against
the standard library, which also keeps the build working on toolchains where
crates that need `raw-dylib` cannot be compiled.

## Build and run

```bat
run.bat
```

`run.bat [port]` builds the binary if it is missing, opens a browser and starts
the server. The default port is 7878 and it binds to `127.0.0.1` only.

Manually:

```bat
cargo build --release
target\release\loadscope.exe 7878
```

Then open <http://127.0.0.1:7878>.

## HTTP API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/analyze` | Body `{path, depth, extra_dirs}`. Returns the chain, every module's details and the dashboard metrics |
| `GET` | `/api/browse` | Opens a native file picker and returns `{path}`, or `{path: null}` when cancelled |
| `GET` | `/api/knowndlls` | KnownDLLs from the registry. `?arch=x86` for the 32-bit view |
| `GET` | `/api/apisets` | The parsed ApiSet schema as apiset name to host DLL |

```bat
curl -s -X POST http://127.0.0.1:7878/api/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"path\":\"C:\\Windows\\System32\\notepad.exe\",\"depth\":3}"
```

## Layout

```
src/
  main.rs       routes and request handling
  http.rs       minimal HTTP/1.1 server
  pe.rs         PE parser: headers, sections, imports, exports, resources
  dotnet.rs     CLI metadata reader for AssemblyRef and ModuleRef
  apiset.rs     API_SET_NAMESPACE v6 schema reader
  resolve.rs    search strategies and dependency chain walking
  dashboard.rs  graph and security metrics
static/         single page front end, no build step
docs/           analysis notes and verification results
```

## Accuracy

Output was compared against the original tool's CLI:

- `ClrPhlib.dll` — 22 import modules, every function set identical
- `kernel32.dll` — all 1698 exports match by name and ordinal, forwarders included
- `DependenciesGui.exe` — 13 assembly references match, in the same order

Details in [docs/verification.md](docs/verification.md).

## Design notes

The documents under `docs/` are written in Korean.

- [docs/rea-analysis-report.md](docs/rea-analysis-report.md) — how the original
  binaries were analysed and how each finding was used here
- [docs/reverse-engineering-notes.md](docs/reverse-engineering-notes.md) —
  the reconstructed facts, separating observation from inference
- [docs/dashboard-rationale.md](docs/dashboard-rationale.md) — why these metrics
- [docs/verification.md](docs/verification.md) — comparison results and limits
