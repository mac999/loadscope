mod apiset;
mod dashboard;
mod dotnet;
mod http;
mod pe;
mod resolve;

use http::{Request, Response};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct AnalyzeRequest {
    path: String,
    #[serde(default = "default_depth")]
    depth: usize,
    #[serde(default)]
    extra_dirs: Vec<String>,
}

fn default_depth() -> usize {
    4
}

fn handle(req: &Request) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => Response::ok("text/html; charset=utf-8", include_str!("../static/index.html")),
        ("GET", "/app.js") => Response::ok(
            "application/javascript; charset=utf-8",
            include_str!("../static/app.js"),
        ),
        ("GET", "/style.css") => Response::ok(
            "text/css; charset=utf-8",
            include_str!("../static/style.css"),
        ),
        ("GET", "/api/knowndlls") => {
            let is_64 = req.query.get("arch").map(String::as_str) != Some("x86");
            let mut names: Vec<String> = resolve::read_known_dlls(is_64).into_iter().collect();
            names.sort();
            Response::json(
                200,
                &serde_json::json!({
                    "arch": if is_64 { "x64" } else { "x86" },
                    "known_dlls": names,
                }),
            )
        }
        ("GET", "/api/browse") => browse(),
        ("GET", "/api/apisets") => {
            let system = std::path::Path::new(
                &std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()),
            )
            .join("System32");
            let map = apiset::load(&system);
            let mut pairs: Vec<(String, String)> = map.into_iter().collect();
            pairs.sort();
            Response::json(
                200,
                &serde_json::json!({ "count": pairs.len(), "api_sets": pairs }),
            )
        }
        ("POST", "/api/analyze") => analyze(&req.body),
        _ => Response::ok("text/plain; charset=utf-8", "not found").with_status(404),
    }
}

/// Native file picker. Browsers withhold the full path for security reasons,
/// so the server shows a WinForms OpenFileDialog and returns the chosen path.
fn browse() -> Response {
    const SCRIPT: &str = "Add-Type -AssemblyName System.Windows.Forms; \
         $d = New-Object System.Windows.Forms.OpenFileDialog; \
         $d.Title = 'Select a PE file'; \
         $d.Filter = 'PE files (*.exe;*.dll;*.sys;*.ocx)|*.exe;*.dll;*.sys;*.ocx|All files (*.*)|*.*'; \
         if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write($d.FileName) }";

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", SCRIPT])
        .output();

    match output {
        Ok(o) => {
            let path = String::from_utf8_lossy(&o.stdout).trim().to_string();
            Response::json(
                200,
                &serde_json::json!({ "path": if path.is_empty() { None } else { Some(path) } }),
            )
        }
        Err(e) => Response::json(500, &serde_json::json!({ "error": e.to_string() })),
    }
}

fn analyze(body: &str) -> Response {
    let req: AnalyzeRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => {
            return Response::json(400, &serde_json::json!({ "error": e.to_string() }));
        }
    };
    let dirs: Vec<PathBuf> = req.extra_dirs.iter().map(PathBuf::from).collect();
    let depth = req.depth.clamp(1, 16);

    match resolve::analyze(&req.path, depth, dirs) {
        Ok(result) => Response::json(200, &result),
        Err(e) => Response::json(400, &serde_json::json!({ "error": e })),
    }
}

fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(7878);

    if let Err(e) = http::serve(port, handle) {
        eprintln!("loadscope: {e}");
        std::process::exit(1);
    }
}
