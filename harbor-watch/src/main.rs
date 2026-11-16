//! harbor-watch: fitness-for-duty attestation for model weights.
//!
//!   harbor-watch enroll <file> --name <model> [--publisher P] [--note N]
//!       The hire: hash the whole file and every tensor (safetensors),
//!       write the enrollment receipt, open the shift log.
//!   harbor-watch check <file> [--name <model>]
//!       The shift: re-hash, diff against the enrollment, append the
//!       fitness verdict to the hash-chained shift log.
//!   harbor-watch log <model>
//!       Show the shift history.
//!   harbor-watch verify <model>
//!       Re-hash the shift log's chain: tamper evidence.
//!   harbor-watch report <model>
//!       The fitness summary: enrolled, checks, last fit, drift events.
//!
//! Honesty class: this tool attests FIT-VS-ENROLLMENT. It cannot attest
//! that the enrollment itself was clean — that is the publisher's
//! receipt. The store lives beside the models: <root>/enrollments/ and
//! <root>/shifts/ (default root: ./harbor-watch-store).

use harbor_watch::{board, http, json, receipts::ShiftLog, safetensors, sha512};
use std::path::{Path, PathBuf};
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    let mut root = PathBuf::from("harbor-watch-store");
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" if i + 1 < args.len() => {
                root = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            _ => {
                rest.push(args[i].clone());
                i += 1;
            }
        }
    }
    let cmd = if cmd.is_empty() { rest.first().map(|s| s.as_str()).unwrap_or("") } else { cmd };
    match cmd {
        "enroll" => cmd_enroll(&root, &rest[1..]),
        "check" => cmd_check(&root, &rest[1..]),
        "log" => cmd_log(&root, rest.get(1).map(|s| s.as_str()).unwrap_or("")),
        "verify" => cmd_verify(&root, rest.get(1).map(|s| s.as_str()).unwrap_or("")),
        "report" => cmd_report(&root, rest.get(1).map(|s| s.as_str()).unwrap_or("")),
        "serve" => cmd_serve(&root, &rest[1..]),
        _ => {
            eprintln!("usage: harbor-watch <enroll|check|log|verify|report|serve> [args] [--root <dir>]");
            std::process::exit(2);
        }
    }
}

/// The shift-board server: the tool's face. Loopback by default (the
/// machine is the boundary); --lan requires --token-file (the
/// admission law). Zero-JS; rebuilt from the store on every request.
fn cmd_serve(root: &Path, args: &[String]) {
    let port = flag(args, "--port").unwrap_or_else(|| "9003".to_string());
    let lan = args.iter().any(|a| a == "--lan");
    let bind = format!("{}:{}", if lan { "0.0.0.0" } else { "127.0.0.1" }, port);
    let token: Option<String> = if lan {
        match flag(args, "--token-file").map(|p| std::fs::read_to_string(p)) {
            Some(Ok(t)) if !t.trim().is_empty() => Some(t.trim().to_string()),
            _ => {
                eprintln!("refused: --lan requires --token-file (the admission law)");
                exit(2)
            }
        }
    } else {
        None
    };
    let board = std::sync::Arc::new(board::Board::new(root));
    let adm = http::Admission {
        token: token.clone(),
        token_fp: token.as_ref().map(|t| sha512::hex(&sha512::digest(t.as_bytes()))[..8].to_string()),
    };
    let handler: http::Handler = {
        let board = board.clone();
        std::sync::Arc::new(move |req| {
            let p = req.path.clone();
            if p == "/" || p == "/board" {
                return html_response(board.board_html())
            }
            if p == "/board.md" {
                return md_response(board.board_md())
            }
            if p == "/llms.txt" {
                return text_response(&board.llms_txt(), "text/markdown; charset=utf-8")
            }
            if p == "/board.css" {
                return text_response(board::BOARD_CSS, "text/css; charset=utf-8")
            }
            if let Some(name) = p.strip_prefix("/model/") {
                let bare = name.trim_end_matches(".md");
                if name.ends_with(".md") {
                    return match board.model_md(bare) {
                        Some(md) => md_response(md),
                        None => text_response("no such model", "text/plain; charset=utf-8").with_status(404),
                    }
                }
                return match board.model_html(bare) {
                    Some(h) => html_response(h),
                    None => text_response("no such model", "text/plain; charset=utf-8").with_status(404),
                }
            }
            text_response("not found", "text/plain; charset=utf-8").with_status(404)
        })
    };
    println!("harbor-watch shift-board on {} (store: {})", bind, root.display());
    println!("admission: {}", if token.is_some() { "bearer token on the API (headers only)" } else { "loopback — the machine is the boundary" });
    if let Err(e) = http::serve(&bind, adm, handler) {
        eprintln!("{}", e);
        exit(1)
    }
}

fn html_response(body: String) -> http::Response {
    http::Response::new_html(body)
}

fn md_response(body: String) -> http::Response {
    http::Response::new_md(body)
}

fn text_response(body: &str, ct: &str) -> http::Response {
    http::Response::new_text(body, ct)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn positional(args: &[String]) -> Option<String> {
    args.iter().find(|a| !a.starts_with("--")).cloned()
}

fn enroll_path(root: &Path, model: &str) -> PathBuf {
    root.join("enrollments").join(format!("{}.json", model))
}

fn read_enrollment(root: &Path, model: &str) -> Result<json::Value, String> {
    let p = enroll_path(root, model);
    let text = std::fs::read_to_string(&p).map_err(|_| format!("no enrollment for {:?} at {} — run: harbor-watch enroll <file> --name {}", model, p.display(), model))?;
    json::parse(&text).map_err(|e| format!("enrollment {}: {}", p.display(), e))
}

fn cmd_enroll(root: &Path, args: &[String]) {
    let file = positional(args).unwrap_or_else(|| {
        eprintln!("usage: harbor-watch enroll <file> --name <model> [--publisher P] [--note N] [--shift-hours H]");
        exit(2);
    });
    let name = flag(args, "--name").unwrap_or_else(|| {
        eprintln!("enroll requires --name <model>");
        exit(2);
    });
    let publisher = flag(args, "--publisher").unwrap_or_default();
    let note = flag(args, "--note").unwrap_or_default();
    let shift_hours: u64 = flag(args, "--shift-hours").and_then(|s| s.parse().ok()).unwrap_or(24);
    let attest_clean = flag(args, "--attest-clean");
    let attest_reason = flag(args, "--attest-reason").unwrap_or_default();

    // THE STOP-RULE AS MECHANISM: re-enrolling over an existing model —
    // especially one with unfit events — is the forbidden move. It
    // requires the explicit attest-clean flag WITH a reason, and the
    // reason is receipted in the shift log forever.
    let p = enroll_path(root, &name);
    if p.exists() {
        let log = ShiftLog::open(&root.join("shifts"), &name);
        let had_unfit = log.entries().map(|es| es.iter().any(|e| e.result == "unfit")).unwrap_or(false);
        if !attest_clean.is_some() {
            eprintln!("REFUSED: {} is already enrolled — re-enrolling over it would silence the record.", name);
            eprintln!("  If the weights were re-verified against their SOURCE and found sound,");
            eprintln!("  re-run with --attest-clean --attest-reason \"why this is sound\".");
            eprintln!("  The reason is receipted in the shift log forever. Nothing blurred.");
            exit(1);
        }
        if attest_clean.unwrap().is_empty() || attest_reason.is_empty() {
            eprintln!("REFUSED: --attest-clean requires --attest-reason \"why this is sound\".");
            exit(1);
        }
        let reason = format!("RE-ENROLLMENT ATTESTED CLEAN by operator; reason: {}", attest_reason);
        let re_note = if had_unfit { " (over prior UNFIT events)" } else { "" };
        log.append("re_enrolled", "attested", "", &format!("{}{}", reason, re_note));
        println!("RE-ENROLLMENT ATTESTED{} — the reason is receipted in the shift log.", re_note);
    }
    let path = Path::new(&file);
    let wf = safetensors::hash_file(path).unwrap_or_else(|e| {
        eprintln!("refused: {}", e);
        exit(1);
    });
    let mut receipt = format!(
        "{{\"model\":\"{}\",\"file\":\"{}\",\"size\":{},\"kind\":\"{}\",\"whole_sha512\":\"{}\",\"enrolled\":\"{}\",\"shift_hours\":{}",
        name, file, wf.size, if wf.kind == safetensors::Kind::Safetensors { "safetensors" } else { "opaque" }, wf.whole_sha512, harbor_watch::today(), shift_hours
    );
    if !publisher.is_empty() {
        receipt.push_str(&format!(",\"publisher\":\"{}\"", publisher));
    }
    if !note.is_empty() {
        receipt.push_str(&format!(",\"note\":\"{}\"", note));
    }
    if !wf.tensors.is_empty() {
        receipt.push_str(",\"tensors\":[");
        for (idx, (t, h)) in wf.tensors.iter().enumerate() {
            if idx > 0 {
                receipt.push(',');
            }
            receipt.push_str(&format!("{{\"name\":\"{}\",\"dtype\":\"{}\",\"sha512\":\"{}\"}}", t.name, t.dtype, h));
        }
        receipt.push(']');
    }
    receipt.push('}');
    let p = enroll_path(root, &name);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("create enrollments dir");
    }
    std::fs::write(&p, &receipt).unwrap_or_else(|e| {
        eprintln!("write {}: {}", p.display(), e);
        exit(1);
    });
    let log = ShiftLog::open(&root.join("shifts"), &name);
    log.append("enrolled", "enrolled", &wf.whole_sha512, &format!("{} tensors enrolled", wf.tensors.len()));
    println!("ENROLLED  {} ({} bytes, {})", name, wf.size, if wf.kind == safetensors::Kind::Safetensors { "safetensors" } else { "opaque" });
    println!("  whole sha512: {}", wf.whole_sha512);
    println!("  tensors enrolled: {}", wf.tensors.len());
    println!("  receipt: {}", p.display());
    println!();
    println!("  honesty class: fit-vs-enrollment. The baseline's cleanliness is attested by its publisher, not by this tool.");
    println!("  The shift checks begin: harbor-watch check <file> --name {}", name);
}

/// Hours elapsed since an ISO-8601 UTC timestamp (the cadence math).
fn hours_since(ts: &str) -> f64 {
    fn parse(s: &str) -> f64 {
        // YYYY-MM-DDTHH:MM:SSZ → seconds (civil → days via the inverse
        // of the Hinnant algorithm; only needs to be monotone-correct)
        let b = s.as_bytes();
        if s.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
            return 0.0;
        }
        let y: i64 = s[0..4].parse().unwrap_or(1970);
        let mo: i64 = s[5..7].parse().unwrap_or(1);
        let d: i64 = s[8..10].parse().unwrap_or(1);
        let hh: f64 = s[11..13].parse().unwrap_or(0.0);
        let mm: f64 = s[14..16].parse().unwrap_or(0.0);
        let ss: f64 = s[17..19].parse().unwrap_or(0.0);
        // days from civil (Hinnant)
        let y2 = if mo <= 2 { y - 1 } else { y };
        let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
        let yoe = y2 - era * 400;
        let mp = if mo > 2 { mo - 3 } else { mo + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146_097 + doe;
        (days * 86_400) as f64 + hh * 3600.0 + mm * 60.0 + ss
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as f64;
    now - parse(ts)
}

fn cmd_check(root: &Path, args: &[String]) {
    let file = positional(args).unwrap_or_else(|| {
        eprintln!("usage: harbor-watch check <file> [--name <model>]");
        exit(2);
    });
    let name = match flag(args, "--name") {
        Some(n) => n,
        None => Path::new(&file).file_stem().and_then(|s| s.to_str()).unwrap_or("model").to_string(),
    };
    let enrollment = read_enrollment(root, &name).unwrap_or_else(|e| {
        eprintln!("refused: {}", e);
        exit(1);
    });
    let enrolled_hash = enrollment.get("whole_sha512").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let path = Path::new(&file);
    let wf = safetensors::hash_file(path).unwrap_or_else(|e| {
        eprintln!("refused: {}", e);
        exit(1);
    });
    let log = ShiftLog::open(&root.join("shifts"), &name);
    // THE CADENCE AS MECHANISM: the enrollment carries shift_hours; the
    // check computes staleness against the last fit. FIT is not the
    // whole verdict — a fit-but-stale model is OVERDUE, and the tool
    // says so. The bell is part of the thing, not a operator memory test.
    let shift_hours = enrollment.get("shift_hours").and_then(|v| v.as_f64()).unwrap_or(24.0);
    let last_fit_ts = log.entries().ok().and_then(|es| es.iter().rev().find(|e| e.result == "fit" || e.event == "enrolled").map(|e| e.ts.clone()));
    let overdue = last_fit_ts.as_ref().map(|ts| hours_since(ts)).unwrap_or(f64::INFINITY) > shift_hours;
    if wf.whole_sha512 == enrolled_hash {
        log.append("shift_check", "fit", &wf.whole_sha512, "");
        if overdue {
            println!("FIT FOR DUTY — but OVERDUE  {}", name);
            println!("  the weights are the ones enrolled on {}", enrollment.get("enrolled").and_then(|v| v.as_str()).unwrap_or("?"));
            println!("  cadence: every {}h — this check came {}h after the last fit", shift_hours, last_fit_ts.as_ref().map(|ts| format!("{:.1}", hours_since(ts))).unwrap_or("?".into()));
            println!("  the bell rings: tighten the shift cadence or widen the enrollment.");
        } else {
            println!("FIT FOR DUTY  {}", name);
            println!("  the weights are the ones enrolled on {}", enrollment.get("enrolled").and_then(|v| v.as_str()).unwrap_or("?"));
        }
        println!("  sha512: {}", wf.whole_sha512);
        println!("  honesty class: fit-vs-enrollment ({}).", if wf.kind == safetensors::Kind::Safetensors { format!("{} tensors verified", wf.tensors.len()) } else { "whole-file".to_string() });
    } else {
        // localize the change when we can
        let enrolled = safetensors::hash_file(Path::new(&enrollment.get("file").and_then(|v| v.as_str()).unwrap_or(""))).ok();
        let detail = match enrolled {
            Some(ref orig) => {
                let changed = safetensors::diff(orig, &wf);
                let names: Vec<String> = changed.iter().take(8).cloned().collect();
                let more = if changed.len() > 8 { format!(" (+{} more)", changed.len() - 8) } else { String::new() };
                format!("changed tensors: {}{}", names.join(", "), more)
            }
            None => "whole-file hash differs from enrollment".to_string(),
        };
        log.append("shift_check", "unfit", &wf.whole_sha512, &detail);
        println!("UNFIT FOR DUTY  {}", name);
        println!("  the weights are NOT the ones enrolled.");
        println!("  enrolled:  {}", enrolled_hash);
        println!("  current:   {}", wf.whole_sha512);
        println!("  {}", detail);
        println!();
        println!("  A Lazarus-class edit changes few tensors; the diff above localizes it. Do not load this checkpoint for trusted work.");
        std::process::exit(1);
    }
}

fn cmd_log(root: &Path, model: &str) {
    if model.is_empty() {
        eprintln!("usage: harbor-watch log <model>");
        exit(2);
    }
    let log = ShiftLog::open(&root.join("shifts"), model);
    match log.entries() {
        Ok(entries) => {
            println!("shift log for {} ({} entries):", model, entries.len());
            for e in entries {
                println!("  {}  {:<12} {:<8} {}", e.ts, e.event, e.result, if e.detail.is_empty() { String::new() } else { e.detail.clone() });
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            exit(1);
        }
    }
}

fn cmd_verify(root: &Path, model: &str) {
    if model.is_empty() {
        eprintln!("usage: harbor-watch verify <model>");
        exit(2);
    }
    let log = ShiftLog::open(&root.join("shifts"), model);
    match log.verify() {
        Ok(n) => println!("chain intact: {} entries verified for {}", n, model),
        Err(e) => {
            eprintln!("CHAIN BROKEN: {}", e);
            exit(1);
        }
    }
}

fn cmd_report(root: &Path, model: &str) {
    if model.is_empty() {
        eprintln!("usage: harbor-watch report <model>");
        exit(2);
    }
    let enrollment = read_enrollment(root, model).unwrap_or_else(|e| {
        eprintln!("refused: {}", e);
        exit(1);
    });
    let log = ShiftLog::open(&root.join("shifts"), model);
    let entries = log.entries().unwrap_or_default();
    let checks = entries.iter().filter(|e| e.event == "shift_check").count();
    let unfit = entries.iter().filter(|e| e.result == "unfit").count();
    let last_fit = entries.iter().rev().find(|e| e.result == "fit").map(|e| e.ts.clone()).unwrap_or_else(|| "never".into());
    println!("FITNESS REPORT — {}", model);
    println!("  enrolled:     {} ({})", enrollment.get("enrolled").and_then(|v| v.as_str()).unwrap_or("?"), enrollment.get("publisher").and_then(|v| v.as_str()).unwrap_or("publisher unrecorded"));
    println!("  sha512:       {}", enrollment.get("whole_sha512").and_then(|v| v.as_str()).unwrap_or("?"));
    println!("  shift checks: {} total, {} unfit", checks, unfit);
    println!("  last fit:     {}", last_fit);
    println!("  honesty class: fit-vs-enrollment — the baseline's cleanliness is the publisher's receipt.");
}
