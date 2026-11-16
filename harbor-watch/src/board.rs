//! The shift-board: the tool's face. A zero-JS local web page over the
//! store, rebuilt from the files on every request (files are the truth).
//! Dual representation: the board and every model page have markdown
//! twins, and the board serves its own llms.txt — the agents are users.
//!
//! Posture: loopback-only by default (the machine is the boundary);
//! --lan requires --token-file (the Waterfront admission law). Posture
//! headers on every response: CSP default-src 'none', capability-deny,
//! no-referrer, nosniff, no banner.

use std::path::{Path, PathBuf};

use crate::json;
use crate::receipts::ShiftLog;

pub struct Board {
    pub root: PathBuf,
}

struct ModelRow {
    name: String,
    publisher: String,
    jurisdiction: String,
    source: String,
    enrolled: String,
    shift_hours: f64,
    last_fit: String,
    checks: usize,
    unfit: usize,
    status: &'static str, // FIT | OVERDUE | UNFIT
    file_sha512: String,
}

impl Board {
    pub fn new(root: &Path) -> Board {
        Board { root: root.to_path_buf() }
    }

    /// The fleet, computed from the store (files are the truth).
    fn fleet(&self) -> Vec<ModelRow> {
        let mut rows = Vec::new();
        let enr_dir = self.root.join("enrollments");
        let Ok(listing) = std::fs::read_dir(&enr_dir) else { return rows };
        for entry in listing.filter_map(|e| e.ok()) {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else { continue };
            let Ok(v) = json::parse(&text) else { continue };
            let name = v.get("model").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let publisher = v.get("publisher").and_then(|x| x.as_str()).unwrap_or("unrecorded").to_string();
            let jurisdiction = v.get("jurisdiction").and_then(|x| x.as_str()).unwrap_or("unrecorded").to_string();
            let source = v.get("source").and_then(|x| x.as_str()).unwrap_or("https://huggingface.co").to_string();
            let enrolled = v.get("enrolled").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let shift_hours = v.get("shift_hours").and_then(|x| x.as_f64()).unwrap_or(24.0);
            let sha = v.get("whole_sha512").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let log = ShiftLog::open(&self.root.join("shifts"), &name);
            let entries = log.entries().unwrap_or_default();
            let checks = entries.iter().filter(|e| e.event == "shift_check").count();
            let unfit = entries.iter().filter(|e| e.result == "unfit").count();
            let last_fit = entries
                .iter()
                .rev()
                .find(|e| e.result == "fit" || e.event == "enrolled")
                .map(|e| e.ts.clone())
                .unwrap_or_else(|| "never".into());
            let stale_hours = last_fit_ts_hours(&last_fit).unwrap_or(f64::INFINITY);
            let status = if unfit > 0 {
                "UNFIT"
            } else if stale_hours > shift_hours {
                "OVERDUE"
            } else {
                "FIT"
            };
            rows.push(ModelRow { name, publisher, jurisdiction, source, enrolled, shift_hours, last_fit, checks, unfit, status, file_sha512: sha });
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }

    /// The fleet board (HTML).
    pub fn board_html(&self) -> String {
        let rows = self.fleet();
        let mut body = String::new();
        if rows.is_empty() {
            body.push_str("<p class=\"empty\">Nothing enrolled yet. The hire comes first: <code>harbor-watch enroll &lt;file&gt; --name &lt;model&gt;</code></p>");
        } else {
            body.push_str("<table><thead><tr><th>Model</th><th>Publisher</th><th>Origin · jurisdiction</th><th>Enrolled</th><th>Cadence</th><th>Shift checks</th><th>Unfit</th><th>Status</th></tr></thead><tbody>");
            for r in &rows {
                let pill = format!("<span class=\"pill {}\">{}</span>", r.status.to_lowercase(), r.status);
                let pill = format!("<span class=\"pill {}\">{}</span>", r.status.to_lowercase(), r.status);
                let origin = format!("{} · {}", r.source, r.jurisdiction);
                body.push_str(&format!(
                    "<tr><td><a href=\"/model/{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>every {}h</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    r.name, r.name, r.publisher, origin, r.enrolled, fmt_hours(r.shift_hours), r.checks, r.unfit, pill
                ));
            }
            body.push_str("</tbody></table>");
        }
        let fit = rows.iter().filter(|r| r.status == "FIT").count();
        let overdue = rows.iter().filter(|r| r.status == "OVERDUE").count();
        let unfit = rows.iter().filter(|r| r.status == "UNFIT").count();
        page(
            "The shift board",
            &format!(
                "<p class=\"summary\"><strong>{}</strong> fit · <strong>{}</strong> overdue · <strong>{}</strong> unfit — across {} enrolled models. Fitness class: fit-vs-enrollment; the baseline's cleanliness is the publisher's receipt.</p>{}",
                fit, overdue, unfit, rows.len(), body
            ),
        )
    }

    /// The fleet board (markdown twin, for the agents).
    pub fn board_md(&self) -> String {
        let rows = self.fleet();
        let mut out = String::from("# The shift board\n\nFitness for duty, per model — fit-vs-enrollment; the baseline's cleanliness is the publisher's receipt.\n\n");
        if rows.is_empty() {
            out.push_str("Nothing enrolled yet.\n");
        } else {
            out.push_str("| Model | Publisher | Enrolled | Cadence | Checks | Unfit | Last fit | Status |\n|---|---|---|---|---|---|---|---|\n");
            for r in &rows {
                out.push_str(&format!(
                    "| [{}](/model/{}.md) | {} | {} | every {}h | {} | {} | {} | **{}** |\n",
                    r.name, r.name, r.publisher, r.enrolled, fmt_hours(r.shift_hours), r.checks, r.unfit, r.last_fit, r.status
                ));
            }
        }
        out
    }

    /// One model's page (HTML): the enrollment receipt + the shift log.
    pub fn model_html(&self, name: &str) -> Option<String> {
        let enr = self.root.join("enrollments").join(format!("{}.json", name));
        let text = std::fs::read_to_string(&enr).ok()?;
        let v = json::parse(&text).ok()?;
        let log = ShiftLog::open(&self.root.join("shifts"), name);
        let entries = log.entries().unwrap_or_default();
        let chain = log.verify().is_ok();

        let tensor_count = match v.get("tensors") {
            Some(json::Value::Arr(a)) => a.len(),
            _ => 0,
        };
        let mut body = String::new();
        body.push_str(&format!(
            "<p class=\"summary\">Enrolled <strong>{}</strong> by <strong>{}</strong> · cadence every {}h · {} tensors · honesty class: fit-vs-enrollment.</p>",
            v.get("enrolled").and_then(|x| x.as_str()).unwrap_or("?"),
            v.get("publisher").and_then(|x| x.as_str()).unwrap_or("unrecorded"),
            fmt_hours(v.get("shift_hours").and_then(|x| x.as_f64()).unwrap_or(24.0)),
            tensor_count
        ));
        body.push_str(&format!(
            "<p>whole sha512: <code>{}</code></p>",
            v.get("whole_sha512").and_then(|x| x.as_str()).unwrap_or("?")
        ));
        body.push_str(&format!(
            "<p>shift-log chain: <span class=\"pill {}\">{}</span></p>",
            if chain { "fit" } else { "unfit" },
            if chain { "INTACT" } else { "BROKEN" }
        ));
        body.push_str("<table><thead><tr><th>When</th><th>Event</th><th>Result</th><th>Detail</th></tr></thead><tbody>");
        for e in &entries {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><span class=\"pill {}\">{}</span></td><td>{}</td></tr>",
                e.ts, e.event, e.result, e.result, esc_html(&e.detail)
            ));
        }
        body.push_str("</tbody></table>");
        Some(page(&format!("{} — the shift log", name), &body))
    }

    /// One model's page (markdown twin).
    pub fn model_md(&self, name: &str) -> Option<String> {
        let enr = self.root.join("enrollments").join(format!("{}.json", name));
        let text = std::fs::read_to_string(&enr).ok()?;
        let v = json::parse(&text).ok()?;
        let log = ShiftLog::open(&self.root.join("shifts"), name);
        let entries = log.entries().unwrap_or_default();
        let chain = log.verify().is_ok();
        let mut out = format!(
            "# {} — the shift log\n\nEnrolled {} by {} · cadence every {}h · honesty class: fit-vs-enrollment · chain: {}.\n\n",
            name,
            v.get("enrolled").and_then(|x| x.as_str()).unwrap_or("?"),
            v.get("publisher").and_then(|x| x.as_str()).unwrap_or("unrecorded"),
            fmt_hours(v.get("shift_hours").and_then(|x| x.as_f64()).unwrap_or(24.0)),
            if chain { "INTACT" } else { "BROKEN" }
        );
        out.push_str("| When | Event | Result | Detail |\n|---|---|---|---|\n");
        for e in &entries {
            out.push_str(&format!("| {} | {} | {} | {} |\n", e.ts, e.event, e.result, esc_md(&e.detail)));
        }
        Some(out)
    }

    /// The board's own llms.txt.
    pub fn llms_txt(&self) -> String {
        let rows = self.fleet();
        let mut out = String::from(
            "# The shift board\n\n> harbor-watch: fitness-for-duty attestation for model weights. The model was never verified by buying it; it proves it is still the same weights, every shift, every day. Fitness class: fit-vs-enrollment — the baseline's cleanliness is the publisher's receipt.\n\n## Models\n\n",
        );
        for r in &rows {
            out.push_str(&format!(
                "- [{}](/model/{}.md): {} shift checks, {} unfit, last fit {}, status {}.\n",
                r.name, r.name, r.checks, r.unfit, r.last_fit, r.status
            ));
        }
        out.push_str("\n## Optional\n\n- [The board as Markdown](/board.md): this page, for agents.\n- [Tool](https://github.com/sustainabilities/welcome-wagon): the harbor-watch source and proofs.\n");
        out
    }
}

fn last_fit_ts_hours(ts: &str) -> Option<f64> {
    if ts == "never" {
        return Some(f64::INFINITY);
    }
    Some(hours_since(ts))
}

fn hours_since(ts: &str) -> f64 {
    fn parse(s: &str) -> f64 {
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

fn fmt_hours(h: f64) -> String {
    if h.fract() == 0.0 { format!("{}", h as u64) } else { format!("{:.1}", h) }
}

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn esc_md(s: &str) -> String {
    s.replace('|', "\\|")
}

/// The page shell: posture-clean, zero-JS, the board's own CSS served
/// from /board.css (CSP style-src 'self' — no inline styles).
fn page(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{t} | harbor-watch</title><link rel=\"stylesheet\" href=\"/board.css\"></head><body><header class=\"board-header\"><span class=\"mark\">⚓</span><strong>harbor-watch</strong> — the shift board<a class=\"md\" href=\"/board.md\">.md</a></header><main>{b}</main><footer class=\"board-foot\">fitness class: fit-vs-enrollment · the baseline's cleanliness is the publisher's receipt · files are the truth</footer></body></html>",
        t = esc_html(title),
        b = body
    )
}

pub const BOARD_CSS: &str = r#"body{margin:0;font:15px/1.5 "Inter",-apple-system,sans-serif;background:#0F1B2D;color:#E9EEF6}main{max-width:1100px;margin:0 auto;padding:24px}a{color:#3B82F6}.board-header{display:flex;gap:12px;align-items:center;padding:14px 24px;border-bottom:1px solid #263A5C;background:#1B2A4A}.board-header .mark{color:#2563EB}.board-header .md{margin-left:auto;font-size:12px;border:1px solid #263A5C;padding:2px 8px;border-radius:4px;text-decoration:none}table{width:100%;border-collapse:collapse;margin:14px 0}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #263A5C;font-size:14px}th{color:#93A7C4;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.08em}.pill{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:700}.pill.fit{background:#123B2A;color:#7FD1A8}.pill.overdue{background:#3B3115;color:#E3B34E}.pill.unfit{background:#3B1B1B;color:#E5735F}.summary{color:#93A7C4}.empty{color:#93A7C4}code{background:#142238;padding:2px 6px;border-radius:4px;font-size:13px}.footer-note{color:#5F7699;font-size:13px}.board-foot{max-width:1100px;margin:0 auto;padding:16px 24px;color:#5F7699;font-size:12px;border-top:1px solid #263A5C}"#;
