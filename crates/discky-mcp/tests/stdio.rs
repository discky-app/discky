//! End-to-end: drive the `discky-mcp` binary over stdio with hand-written JSON-RPC.

#[path = "../../discky-core/tests/fixtures.rs"]
mod fixtures;

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use serde_json::{Value, json};

const READ_TIMEOUT: Duration = Duration::from_secs(60);

struct Mcp {
    child: Child,
    stdin: ChildStdin,
    /// Lines read from the server's stdout by a reader thread, so a hung server fails
    /// the test after [`READ_TIMEOUT`] instead of blocking forever.
    lines: Receiver<String>,
    next: u64,
}

impl Mcp {
    /// Start the server on `home` (also its `$HOME`, so the fixture trees under it are
    /// where the build-dir pass looks), with a fake trash binary that `mv`s its arguments
    /// into `<home>/trashed/`, so tests never touch the real Trash.
    fn start(home: &Path) -> Mcp {
        let bin = home.join("trash");
        let trashed = home.join("trashed");
        std::fs::create_dir_all(&trashed).unwrap();
        std::fs::write(
            &bin,
            format!("#!/bin/sh\nmv \"$@\" \"{}\"/\n", trashed.display()),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let mut child = Command::new(assert_cmd::cargo::cargo_bin!("discky-mcp"))
            .arg("--home")
            .arg(home)
            .env("DISCKY_TRASH_BIN", &bin)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn discky-mcp");
        let stdin = child.stdin.take().unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in out.lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Mcp {
            child,
            stdin,
            lines,
            next: 1,
        }
    }

    fn send(&mut self, msg: &Value) {
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// Send a request and return the response with the same id; notifications and other
    /// messages in between are skipped. Sends `notifications/initialized` after
    /// `initialize`.
    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let response = loop {
            let line = match self.lines.recv_timeout(READ_TIMEOUT) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => panic!("no response to {method} within 60 s"),
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("server closed stdout while waiting for {method}")
                }
            };
            let msg: Value = serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line}"));
            if msg["id"] == json!(id) && msg.get("method").is_none() {
                break msg;
            }
        };
        if method == "initialize" {
            self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        }
        response
    }

    fn tool(&mut self, name: &str, args: Value) -> Value {
        let r = self.call("tools/call", json!({"name": name, "arguments": args}));
        assert_ne!(r["result"]["isError"], true, "{name} failed: {r}");
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no text content: {r}"));
        serde_json::from_str(text).unwrap()
    }

    fn initialize(&mut self) -> Value {
        self.call(
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        )
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn full_flow_scan_findings_plan_refused_then_allowed() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(&d.path().join("tree"));
    let tree = d.path().join("tree");
    std::fs::write(
        d.path().join("config.toml"),
        format!("[scan]\nroots = [\"{}\"]\n", tree.display()),
    )
    .unwrap();
    let mut m = Mcp::start(d.path());
    let init = m.initialize();
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(init["result"]["capabilities"]["resources"].is_object());
    assert!(
        init["result"]["instructions"]
            .as_str()
            .unwrap()
            .contains("disk_overview")
    );
    let tools = m.call("tools/list", json!({}));
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    for n in [
        "disk_overview",
        "scan",
        "scan_status",
        "findings",
        "tree",
        "search",
        "inspect",
        "plan_removal",
        "execute_plan",
        "history",
    ] {
        assert!(names.contains(&n.to_string()), "{n}");
    }

    let ov = m.tool("disk_overview", json!({}));
    assert!(ov["snapshot_at"].is_null());
    assert_eq!(ov["stale"], true);
    // Without the Tasks extension `scan` answers with a plain result, never a task.
    let r = m.call("tools/call", json!({"name": "scan", "arguments": {}}));
    assert_ne!(r["result"]["resultType"], "task", "{r}");
    assert!(r["result"]["content"].is_array(), "{r}");
    let sc = m.tool("scan", json!({"wait_seconds": 30}));
    assert_eq!(sc["status"]["kind"], "done", "{sc}");
    let st = m.tool("scan_status", json!({"scan_id": sc["scan_id"]}));
    assert_eq!(st["kind"], "done");
    let f = m.tool("findings", json!({"category": "project_builds"}));
    // The fixture's Cargo.toml is not valid TOML, so `cargo clean` would fail: use the
    // `node_modules` finding, which is removed by path.
    let item = f["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["removal_kind"] == "trash")
        .unwrap_or_else(|| panic!("no trash finding in {f}"))
        .clone();
    let id = item["id"].as_str().unwrap().to_string();
    assert!(item.get("node").is_none());
    let kind = item["removal_kind"].as_str().unwrap();
    assert!(item["removal"].get(kind).is_some(), "{item}");
    assert!(item["human_size"].as_str().unwrap().ends_with("B"));

    let t = m.tool("tree", json!({"path": tree, "limit": 3}));
    assert_eq!(t["entries"].as_array().unwrap().len(), 3);
    let s = m.tool("search", json!({"name_glob": "*.rlib"}));
    assert_eq!(s["entries"].as_array().unwrap().len(), 3);
    let i = m.tool("inspect", json!({"target": &id}));
    assert_eq!(i["in_snapshot"], true);

    let resources = m.call("resources/list", json!({}));
    assert_eq!(
        resources["result"]["resources"].as_array().unwrap().len(),
        3
    );
    let summary = m.call(
        "resources/read",
        json!({"uri": "discky://snapshot/summary"}),
    );
    let text = summary["result"]["contents"][0]["text"].as_str().unwrap();
    assert!(serde_json::from_str::<Value>(text).unwrap()["snapshot_at"].is_number());

    let plan = m.tool("plan_removal", json!({"finding_ids": [id]}));
    assert!(plan["human_total"].is_string());
    let plan_id = plan["id"].as_str().unwrap().to_string();
    let r = m.call(
        "tools/call",
        json!({"name": "execute_plan", "arguments": {"plan_id": plan_id}}),
    );
    assert_eq!(r["result"]["isError"], true);
    assert!(
        r["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("allow_agent_delete")
    );

    // The removal mode is re-read while the server runs: a plan made after the switch to
    // permanent removes, and running it after switching back to the Trash is refused.
    let config = |extra: &str| {
        std::fs::write(
            d.path().join("config.toml"),
            format!("[scan]\nroots = [\"{}\"]\n{extra}", tree.display()),
        )
        .unwrap();
    };
    config("[removal]\nmode = \"permanent\"\n");
    let permanent = m.tool("plan_removal", json!({"finding_ids": [&id]}));
    let kinds: Vec<_> = permanent["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["kind"].clone())
        .collect();
    assert!(kinds.contains(&json!("remove")), "{permanent}");
    config("[mcp]\nallow_agent_delete = true\n[removal]\nmode = \"trash\"\n");
    let r = m.call(
        "tools/call",
        json!({"name": "execute_plan", "arguments": {"plan_id": permanent["id"]}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("Removal mode changed since planning"),
        "{text}"
    );
    assert!(tree.join("web/node_modules").exists());

    config("[mcp]\nallow_agent_delete = true\n[removal]\nmode = \"permanent\"\n");
    let mut m = Mcp::start(d.path());
    m.initialize();
    let ov = m.tool("disk_overview", json!({}));
    assert!(
        ov["snapshot_at"].is_number(),
        "snapshot persisted across processes"
    );
    assert_eq!(ov["stale"], false);
    let plan = m.tool("plan_removal", json!({"finding_ids": [item["id"]]}));
    let rep = m.tool("execute_plan", json!({"plan_id": plan["id"]}));
    assert_eq!(rep["results"][0]["status"], "done", "{rep}");
    assert!(rep["skipped_interactive"].as_array().unwrap().is_empty());
    assert!(!tree.join("web/node_modules").exists());
    let h = m.tool("history", json!({}));
    assert_eq!(h["records"].as_array().unwrap().len(), 1);

    // The config is re-read on every call: disabling takes effect without a restart.
    std::fs::write(
        d.path().join("config.toml"),
        format!("[scan]\nroots = [\"{}\"]\n", tree.display()),
    )
    .unwrap();
    let plan = m.tool(
        "plan_removal",
        json!({"finding_ids": [f["items"][0]["id"]]}),
    );
    let r = m.call(
        "tools/call",
        json!({"name": "execute_plan", "arguments": {"plan_id": plan["id"]}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
}

#[test]
fn tree_outside_snapshot_is_a_helpful_error() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    fixtures::build_tree(&tree);
    std::fs::write(
        d.path().join("config.toml"),
        format!("[scan]\nroots = [\"{}\"]\n", tree.display()),
    )
    .unwrap();
    let mut m = Mcp::start(d.path());
    m.initialize();
    let r = m.call(
        "tools/call",
        json!({"name": "tree", "arguments": {"path": "/nowhere"}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
    m.tool("scan", json!({"wait_seconds": 30}));
    let r = m.call(
        "tools/call",
        json!({"name": "tree", "arguments": {"path": "/nowhere"}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Path is not in the last snapshot"), "{text}");
    assert!(text.contains(&tree.display().to_string()), "{text}");

    // Trash mode goes through DISCKY_TRASH_BIN: the item lands in <home>/trashed/.
    std::fs::write(
        d.path().join("config.toml"),
        format!(
            "[scan]\nroots = [\"{}\"]\n[mcp]\nallow_agent_delete = true\n",
            tree.display()
        ),
    )
    .unwrap();
    let f = m.tool("findings", json!({"category": "project_builds"}));
    let nm = f["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["removal_kind"] == "trash")
        .unwrap()
        .clone();
    let plan = m.tool("plan_removal", json!({"finding_ids": [nm["id"]]}));
    assert_eq!(plan["steps"][0]["kind"], "trash", "{plan}");
    let rep = m.tool("execute_plan", json!({"plan_id": plan["id"]}));
    assert_eq!(rep["results"][0]["status"], "done", "{rep}");
    assert!(!tree.join("web/node_modules").exists());
    assert!(d.path().join("trashed/node_modules/pkg/index.js").exists());
}

#[test]
fn clients_declaring_tasks_get_a_task_handle_for_scan() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(&d.path().join("tree"));
    std::fs::write(
        d.path().join("config.toml"),
        format!(
            "[scan]\nroots = [\"{}\"]\n",
            d.path().join("tree").display()
        ),
    )
    .unwrap();
    let mut m = Mcp::start(d.path());
    let init = m.call(
        "initialize",
        json!({"protocolVersion": "2026-07-28", "capabilities": {"extensions": {"io.modelcontextprotocol/tasks": {}}}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert!(
        init["result"]["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"].is_object(),
        "{init}"
    );
    let r = m.call("tools/call", json!({"name": "scan", "arguments": {}}));
    assert_eq!(r["result"]["resultType"], "task", "{r}");
    // rmcp's `CreateTaskResult` flattens the task: `taskId` sits at the top of `result`.
    let task_id = r["result"]["taskId"].as_str().unwrap().to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let g = m.call("tasks/get", json!({"taskId": task_id}));
        if g["result"]["status"] == "completed" {
            assert_eq!(g["result"]["result"]["content"][0]["type"], "text", "{g}");
            let text = g["result"]["result"]["content"][0]["text"]
                .as_str()
                .unwrap();
            let out: Value = serde_json::from_str(text).unwrap();
            assert_eq!(out["status"]["kind"], "done", "{out}");
            assert!(out["scan_id"].is_string(), "{out}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "task never completed: {g}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn unparsable_config_blocks_planning_and_removing_until_fixed() {
    let d = tempfile::tempdir().unwrap();
    let tree = d.path().join("tree");
    fixtures::build_tree(&tree);
    let good = format!(
        "[scan]\nroots = [\"{}\"]\n[mcp]\nallow_agent_delete = true\n",
        tree.display()
    );
    let config = d.path().join("config.toml");
    std::fs::write(&config, &good).unwrap();
    let mut m = Mcp::start(d.path());
    m.initialize();
    m.tool("scan", json!({"wait_seconds": 30}));
    let f = m.tool("findings", json!({"category": "project_builds"}));
    let id = f["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["removal_kind"] == "trash")
        .unwrap()["id"]
        .clone();
    let plan = m.tool("plan_removal", json!({"finding_ids": [&id]}));

    // An only_steps index outside the plan is a tool error, and nothing runs.
    let r = m.call(
        "tools/call",
        json!({"name": "execute_plan", "arguments": {"plan_id": plan["id"], "only_steps": [99]}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Step index 99 is not in the plan"), "{text}");
    assert!(tree.join("web/node_modules").exists());

    std::fs::write(&config, "this is [not toml").unwrap();
    let want = "config.toml cannot be parsed";
    let fix = "Fix it before planning or removing anything.";
    for (tool, args) in [
        ("plan_removal", json!({"finding_ids": [&id]})),
        ("execute_plan", json!({"plan_id": plan["id"]})),
    ] {
        let r = m.call("tools/call", json!({"name": tool, "arguments": args}));
        assert_eq!(r["result"]["isError"], true, "{tool}: {r}");
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.starts_with(want) && text.ends_with(fix),
            "{tool}: {text}"
        );
    }
    assert!(tree.join("web/node_modules").exists());
    // Read-only tools keep the last good config.
    m.tool("disk_overview", json!({}));

    std::fs::write(&config, &good).unwrap();
    let again = m.tool("plan_removal", json!({"finding_ids": [&id]}));
    assert_eq!(again["steps"][0]["kind"], "trash", "{again}");
}

#[test]
fn a_trash_bin_override_is_announced_on_stderr() {
    let d = tempfile::tempdir().unwrap();
    let mut child = Command::new(assert_cmd::cargo::cargo_bin!("discky-mcp"))
        .arg("--home")
        .arg(d.path())
        .env("DISCKY_TRASH_BIN", d.path().join("fake-trash"))
        .env("HOME", d.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn discky-mcp");
    let err = BufReader::new(child.stderr.take().unwrap());
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for line in err.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let line = loop {
        match rx.recv_timeout(READ_TIMEOUT) {
            Ok(l) if l.contains("DISCKY_TRASH_BIN") => break l,
            Ok(_) => {}
            Err(e) => panic!("no DISCKY_TRASH_BIN warning on stderr: {e}"),
        }
    };
    assert!(
        line.contains("WARN") && line.contains("fake-trash"),
        "{line}"
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn plan_removal_with_components_selects_steps() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path();
    let app = home.join("Applications/Demo.app/Contents");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
<key>CFBundleName</key><string>Demo</string>
</dict></plist>"#,
    )
    .unwrap();
    for rel in [
        "Library/Application Support/com.example.demo/data.bin",
        "Library/Caches/com.example.demo/c.bin",
    ] {
        let p = home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, vec![7u8; 8192]).unwrap();
    }
    std::fs::write(
        home.join("config.toml"),
        format!("[scan]\nroots = [\"{}\"]\n", home.display()),
    )
    .unwrap();
    let mut m = Mcp::start(home);
    m.initialize();
    let sc = m.tool("scan", json!({"wait_seconds": 30}));
    assert_eq!(sc["status"]["kind"], "done", "{sc}");
    let f = m.tool("findings", json!({"category": "apps"}));
    // The orphan-receipts finding (same category) reads the host's `pkgutil`; ignore it.
    let items: Vec<&Value> = f["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["rule_id"] == "apps")
        .collect();
    assert_eq!(items.len(), 1, "{f}");
    assert_eq!(items[0]["title"], "Demo", "{f}");
    assert!(items[0]["components_count"].as_u64().unwrap() >= 3, "{f}");
    assert!(items[0].get("components").is_none());
    let id = items[0]["id"].as_str().unwrap().to_string();

    let i = m.tool("inspect", json!({"target": &id}));
    let comps = i["finding"]["components"].as_array().unwrap();
    let find = |kind: &str| {
        comps
            .iter()
            .find(|c| c["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} component in {i}"))
    };
    let caches = find("caches")["index"].as_u64().unwrap();
    let bundle = find("app_bundle")["index"].as_u64().unwrap();
    assert_ne!(caches, bundle);
    assert!(find("caches")["human_size"].is_string());

    let p = m.tool(
        "plan_removal",
        json!({"finding_ids": [&id], "components": {&id: [caches]}}),
    );
    let steps = p["steps"].as_array().unwrap();
    let trash: Vec<_> = steps.iter().filter(|s| s["kind"] == "trash").collect();
    assert_eq!(trash.len(), 1, "{p}");
    assert!(
        trash[0].to_string().contains("Caches/com.example.demo"),
        "{p}"
    );
    let all = p["steps"].to_string();
    assert!(!all.contains("Application Support"), "{p}");
    assert!(!all.contains("Demo.app"), "{p}");

    let r = m.call(
        "tools/call",
        json!({"name": "plan_removal", "arguments": {"finding_ids": [&id], "components": {"nope": [0]}}}),
    );
    assert_eq!(r["result"]["isError"], true, "{r}");
}
