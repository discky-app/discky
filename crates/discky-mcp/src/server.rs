//! [`DisckyServer`]: the MCP tools and resources over one [`Engine`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use discky_core::plan::execute::{ExecuteError, StepStatus};
use discky_core::plan::{PlanId, StepFlags};
use discky_core::query::{QueryError, SearchQuery};
use discky_core::{Config, DisckyPaths, Engine, EngineError, ScanId, ScanStatus};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    Implementation, ListResourcesResult, PaginatedRequestParams, ProgressNotificationParam,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, tool, tool_handler, tool_router};

use crate::params::*;

const STALE_AFTER_SECS: u64 = 3600;
const MAX_WAIT_SECS: u32 = 60;
const MAX_PAGE: usize = 200;
const PROGRESS_EVERY: Duration = Duration::from_millis(500);
const LOG_TAIL_LINES: usize = 200;

const URI_SUMMARY: &str = "discky://snapshot/summary";
const URI_CONFIG: &str = "discky://config";
const URI_LOG: &str = "discky://log/removals";

const NO_SNAPSHOT: &str = "No snapshot yet. Call `scan` first.";
const DELETE_DISABLED: &str = "Agent deletion is disabled. Enable it in Discky → Settings → MCP server (`mcp.allow_agent_delete = true` in config.toml)";

const INSTRUCTIONS: &str = "Discky is a macOS disk-cleanup tool: it scans the disk, finds removable things (caches, build outputs, models, large old files) and removes them safely. Call `disk_overview` first; if it reports `stale: true`, call `scan` (pass `wait_seconds` up to 30, or poll `scan_status`). All sizes are bytes actually allocated on disk, and `freed_if_deleted` is what deleting really frees (clones and hard links shared elsewhere are not counted). Always call `plan_removal` and show the plan to the user before `execute_plan`; `execute_plan` is disabled until the user enables agent deletion in Discky settings. Never guess paths: use `findings`, `tree`, `search` and `inspect`.";

#[derive(Clone)]
pub struct DisckyServer {
    engine: Arc<Engine>,
    tool_router: ToolRouter<Self>,
}

/// Run blocking engine work off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("engine task panicked")
}

fn engine_error(e: EngineError) -> String {
    match e {
        EngineError::NoSnapshot => NO_SNAPSHOT.to_string(),
        e => e.to_string(),
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    match (p.strip_prefix('~'), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            PathBuf::from(format!("{}{rest}", Path::new(&home).display()))
        }
        _ => PathBuf::from(p),
    }
}

fn page(limit: Option<usize>, default: usize) -> usize {
    limit.unwrap_or(default).clamp(1, MAX_PAGE)
}

// Tools return `Result<Json<T>, String>`: an `Err` reaches the agent as a tool error
// (`isError: true`) with that text. The return type is spelled out (no alias) so the
// `#[tool]` macro sees `Json<T>` and publishes the output schema.
#[tool_router]
impl DisckyServer {
    pub fn new(engine: Arc<Engine>) -> DisckyServer {
        DisckyServer {
            engine,
            tool_router: Self::tool_router(),
        }
    }

    fn overview_out(&self) -> OverviewOut {
        let o = self.engine.overview();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let age = o.snapshot_at.map(|t| (now - t).max(0) as u64);
        OverviewOut {
            volume: o.volume,
            snapshot_at: o.snapshot_at,
            actor: o.actor,
            scanned_allocated: o.scanned_allocated,
            by_category: o.by_category,
            safe_to_free: o.safe_to_free,
            no_access: o.no_access,
            exact_private_size: o.exact_private_size,
            snapshot_age_seconds: age,
            stale: age.is_none_or(|a| a > STALE_AFTER_SECS),
        }
    }

    #[tool(
        name = "disk_overview",
        description = "Disk usage summary from the last scan: volume size and free space, bytes per category, bytes safe to free, and whether the snapshot is stale. No side effects; call this first."
    )]
    async fn disk_overview(&self) -> Json<OverviewOut> {
        Json(self.overview_out())
    }

    #[tool(
        name = "scan",
        description = "Starts a scan of the configured roots (or `roots`) in the background and returns its id; with `wait_seconds` it waits for the result. Reads the disk only, never removes anything."
    )]
    async fn scan(
        &self,
        Parameters(p): Parameters<ScanParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Json<ScanOut> {
        let roots = p
            .roots
            .map(|rs| rs.iter().map(|r| expand_tilde(r)).collect());
        let id = self.engine.start_scan(roots);
        let wait = p.wait_seconds.unwrap_or(0).min(MAX_WAIT_SECS);
        let status = if wait == 0 {
            self.engine.scan_status(&id)
        } else {
            let progress = ctx.meta.get_progress_token().map(|token| {
                let (engine, id, peer) = (Arc::clone(&self.engine), id.clone(), ctx.peer.clone());
                tokio::spawn(async move {
                    while let ScanStatus::Running { progress, .. } = engine.scan_status(&id) {
                        let mut n =
                            ProgressNotificationParam::new(token.clone(), progress.files as f64);
                        n.message = progress.current.map(|c| c.display().to_string());
                        if peer.notify_progress(n).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(PROGRESS_EVERY).await;
                    }
                })
            });
            let (engine, wait_id) = (Arc::clone(&self.engine), id.clone());
            let status =
                blocking(move || engine.wait_scan(&wait_id, Duration::from_secs(wait.into())))
                    .await;
            if let Some(task) = progress {
                task.abort();
            }
            status
        };
        Json(ScanOut {
            scan_id: id.0,
            status,
        })
    }

    #[tool(
        name = "scan_status",
        description = "Status of a scan started with `scan`: running (with progress), done, failed or unknown. No side effects."
    )]
    async fn scan_status(
        &self,
        Parameters(p): Parameters<ScanStatusParams>,
    ) -> Json<Obj<ScanStatus>> {
        Json(Obj(self.engine.scan_status(&ScanId(p.scan_id))))
    }

    #[tool(
        name = "findings",
        description = "Removable things found by the last scan, largest first, with size, safety label and removal method; filter by category, label, size or age. No side effects."
    )]
    async fn findings(&self, Parameters(p): Parameters<FindingsParams>) -> Json<FindingsOut> {
        let offset = p.offset.unwrap_or(0);
        let (items, total) = self.engine.findings(
            p.category,
            p.label,
            p.min_bytes.unwrap_or(0),
            p.older_than_days,
            offset,
            page(p.limit, 25),
        );
        Json(FindingsOut {
            items: items.into_iter().map(FindingOut::from).collect(),
            total,
            offset,
        })
    }

    #[tool(
        name = "tree",
        description = "The largest children of a directory in the last snapshot, with allocated and freed-if-deleted bytes. No side effects."
    )]
    async fn tree(
        &self,
        Parameters(p): Parameters<TreeParams>,
    ) -> Result<Json<EntriesOut>, String> {
        let path = expand_tilde(&p.path);
        match self.engine.tree(&path, page(p.limit, 20)) {
            Ok(entries) => Ok(Json(EntriesOut { entries })),
            Err(EngineError::Query(QueryError::NotInSnapshot(_))) => {
                let roots = self
                    .engine
                    .snapshot()
                    .map(|s| {
                        let rs: Vec<_> = s
                            .meta
                            .roots
                            .iter()
                            .map(|r| r.display().to_string())
                            .collect();
                        rs.join(", ")
                    })
                    .unwrap_or_default();
                Err(format!(
                    "Path is not in the last snapshot. Run `scan` with this root or choose a path under: {roots}"
                ))
            }
            Err(e) => Err(engine_error(e)),
        }
    }

    #[tool(
        name = "search",
        description = "Search the last snapshot for files and directories by name glob, size, age, kind or parent path, largest first. No side effects."
    )]
    async fn search(
        &self,
        Parameters(p): Parameters<SearchParams>,
    ) -> Result<Json<EntriesOut>, String> {
        let q = SearchQuery {
            name_glob: p.name_glob,
            min_allocated: p.min_bytes,
            older_than_days: p.older_than_days,
            kind: p.kind,
            under: p.under,
            limit: page(p.limit, SearchQuery::default().limit),
        };
        let engine = Arc::clone(&self.engine);
        let entries = blocking(move || engine.search(&q))
            .await
            .map_err(engine_error)?;
        Ok(Json(EntriesOut { entries }))
    }

    #[tool(
        name = "inspect",
        description = "Everything known about a finding id, an absolute path or an app name: the finding, its rule explanation, size and largest children. No side effects."
    )]
    async fn inspect(
        &self,
        Parameters(p): Parameters<InspectParams>,
    ) -> Result<Json<InspectOut>, String> {
        let i = self.engine.inspect(&p.target).ok_or(NO_SNAPSHOT)?;
        Ok(Json(InspectOut {
            finding: i.finding.map(FindingOut::from),
            entry: i.entry,
            children: i.children,
            rule: i.rule,
            owner_app: i.owner_app,
            in_snapshot: i.in_snapshot,
        }))
    }

    #[tool(
        name = "plan_removal",
        description = "Plans the removal of the given findings and returns the ordered steps and the bytes they free. Removes nothing; show the plan to the user, then call `execute_plan`."
    )]
    async fn plan_removal(
        &self,
        Parameters(p): Parameters<PlanParams>,
    ) -> Result<Json<PlanOut>, String> {
        let engine = Arc::clone(&self.engine);
        let plan = blocking(move || engine.plan(&p.finding_ids))
            .await
            .map_err(engine_error)?;
        let mut v = plan.to_json();
        Ok(Json(PlanOut {
            id: plan.id.0,
            created_at: plan.created_at,
            total_freed: plan.total_freed,
            human_total: human_size(plan.total_freed),
            steps: v["steps"].take(),
            skipped: v["skipped"].take(),
        }))
    }

    #[tool(
        name = "execute_plan",
        description = "DELETES files: runs a plan from `plan_removal` (moving items to the Trash or deleting them, per the user's settings). Refused unless the user enabled agent deletion in Discky settings; steps needing an admin prompt are skipped."
    )]
    async fn execute_plan(
        &self,
        Parameters(p): Parameters<ExecuteParams>,
    ) -> Result<Json<ExecuteOut>, String> {
        // Re-read on every call so the user's toggle applies without a restart.
        let config = Config::load(&DisckyPaths::resolve()).map_err(|e| e.to_string())?;
        if !config.mcp.allow_agent_delete {
            return Err(DELETE_DISABLED.to_string());
        }
        let plan = self.engine.get_plan(&PlanId(p.plan_id)).ok_or(
            "Unknown plan id (plans are kept for this server session only). Call plan_removal again.",
        )?;
        let engine = Arc::clone(&self.engine);
        let run = plan.clone();
        let report = blocking(move || engine.execute(&run, false, p.only_steps))
            .await
            .map_err(|e| match e {
                ExecuteError::PlanStale { path } => format!(
                    "Files changed since planning ({}). Call plan_removal again.",
                    path.display()
                ),
                e => format!("Cannot run the plan: {e}"),
            })?;
        let skipped_interactive = report
            .results
            .iter()
            .filter(|r| r.status == StepStatus::Skipped)
            .filter_map(|r| plan.steps.iter().find(|s| s.index == r.index))
            .filter(|s| s.flags.contains(StepFlags::INTERACTIVE))
            .map(|s| SkippedStep {
                index: s.index,
                description: s.description.clone(),
            })
            .collect();
        Ok(Json(ExecuteOut {
            plan: report.plan.0,
            results: report.results,
            freed_total: report.freed_total,
            trashed_bytes: report.trashed_bytes,
            stopped_at: report.stopped_at,
            log_path: report.log_path,
            skipped_interactive,
        }))
    }

    #[tool(
        name = "history",
        description = "Removals Discky has run, newest first, and the items it moved to the Trash that are still there. No side effects."
    )]
    async fn history(&self, Parameters(p): Parameters<HistoryParams>) -> Json<HistoryOut> {
        let in_trash: Vec<TrashItem> = self
            .engine
            .in_trash()
            .into_iter()
            .map(|(path, bytes)| TrashItem { path, bytes })
            .collect();
        Json(HistoryOut {
            records: self.engine.history(p.limit.unwrap_or(50)),
            trash_total: in_trash.iter().map(|t| t.bytes).sum(),
            in_trash,
        })
    }
}

/// The last `n` lines of `path`; empty when it does not exist.
fn tail(path: &Path, n: usize) -> std::io::Result<String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e),
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut out = lines[lines.len().saturating_sub(n)..].join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for DisckyServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("discky", env!("CARGO_PKG_VERSION")))
        .with_instructions(INSTRUCTIONS)
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![
            Resource::new(URI_SUMMARY, "Snapshot summary")
                .with_description("JSON of `disk_overview`.")
                .with_mime_type("application/json"),
            Resource::new(URI_CONFIG, "Configuration")
                .with_description("Discky's effective configuration (config.toml).")
                .with_mime_type("application/toml"),
            Resource::new(URI_LOG, "Removal log")
                .with_description("The last 200 lines of the removal log (JSON lines).")
                .with_mime_type("text/plain"),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let internal = |e: &dyn std::fmt::Display| McpError::internal_error(e.to_string(), None);
        let paths = DisckyPaths::resolve();
        let (text, mime) = match request.uri.as_str() {
            URI_SUMMARY => (
                serde_json::to_string_pretty(&self.overview_out()).map_err(|e| internal(&e))?,
                "application/json",
            ),
            URI_CONFIG => {
                let config = Config::load(&paths).map_err(|e| internal(&e))?;
                (
                    toml::to_string_pretty(&config).map_err(|e| internal(&e))?,
                    "application/toml",
                )
            }
            URI_LOG => (
                tail(&paths.log, LOG_TAIL_LINES).map_err(|e| internal(&e))?,
                "text/plain",
            ),
            uri => {
                return Err(McpError::resource_not_found(
                    format!("Unknown resource {uri}"),
                    None,
                ));
            }
        };
        let contents = ResourceContents::text(text, request.uri).with_mime_type(mime);
        Ok(ReadResourceResult::new(vec![contents]).into())
    }
}
