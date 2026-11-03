//! [`DisckyServer`]: the MCP tools and resources over one [`Engine`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use discky_core::plan::execute::{ExecuteError, StepStatus};
use discky_core::plan::{PlanId, StepFlags, StepKind};
use discky_core::query::{QueryError, SearchQuery};
use discky_core::{
    Config, DisckyPaths, Engine, EngineError, ExecuteRequest, PlanItem, RemovalMode, ScanId,
    ScanStatus,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::{IntoCallToolResult, schema_for_output};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{
    CallToolResponse, CancelTaskParams, GetTaskParams, GetTaskResult, Implementation,
    ListResourcesResult, PaginatedRequestParams, ProgressNotificationParam,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, ServerCapabilities, ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, tool, tool_handler, tool_router};

use crate::params::*;
use crate::tasks::ScanTasks;

const STALE_AFTER_SECS: u64 = 3600;
const MAX_WAIT_SECS: u32 = 60;
const MAX_PAGE: usize = 200;
const PROGRESS_EVERY: Duration = Duration::from_millis(500);
const LOG_TAIL_LINES: usize = 200;

const URI_SUMMARY: &str = "discky://snapshot/summary";
const URI_CONFIG: &str = "discky://config";
const URI_LOG: &str = "discky://log/removals";

const NO_SNAPSHOT: &str = "No snapshot yet. Call `scan` first.";
const MODE_CHANGED: &str = "Removal mode changed since planning. Call plan_removal again.";
const UNKNOWN_PLAN: &str =
    "Unknown plan id (plans are kept for this server session only). Call plan_removal again.";
const DELETE_DISABLED: &str = "Agent deletion is disabled. Enable it in Discky → Settings → MCP server (`mcp.allow_agent_delete = true` in config.toml)";

const INSTRUCTIONS: &str = "Discky is a macOS disk-cleanup tool: it scans the disk, finds removable things (caches, build outputs, models, large old files) and removes them safely. Call `disk_overview` first; if it reports `stale: true`, call `scan` (pass `wait_seconds` up to 60, or poll `scan_status`). All sizes are bytes actually allocated on disk, and `freed_if_deleted` is what deleting really frees (clones and hard links shared elsewhere are not counted). Always call `plan_removal` and show the plan to the user before `execute_plan`; `execute_plan` is disabled until the user enables agent deletion in Discky settings. Never guess paths: use `findings`, `tree`, `search` and `inspect`. Applications and Language versions findings carry `components` (see `inspect`); pass `components` to `plan_removal` to remove only some of them. Steps that need an administrator or quit an app are skipped for agents (run them in Discky.app).";

#[derive(Clone)]
pub struct DisckyServer {
    engine: Arc<Engine>,
    tasks: ScanTasks,
    tool_router: ToolRouter<Self>,
}

/// Run blocking engine work off the async runtime; a panic becomes a tool error.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| "internal error: engine task panicked".to_string())
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
            tasks: ScanTasks::default(),
            tool_router: Self::tool_router(),
        }
    }

    /// Pick up edits Discky.app made to config.toml; on error keep the last good config.
    /// For read-only tools.
    fn reload_config(&self) {
        if let Err(e) = self.engine.reload_config() {
            tracing::warn!("keeping the previous config: {e}");
        }
    }

    /// Re-read config.toml for a tool that plans or removes: a file that cannot be parsed
    /// is a tool error, never a silent fallback to the last good config.
    fn reload_config_strict(&self) -> Result<(), String> {
        self.engine.reload_config().map_err(|e| {
            format!(
                "config.toml cannot be parsed: {e}. Fix it before planning or removing anything."
            )
        })
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
            protected_bytes: o.protected_bytes,
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
        description = "Starts a scan of the configured roots (or `roots`) in the background and returns its id; with `wait_seconds` it waits for the result. Reads the disk only, never removes anything.",
        // Spelled out: the return type is not `Json<T>`, so the macro cannot derive it.
        output_schema = schema_for_output::<ScanOut>()
    )]
    async fn scan(
        &self,
        Parameters(p): Parameters<ScanParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, String> {
        self.reload_config();
        let roots = p
            .roots
            .map(|rs| rs.iter().map(|r| expand_tilde(r)).collect());
        let wait = p.wait_seconds.unwrap_or(0).min(MAX_WAIT_SECS);
        // Tasks extension: a client that declared it polls `tasks/get` instead of
        // `scan_status`; an explicit `wait_seconds` keeps the synchronous answer.
        let declared_tasks = ctx
            .client_capabilities()
            .is_some_and(|caps| caps.supports_tasks());
        if declared_tasks && wait == 0 {
            let task = self.tasks.spawn(Arc::clone(&self.engine), roots);
            return Ok(CallToolResponse::Task(task));
        }
        let id = self.engine.start_scan(roots);
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
            status?
        };
        Json(ScanOut {
            scan_id: id.0,
            status,
        })
        .into_call_tool_result()
        .map_err(|e| e.message.to_string())
    }

    #[tool(
        name = "scan_status",
        description = "Status of a scan started with `scan`: running (with progress), done, failed, cancelled or unknown. No side effects."
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
            items: items
                .into_iter()
                .map(|f| FindingOut::new(f, false))
                .collect(),
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
            .await?
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
            finding: i.finding.map(|f| FindingOut::new(f, true)),
            entry: i.entry,
            children: i.children,
            rule: i.rule,
            owner_app: i.owner_app,
            in_snapshot: i.in_snapshot,
        }))
    }

    #[tool(
        name = "plan_removal",
        description = "Plans the removal of the given findings (optionally only some of their `components`) and returns the ordered steps and the bytes they free. Removes nothing; show the plan to the user, then call `execute_plan`."
    )]
    async fn plan_removal(
        &self,
        Parameters(p): Parameters<PlanParams>,
    ) -> Result<Json<PlanOut>, String> {
        self.reload_config_strict()?;
        let engine = Arc::clone(&self.engine);
        let mut by_id = p.components.unwrap_or_default();
        let items: Vec<PlanItem> = p
            .finding_ids
            .into_iter()
            .map(|id| PlanItem {
                components: by_id.remove(&id),
                id,
            })
            .collect();
        if let Some(extra) = by_id.keys().min() {
            return Err(format!(
                "components refers to an id not in finding_ids: {extra}"
            ));
        }
        let plan = blocking(move || engine.plan_items(&items))
            .await?
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
        // Re-read on every call so the user's settings apply without a restart.
        self.reload_config_strict()?;
        let config = self.engine.config();
        if !config.mcp.allow_agent_delete {
            return Err(DELETE_DISABLED.to_string());
        }
        let id = PlanId(p.plan_id);
        let plan = self.engine.get_plan(&id).ok_or(UNKNOWN_PLAN)?;
        let wrong_kind = |k: &StepKind| match config.removal.mode {
            RemovalMode::Trash => matches!(k, StepKind::Remove { .. }),
            RemovalMode::Permanent => matches!(k, StepKind::Trash { .. }),
        };
        if plan.steps.iter().any(|s| wrong_kind(&s.kind)) {
            return Err(MODE_CHANGED.to_string());
        }
        let engine = Arc::clone(&self.engine);
        let req = ExecuteRequest {
            allow_interactive: false,
            only_steps: p.only_steps,
            on_step: None,
        };
        let report = blocking(move || engine.execute_plan(&id, req))
            .await?
            .map_err(|e| match e {
                ExecuteError::UnknownPlan(_) => UNKNOWN_PLAN.to_string(),
                ExecuteError::PlanStale { path } => format!(
                    "Files changed since planning ({}). Call plan_removal again.",
                    path.display()
                ),
                ExecuteError::BadStepIndex(i) => format!(
                    "Step index {i} is not in the plan (it has {} steps).",
                    plan.steps.len()
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
                .enable_tasks()
                .build(),
        )
        .with_server_info(Implementation::new("discky", env!("CARGO_PKG_VERSION")))
        .with_instructions(INSTRUCTIONS)
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        self.tasks.get(&request.task_id)
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.tasks.cancel(&request.task_id)
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
