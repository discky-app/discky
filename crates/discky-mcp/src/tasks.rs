//! The MCP Tasks extension (`io.modelcontextprotocol/tasks`) for `scan`: runs a scan as a
//! task the client polls with `tasks/get`, resolving with the synchronous `scan` result.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use discky_core::Engine;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::handler::server::wrapper::Json;
use rmcp::model::{CallToolResponse, CallToolResult, CreateTaskResult, GetTaskResult};
use rmcp::task_manager::{TaskExit, TaskManager, TaskOptions};

use crate::params::ScanOut;

/// How long a scan task may run; its final state stays readable for one more TTL.
const TASK_TTL: Duration = Duration::from_secs(30 * 60);

/// The server's task store. Cheap to clone; clones share the tasks.
#[derive(Clone, Default)]
pub struct ScanTasks(TaskManager);

impl ScanTasks {
    /// Start a scan of `roots` (the configured roots when `None`) as a task and return
    /// its handle; the task completes when the scan is no longer running.
    pub fn spawn(&self, engine: Arc<Engine>, roots: Option<Vec<PathBuf>>) -> CreateTaskResult {
        let options = TaskOptions::new().with_ttl_ms(TASK_TTL.as_millis() as u64);
        let task = self.0.spawn(options, move |_ctx| {
            Box::pin(async move {
                let out = tokio::task::spawn_blocking(move || {
                    let id = engine.start_scan(roots);
                    let status = engine.wait_scan(&id, TASK_TTL);
                    ScanOut {
                        scan_id: id.0,
                        status,
                    }
                })
                .await
                .map_err(|_| McpError::internal_error("scan task panicked", None))?;
                scan_result(out)
            })
        });
        CreateTaskResult::new(task)
    }

    pub fn get(&self, task_id: &str) -> Result<GetTaskResult, McpError> {
        self.0.get_task(task_id).map(GetTaskResult::new)
    }

    pub fn cancel(&self, task_id: &str) -> Result<(), McpError> {
        self.0.cancel_task(task_id)
    }
}

/// The same `CallToolResult` the synchronous `scan` returns for `out`.
fn scan_result(out: ScanOut) -> Result<CallToolResult, TaskExit> {
    match Json(out).into_call_tool_result()? {
        CallToolResponse::Complete(result) => Ok(result),
        _ => unreachable!("Json always converts to a complete result"),
    }
}
