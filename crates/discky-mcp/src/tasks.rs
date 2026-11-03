//! The MCP Tasks extension (`io.modelcontextprotocol/tasks`) for `scan`: runs a scan as a
//! task the client polls with `tasks/get`, resolving with the synchronous `scan` result.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use discky_core::Engine;
use discky_core::scan::{ScanId, ScanStatus};
use rmcp::ErrorData as McpError;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::handler::server::wrapper::Json;
use rmcp::model::{
    CallToolResponse, CallToolResult, ContentBlock, CreateTaskResult, GetTaskResult,
};
use rmcp::task_manager::{TaskExit, TaskManager, TaskOptions};

use crate::params::ScanOut;

/// How long a scan task may run; its final state stays readable for one more TTL.
const TASK_TTL: Duration = Duration::from_secs(30 * 60);

/// Task id → the engine and scan it waits for.
type TaskScans = HashMap<String, (Arc<Engine>, ScanId)>;

/// The server's task store. Cheap to clone; clones share the tasks.
#[derive(Clone, Default)]
pub struct ScanTasks {
    manager: TaskManager,
    /// The engine and scan behind each task id, so `cancel` can stop the scan; an entry
    /// is dropped when its task is cancelled or its scan ends.
    scans: Arc<Mutex<TaskScans>>,
}

impl ScanTasks {
    /// Start a scan of `roots` (the configured roots when `None`; joins a running scan)
    /// as a task and return its handle; the task completes when the scan is no longer
    /// running.
    pub fn spawn(&self, engine: Arc<Engine>, roots: Option<Vec<PathBuf>>) -> CreateTaskResult {
        let options = TaskOptions::new().with_ttl_ms(TASK_TTL.as_millis() as u64);
        let id = engine.start_scan(roots);
        let (task_engine, task_scan_id) = (Arc::clone(&engine), id.clone());
        let scans = Arc::clone(&self.scans);
        let task = self.manager.spawn(options, move |_ctx| {
            Box::pin(async move {
                let out = tokio::task::spawn_blocking(move || {
                    let (engine, id) = (task_engine, task_scan_id);
                    let status = engine.wait_scan(&id, TASK_TTL);
                    lock(&scans).retain(|_, (_, s)| s != &id);
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
        // Recorded only while the scan may still run, so a finished scan is not re-added.
        if matches!(engine.scan_status(&id), ScanStatus::Running { .. }) {
            lock(&self.scans).insert(task.task_id.clone(), (engine, id));
        }
        CreateTaskResult::new(task)
    }

    pub fn get(&self, task_id: &str) -> Result<GetTaskResult, McpError> {
        self.manager.get_task(task_id).map(GetTaskResult::new)
    }

    /// Cancel the task and stop its scan.
    pub fn cancel(&self, task_id: &str) -> Result<(), McpError> {
        self.manager.cancel_task(task_id)?;
        if let Some((engine, id)) = lock(&self.scans).remove(task_id) {
            engine.cancel_scan(&id);
        }
        Ok(())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The same `CallToolResult` the synchronous `scan` returns for `out`; a cancelled scan is
/// a tool error.
fn scan_result(out: ScanOut) -> Result<CallToolResult, TaskExit> {
    if matches!(out.status, ScanStatus::Cancelled { .. }) {
        return Ok(CallToolResult::error(vec![ContentBlock::text(
            "Scan cancelled",
        )]));
    }
    match Json(out).into_call_tool_result()? {
        CallToolResponse::Complete(result) => Ok(result),
        _ => unreachable!("Json always converts to a complete result"),
    }
}
