//! Dataless (cloud-evicted) files: detection and the process-wide "never materialize" policy.

use std::io;
use std::os::raw::c_int;

/// BSD flag set on dataless files (contents live in the cloud). Missing from `libc`.
pub const SF_DATALESS: u32 = 0x4000_0000;

const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: c_int = 3;
const IOPOL_SCOPE_PROCESS: c_int = 0;
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: c_int = 1;

// SAFETY: matches the declaration in <sys/resource.h>.
unsafe extern "C" {
    fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;
}

/// True when `bsd_flags` (`ATTR_CMN_FLAGS`) marks the file as dataless.
pub fn is_dataless(bsd_flags: u32) -> bool {
    bsd_flags & SF_DATALESS != 0
}

/// Forbid this process from materializing dataless files, so touching one fails
/// instead of silently downloading it. Call before scanning.
pub fn set_no_materialize() -> io::Result<()> {
    // SAFETY: setiopolicy_np takes three plain integers and touches no caller memory.
    let rc = unsafe {
        setiopolicy_np(
            IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
            IOPOL_SCOPE_PROCESS,
            IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
