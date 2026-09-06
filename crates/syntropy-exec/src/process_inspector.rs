#[cfg(target_os = "linux")]
use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InspectorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Platform error: {0}")]
    Platform(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub command_line: Option<String>,
}

pub struct ProcessInspector;

impl ProcessInspector {
    /// Lists running processes without spawning expensive shell forks (`ps`/`pgrep`/`tasklist`).
    pub fn list_processes() -> Result<Vec<ProcessEntry>, InspectorError> {
        #[cfg(target_os = "windows")]
        {
            Self::list_windows_processes()
        }

        #[cfg(target_os = "linux")]
        {
            Self::list_linux_processes("/proc")
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux")))]
        {
            Ok(vec![ProcessEntry {
                pid: std::process::id(),
                parent_pid: 0,
                name: "current".into(),
                command_line: None,
            }])
        }
    }

    /// Finds processes matching a given name.
    pub fn find_by_name(name: &str) -> Result<Vec<ProcessEntry>, InspectorError> {
        let all = Self::list_processes()?;
        let query = name.to_lowercase();
        Ok(all.into_iter().filter(|p| p.name.to_lowercase().contains(&query)).collect())
    }

    /// Checks if a PID is alive.
    pub fn is_pid_alive(pid: u32) -> bool {
        #[cfg(target_os = "windows")]
        {
            unsafe {
                let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if handle.is_null() {
                    false
                } else {
                    let mut exit_code: u32 = 0;
                    let success = GetExitCodeProcess(handle, &mut exit_code);
                    CloseHandle(handle);
                    success != 0 && exit_code == STILL_ACTIVE
                }
            }
        }

        #[cfg(unix)]
        {
            let res = unsafe { libc_kill(pid as i32, 0) };
            res == 0 || std::io::Error::last_os_error().raw_os_error() == Some(1) // EPERM
        }

        #[cfg(not(any(target_os = "windows", unix)))]
        {
            pid == std::process::id()
        }
    }

    #[cfg(target_os = "linux")]
    pub fn list_linux_processes(proc_root: impl AsRef<Path>) -> Result<Vec<ProcessEntry>, InspectorError> {
        let mut entries = Vec::new();
        let dir = std::fs::read_dir(proc_root)?;
        for entry in dir.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if let Ok(pid) = file_name.parse::<u32>() {
                let path = entry.path();
                let comm = std::fs::read_to_string(path.join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let cmdline = std::fs::read(path.join("cmdline"))
                    .ok()
                    .map(|bytes| {
                        bytes
                            .split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect::<Vec<_>>()
                            .join(" ")
                    });

                // Parse stat for ppid
                let parent_pid = if let Ok(stat) = std::fs::read_to_string(path.join("stat")) {
                    if let Some(close) = stat.rfind(')') {
                        let remainder = &stat[close + 1..].trim();
                        let parts: Vec<&str> = remainder.split_whitespace().collect();
                        parts.get(1).and_then(|pp| pp.parse::<u32>().ok()).unwrap_or(0)
                    } else {
                        0
                    }
                } else {
                    0
                };

                entries.push(ProcessEntry {
                    pid,
                    parent_pid,
                    name: comm,
                    command_line: cmdline,
                });
            }
        }
        Ok(entries)
    }

    #[cfg(target_os = "windows")]
    fn list_windows_processes() -> Result<Vec<ProcessEntry>, InspectorError> {
        const TH32CS_SNAPPROCESS: u32 = 0x00000002;

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == (-1isize as *mut std::ffi::c_void) || snapshot.is_null() {
                return Err(InspectorError::Platform("CreateToolhelp32Snapshot failed".into()));
            }

            let mut entry = ProcessEntry32W {
                dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
                cnt_usage: 0,
                th32_process_id: 0,
                th32_default_heap_id: 0,
                th32_module_id: 0,
                cnt_threads: 0,
                th32_parent_process_id: 0,
                pc_pri_class_base: 0,
                dw_flags: 0,
                sz_exe_file: [0u16; 260],
            };

            let mut processes = Vec::new();
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let len = entry
                        .sz_exe_file
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.sz_exe_file.len());
                    let exe_name = String::from_utf16_lossy(&entry.sz_exe_file[..len]);

                    processes.push(ProcessEntry {
                        pid: entry.th32_process_id,
                        parent_pid: entry.th32_parent_process_id,
                        name: exe_name,
                        command_line: None,
                    });

                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
            Ok(processes)
        }
    }
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ProcessEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_pri_class_base: i32,
    dw_flags: u32,
    sz_exe_file: [u16; 260],
}

#[cfg(target_os = "windows")]
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
#[cfg(target_os = "windows")]
const STILL_ACTIVE: u32 = 259;

#[cfg(target_os = "windows")]
extern "system" {
    fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut std::ffi::c_void;
    fn Process32FirstW(h_snapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(h_snapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn OpenProcess(dw_desired_access: u32, b_inherit_handle: i32, dw_process_id: u32) -> *mut std::ffi::c_void;
    fn GetExitCodeProcess(h_process: *mut std::ffi::c_void, lp_exit_code: *mut u32) -> i32;
    fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
}

#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_inspector_queries_current_process() {
        let current_pid = std::process::id();
        let procs = ProcessInspector::list_processes().expect("Failed to list processes");
        assert!(!procs.is_empty());

        let current = procs.iter().find(|p| p.pid == current_pid);
        assert!(current.is_some(), "Current process should be in the process table");

        assert!(ProcessInspector::is_pid_alive(current_pid));
        assert!(!ProcessInspector::is_pid_alive(999999999));
    }
}
