//! System metrics collection via the `sysinfo` crate.
//!
//! Provides CPU, memory, and disk usage for the node operator dashboard
//! (spec 10-dashboard.md §6.1).

use sysinfo::{Disks, System};

/// System resource metrics snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMetrics {
    /// CPU usage as a percentage (0.0–100.0), averaged across all cores.
    pub cpu_percent: f32,
    /// Memory used by the system in bytes.
    pub memory_used_bytes: u64,
    /// Total system memory in bytes.
    pub memory_total_bytes: u64,
    /// Disk space used on the data directory's partition in bytes.
    pub disk_used_bytes: u64,
    /// Disk total capacity on the data directory's partition in bytes.
    pub disk_total_bytes: u64,
}

/// Collects system metrics using the `sysinfo` crate.
///
/// Maintains internal state between samples for accurate CPU measurement
/// (sysinfo requires two refreshes to compute CPU usage).
pub struct SystemCollector {
    system: System,
    disks: Disks,
    /// Path to the node's data directory (for finding the correct disk).
    data_dir: String,
}

impl SystemCollector {
    /// Create a new system collector.
    ///
    /// The `data_dir` is used to find the correct disk partition for
    /// disk usage reporting.
    pub fn new(data_dir: &str) -> Self {
        let mut system = System::new();
        system.refresh_cpu_all();
        system.refresh_memory();
        let disks = Disks::new_with_refreshed_list();

        Self {
            system,
            disks,
            data_dir: data_dir.to_string(),
        }
    }

    /// Refresh CPU and memory metrics.
    ///
    /// Call this at the system sampling interval (default: 10s).
    pub fn refresh_cpu_memory(&mut self) {
        self.system.refresh_cpu_all();
        self.system.refresh_memory();
    }

    /// Refresh disk metrics.
    ///
    /// Call this at the storage sampling interval (default: 60s).
    pub fn refresh_disks(&mut self) {
        self.disks.refresh(true);
    }

    /// Collect the current system metrics snapshot.
    pub fn collect(&self) -> SystemMetrics {
        let cpu_percent = self
            .system
            .cpus()
            .iter()
            .map(|cpu| cpu.cpu_usage())
            .sum::<f32>()
            / self.system.cpus().len().max(1) as f32;

        let memory_used_bytes = self.system.used_memory();
        let memory_total_bytes = self.system.total_memory();

        // Find the disk partition that contains the data directory.
        // Fall back to the largest partition if no match is found.
        let (disk_used, disk_total) = self.find_data_disk();

        SystemMetrics {
            cpu_percent,
            memory_used_bytes,
            memory_total_bytes,
            disk_used_bytes: disk_used,
            disk_total_bytes: disk_total,
        }
    }

    /// Find the disk partition for the data directory.
    fn find_data_disk(&self) -> (u64, u64) {
        let mut best_match: Option<(&sysinfo::Disk, usize)> = None;

        for disk in self.disks.list() {
            let mount = disk.mount_point().to_string_lossy();
            if self.data_dir.starts_with(mount.as_ref()) {
                let mount_len = mount.len();
                match &best_match {
                    Some((_, best_len)) if mount_len > *best_len => {
                        best_match = Some((disk, mount_len));
                    }
                    None => {
                        best_match = Some((disk, mount_len));
                    }
                    _ => {}
                }
            }
        }

        // Fall back to largest disk
        let disk = best_match
            .map(|(d, _)| d)
            .or_else(|| {
                self.disks
                    .list()
                    .iter()
                    .max_by_key(|d| d.total_space())
            });

        match disk {
            Some(d) => {
                let total = d.total_space();
                let available = d.available_space();
                (total.saturating_sub(available), total)
            }
            None => (0, 0),
        }
    }
}
