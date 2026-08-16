use std::{fs, io::Write, path::Path, process::Command};

use serde::Serialize;

use crate::{
    config::{self, AppConfig, LIBKRUN_VERSION},
    embedded_runtime, runtime_image,
};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pass,
    Warn,
    Fail,
    NotApplicable,
}

#[derive(Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    required: bool,
    message: String,
}

#[derive(Serialize)]
struct Report {
    overall: bool,
    checks: Vec<Check>,
}

struct LibkrunCapabilities {
    version: String,
    blk: bool,
    net: bool,
    vsock: bool,
}

trait Probe {
    fn writable(&self, path: &Path) -> Result<(), String>;
    fn free_bytes(&self, path: &Path) -> Result<u64, String>;
    fn cow_supported(&self, path: &Path) -> Result<bool, String>;
    fn accessible_read_write(&self, path: &Path) -> bool;
    fn exists(&self, path: &Path) -> bool;
    fn read_text(&self, path: &Path) -> Result<String, String>;
    fn command_output(&self, program: &str, args: &[&str]) -> Result<String, String>;
    fn libkrun_present(&self, config: &AppConfig) -> Result<String, String>;
    fn libkrun_capabilities(&self, config: &AppConfig) -> Result<LibkrunCapabilities, String>;
    fn database_migrations_current(&self, config: &AppConfig) -> Result<bool, String>;
    fn runtime_bundle(&self, config: &AppConfig) -> Result<String, String>;
    fn worker_cgroup_enforcement(&self) -> Result<String, String>;
    fn worker_seccomp_enforcement(&self) -> Result<String, String>;
    fn os(&self) -> &'static str;
    fn arch(&self) -> &'static str;
}

struct SystemProbe;

impl Probe for SystemProbe {
    fn writable(&self, path: &Path) -> Result<(), String> {
        fs::create_dir_all(path).map_err(|error| error.to_string())?;
        let probe = path.join(format!(".boxd-doctor-write-{}", std::process::id()));
        let result = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .and_then(|mut file| file.write_all(b"boxd-doctor"));
        let _ = fs::remove_file(&probe);
        result.map_err(|error| error.to_string())
    }

    fn free_bytes(&self, path: &Path) -> Result<u64, String> {
        let path = path
            .to_str()
            .ok_or_else(|| "data directory is not valid UTF-8".to_owned())?;
        let output = self.command_output("df", &["-Pk", path])?;
        let line = output
            .lines()
            .rfind(|line| !line.trim().is_empty())
            .ok_or_else(|| "df returned no filesystem row".to_owned())?;
        let available_kib = line
            .split_whitespace()
            .nth(3)
            .ok_or_else(|| "df output has no available-blocks column".to_owned())?
            .parse::<u64>()
            .map_err(|error| format!("invalid df available-blocks value: {error}"))?;
        available_kib
            .checked_mul(1024)
            .ok_or_else(|| "free-space value overflowed".to_owned())
    }

    fn cow_supported(&self, path: &Path) -> Result<bool, String> {
        let source = path.join(format!(".boxd-doctor-cow-source-{}", std::process::id()));
        let target = path.join(format!(".boxd-doctor-cow-target-{}", std::process::id()));
        fs::write(&source, b"boxd-cow-probe").map_err(|error| error.to_string())?;
        let result = match std::env::consts::OS {
            "macos" => Command::new("cp")
                .arg("-c")
                .arg(&source)
                .arg(&target)
                .output(),
            "linux" => Command::new("cp")
                .arg("--reflink=always")
                .arg(&source)
                .arg(&target)
                .output(),
            other => {
                let _ = fs::remove_file(&source);
                return Err(format!("CoW probe is unsupported on {other}"));
            }
        };
        let _ = fs::remove_file(&source);
        let _ = fs::remove_file(&target);
        result
            .map(|output| output.status.success())
            .map_err(|error| format!("failed to execute CoW probe: {error}"))
    }

    fn accessible_read_write(&self, path: &Path) -> bool {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_ok()
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn read_text(&self, path: &Path) -> Result<String, String> {
        fs::read_to_string(path).map_err(|error| error.to_string())
    }

    fn command_output(&self, program: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| format!("failed to execute {program}: {error}"))?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() {
            Ok(combined)
        } else {
            Err(format!("{program} failed: {}", combined.trim()))
        }
    }

    fn libkrun_capabilities(&self, config: &AppConfig) -> Result<LibkrunCapabilities, String> {
        let assets = embedded_runtime::install(&config.storage.data_dir)?;
        let identity = box_runtime::LibraryIdentity {
            tag: box_runtime_libkrun::LIBKRUN_TAG.into(),
            commit: box_runtime_libkrun::LIBKRUN_COMMIT.into(),
            header_sha256: box_runtime_libkrun::LIBKRUN_HEADER_SHA256.into(),
            artifact_sha256: embedded_runtime::LIBKRUN_SHA256.into(),
        };
        let firmware = box_runtime::FirmwareIdentity {
            version: "5".into(),
            soname: if cfg!(target_os = "macos") {
                "libkrunfw.5.dylib"
            } else {
                "libkrunfw.so.5"
            }
            .into(),
            artifact_sha256: embedded_runtime::LIBKRUNFW_SHA256.into(),
        };
        let capabilities = box_runtime_libkrun::probe_library(
            &assets.libkrun,
            &identity,
            &assets.libkrunfw,
            &firmware,
        )
        .map_err(|error| error.to_string())?;
        Ok(LibkrunCapabilities {
            version: LIBKRUN_VERSION.into(),
            blk: capabilities.blk,
            net: capabilities.net,
            vsock: capabilities.vsock,
        })
    }

    fn libkrun_present(&self, config: &AppConfig) -> Result<String, String> {
        let assets = embedded_runtime::install(&config.storage.data_dir)?;
        Ok(format!(
            "embedded libkrun {LIBKRUN_VERSION} and firmware are installed at {} and {}",
            assets.libkrun.display(),
            assets.libkrunfw.display()
        ))
    }

    fn database_migrations_current(&self, config: &AppConfig) -> Result<bool, String> {
        let url = config.database.url.clone();
        let max_connections = config.database.max_connections;
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let database = box_db::connect(&url, max_connections)
                    .await
                    .map_err(|error| error.to_string())?;
                box_db::migrations_current(&database)
                    .await
                    .map_err(|error| error.to_string())
            })
        })
        .join()
        .map_err(|_| "database migration probe thread panicked".to_owned())?
    }

    fn runtime_bundle(&self, config: &AppConfig) -> Result<String, String> {
        verify_runtime_bundles(config)
    }

    fn worker_cgroup_enforcement(&self) -> Result<String, String> {
        box_runtime_libkrun::probe_linux_worker_cgroup()
            .map(|()| "delegated cgroup v2 supports cpu, memory, and pids worker limits".into())
            .map_err(|error| error.to_string())
    }

    fn worker_seccomp_enforcement(&self) -> Result<String, String> {
        box_runtime_libkrun::probe_linux_worker_seccomp()
            .map(|()| "versioned worker seccomp policy is available".into())
            .map_err(|error| error.to_string())
    }

    fn os(&self) -> &'static str {
        std::env::consts::OS
    }

    fn arch(&self) -> &'static str {
        std::env::consts::ARCH
    }
}

pub fn run(config: &AppConfig, json: bool) -> Result<(), String> {
    let report = inspect(config, &SystemProbe);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        for check in &report.checks {
            println!("{:?}: {} — {}", check.status, check.name, check.message);
        }
    }
    if report.overall {
        Ok(())
    } else {
        Err("doctor found required failures".into())
    }
}

/// Side-effect-free with respect to user data and secrets. Linux enforcement
/// probes may create and remove a transient empty cgroup and a short-lived
/// seccomp child, matching the production worker gates.
pub(crate) fn platform_readiness() -> Result<(), String> {
    platform_readiness_with(&SystemProbe)
}

fn platform_readiness_with(probe: &dyn Probe) -> Result<(), String> {
    match probe.os() {
        "macos" => {
            if probe.arch() != "aarch64" {
                return Err("requires macOS on Apple Silicon".into());
            }
            let version = probe.command_output("sw_vers", &["-productVersion"])?;
            let major = version
                .trim()
                .split('.')
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| "unable to parse macOS version".to_owned())?;
            if major < 14 {
                return Err("requires macOS 14+ on Apple Silicon".into());
            }
            let value = probe.command_output("sysctl", &["-n", "kern.hv_support"])?;
            if value.trim() != "1" {
                return Err("kern.hv_support is not 1".into());
            }
            let executable = std::env::current_exe()
                .map_err(|error| format!("cannot resolve current executable: {error}"))?;
            let executable = executable
                .to_str()
                .ok_or_else(|| "current executable path is not UTF-8".to_owned())?;
            let entitlements =
                probe.command_output("codesign", &["-d", "--entitlements", ":-", executable])?;
            entitlements
                .contains("com.apple.security.hypervisor")
                .then_some(())
                .ok_or_else(|| "com.apple.security.hypervisor entitlement is missing".into())
        }
        "linux" => {
            if !matches!(probe.arch(), "x86_64" | "aarch64") {
                return Err("Linux KVM requires x86_64 or aarch64".into());
            }
            if !probe.accessible_read_write(Path::new("/dev/kvm")) {
                return Err("/dev/kvm must be readable and writable".into());
            }
            probe.worker_cgroup_enforcement()?;
            probe.worker_seccomp_enforcement()?;
            Ok(())
        }
        other => Err(format!("unsupported production platform: {other}")),
    }
}

fn inspect(config: &AppConfig, probe: &dyn Probe) -> Report {
    let mut checks = Vec::new();
    checks.push(result_check(
        "configuration",
        true,
        config::validate(config).map(|_| "configuration is self-consistent".to_owned()),
    ));
    checks.push(result_check(
        "data_dir",
        true,
        probe
            .writable(&config.storage.data_dir)
            .map(|()| format!("{} is writable", config.storage.data_dir.display())),
    ));
    checks.push(result_check(
        "copy_on_write",
        true,
        probe
            .cow_supported(&config.storage.data_dir)
            .and_then(|supported| {
                supported
                    .then(|| "filesystem clone/reflink probe succeeded".to_owned())
                    .ok_or_else(|| {
                        "filesystem does not support the required clone/reflink operation"
                            .to_owned()
                    })
            }),
    ));
    let required_bytes = config
        .storage
        .minimum_free_gib
        .saturating_mul(1024_u64.pow(3));
    checks.push(result_check(
        "free_space",
        true,
        probe
            .free_bytes(&config.storage.data_dir)
            .and_then(|available| {
                (available >= required_bytes)
                    .then(|| format!("{} bytes available", available))
                    .ok_or_else(|| {
                        format!("only {available} bytes available; require {required_bytes}")
                    })
            }),
    ));
    checks.push(result_check(
        "libkrun_presence",
        true,
        probe.libkrun_present(config),
    ));
    checks.push(result_check(
        "libkrun_capabilities",
        true,
        probe.libkrun_capabilities(config).and_then(|capabilities| {
            (capabilities.version == LIBKRUN_VERSION
                && capabilities.blk
                && capabilities.net
                && capabilities.vsock)
                .then(|| format!("libkrun {} exposes BLK/NET/vsock", capabilities.version))
                .ok_or_else(|| {
                    format!(
                        "require libkrun {LIBKRUN_VERSION} with BLK/NET/vsock; found version={} blk={} net={} vsock={}",
                        capabilities.version, capabilities.blk, capabilities.net, capabilities.vsock
                    )
                })
        }),
    ));
    checks.push(result_check(
        "runtime_bundle",
        true,
        probe.runtime_bundle(config),
    ));
    checks.push(result_check(
        "database_migrations",
        true,
        probe
            .database_migrations_current(config)
            .and_then(|current| {
                current
                    .then(|| "all database migrations are applied".to_owned())
                    .ok_or_else(|| "database has pending migrations".to_owned())
            }),
    ));
    checks.push(status_check(
        "sqlite_single_instance",
        if config.database.url.starts_with("sqlite:") {
            Status::Warn
        } else {
            Status::NotApplicable
        },
        false,
        "SQLite deployments must run exactly one active control-plane process",
    ));
    add_platform_checks(&mut checks, probe);
    let overall = !checks
        .iter()
        .any(|check| check.required && check.status == Status::Fail);
    Report { overall, checks }
}

fn add_platform_checks(checks: &mut Vec<Check>, probe: &dyn Probe) {
    match probe.os() {
        "macos" => {
            let version = probe.command_output("sw_vers", &["-productVersion"]);
            let platform = version.and_then(|version| {
                let major = version
                    .trim()
                    .split('.')
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or_else(|| "unable to parse macOS version".to_owned())?;
                (probe.arch() == "aarch64" && major >= 14)
                    .then(|| format!("macOS {major} on Apple Silicon"))
                    .ok_or_else(|| "requires macOS 14+ on Apple Silicon".to_owned())
            });
            checks.push(result_check("platform", true, platform));
            checks.push(result_check(
                "hvf_support",
                true,
                probe
                    .command_output("sysctl", &["-n", "kern.hv_support"])
                    .and_then(|value| {
                        (value.trim() == "1")
                            .then(|| "Hypervisor.framework is supported".to_owned())
                            .ok_or_else(|| "kern.hv_support is not 1".to_owned())
                    }),
            ));
            let executable = std::env::current_exe()
                .ok()
                .and_then(|path| path.into_os_string().into_string().ok());
            checks.push(result_check(
                "hvf_entitlement",
                true,
                executable
                    .as_deref()
                    .ok_or_else(|| "cannot resolve current executable".to_owned())
                    .and_then(|path| {
                        probe.command_output("codesign", &["-d", "--entitlements", ":-", path])
                    })
                    .and_then(|entitlements| {
                        entitlements
                            .contains("com.apple.security.hypervisor")
                            .then(|| "hypervisor entitlement is present".to_owned())
                            .ok_or_else(|| {
                                "com.apple.security.hypervisor entitlement is missing".to_owned()
                            })
                    }),
            ));
            checks.push(result_check(
                "code_signature",
                true,
                executable
                    .as_deref()
                    .ok_or_else(|| "cannot resolve current executable".to_owned())
                    .and_then(|path| probe.command_output("codesign", &["-v", path]))
                    .map(|_| "code signature verification passed".to_owned()),
            ));
            checks.push(status_check(
                "worker_cgroup_enforcement",
                Status::NotApplicable,
                false,
                "cgroup v2 worker placement only applies to Linux",
            ));
            checks.push(status_check(
                "worker_seccomp_enforcement",
                Status::NotApplicable,
                false,
                "Linux seccomp only applies to Linux",
            ));
        }
        "linux" => {
            let arch_ok = matches!(probe.arch(), "x86_64" | "aarch64");
            let cpu_virtualization = if probe.arch() == "x86_64" {
                probe
                    .read_text(Path::new("/proc/cpuinfo"))
                    .is_ok_and(|cpuinfo| {
                        cpuinfo
                            .split_whitespace()
                            .any(|item| matches!(item, "vmx" | "svm"))
                    })
            } else {
                probe.accessible_read_write(Path::new("/dev/kvm"))
            };
            checks.push(status_check(
                "platform",
                if arch_ok && cpu_virtualization {
                    Status::Pass
                } else {
                    Status::Fail
                },
                true,
                "requires Linux x86_64/aarch64 with hardware virtualization",
            ));
            checks.push(status_check(
                "kvm_device",
                if probe.accessible_read_write(Path::new("/dev/kvm")) {
                    Status::Pass
                } else {
                    Status::Fail
                },
                true,
                "/dev/kvm must be readable and writable",
            ));
            checks.push(status_check(
                "kvm_module",
                if probe.exists(Path::new("/sys/module/kvm")) {
                    Status::Pass
                } else {
                    Status::Fail
                },
                true,
                "the KVM kernel module must be loaded",
            ));
            checks.push(status_check(
                "cgroup_v2",
                if probe.exists(Path::new("/sys/fs/cgroup/cgroup.controllers")) {
                    Status::Pass
                } else {
                    Status::Fail
                },
                true,
                "cgroup v2 controllers must be mounted",
            ));
            checks.push(result_check(
                "worker_cgroup_enforcement",
                true,
                probe.worker_cgroup_enforcement(),
            ));
            checks.push(result_check(
                "worker_seccomp_enforcement",
                true,
                probe.worker_seccomp_enforcement(),
            ));
            checks.push(status_check(
                "tun",
                if probe.accessible_read_write(Path::new("/dev/net/tun")) {
                    Status::Pass
                } else {
                    Status::Fail
                },
                true,
                "/dev/net/tun must be readable and writable",
            ));
            checks.push(status_check(
                "hvf_entitlement",
                Status::NotApplicable,
                false,
                "only applies to macOS",
            ));
        }
        _ => checks.push(status_check(
            "platform",
            Status::Fail,
            true,
            "only macOS Apple Silicon and Linux KVM are supported",
        )),
    }
}

fn verify_runtime_bundles(config: &AppConfig) -> Result<String, String> {
    let manager = runtime_image::configured_manager(config)?;
    let resolved = manager
        .resolve_installed("node", std::env::consts::ARCH)
        .map_err(|error| error.to_string())?;
    Ok(format!(
        "verified signed node runtime {} for {} with rootfs sha256 {}",
        resolved.manifest.runtime_version, resolved.manifest.arch, resolved.rootfs_sha256
    ))
}

fn result_check(name: &'static str, required: bool, result: Result<String, String>) -> Check {
    match result {
        Ok(message) => status_check(name, Status::Pass, required, message),
        Err(message) => status_check(name, Status::Fail, required, message),
    }
}

fn status_check(
    name: &'static str,
    status: Status,
    required: bool,
    message: impl Into<String>,
) -> Check {
    Check {
        name,
        status,
        required,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mock {
        libkrun: Result<(), &'static str>,
        runtime: Result<(), &'static str>,
        migrations: Result<bool, &'static str>,
        os: &'static str,
        arch: &'static str,
        cgroup: Result<(), &'static str>,
        seccomp: Result<(), &'static str>,
    }

    impl Probe for Mock {
        fn writable(&self, _: &Path) -> Result<(), String> {
            Ok(())
        }
        fn free_bytes(&self, _: &Path) -> Result<u64, String> {
            Ok(100 * 1024_u64.pow(3))
        }
        fn cow_supported(&self, _: &Path) -> Result<bool, String> {
            Ok(true)
        }
        fn accessible_read_write(&self, _: &Path) -> bool {
            true
        }
        fn exists(&self, _: &Path) -> bool {
            true
        }
        fn read_text(&self, _: &Path) -> Result<String, String> {
            Ok("flags vmx".into())
        }
        fn command_output(&self, program: &str, args: &[&str]) -> Result<String, String> {
            match (program, args.first().copied()) {
                ("sw_vers", _) => Ok("14.0\n".into()),
                ("sysctl", _) => Ok("1\n".into()),
                ("codesign", Some("-d")) => Ok("com.apple.security.hypervisor\n".into()),
                ("codesign", _) => Ok(String::new()),
                _ => Err("unexpected command".into()),
            }
        }
        fn libkrun_present(&self, _: &AppConfig) -> Result<String, String> {
            Ok("present".into())
        }
        fn libkrun_capabilities(&self, _: &AppConfig) -> Result<LibkrunCapabilities, String> {
            self.libkrun
                .map(|()| LibkrunCapabilities {
                    version: LIBKRUN_VERSION.into(),
                    blk: true,
                    net: true,
                    vsock: true,
                })
                .map_err(str::to_owned)
        }
        fn database_migrations_current(&self, _: &AppConfig) -> Result<bool, String> {
            self.migrations.map_err(str::to_owned)
        }
        fn runtime_bundle(&self, _: &AppConfig) -> Result<String, String> {
            self.runtime
                .map(|()| "verified runtime".into())
                .map_err(str::to_owned)
        }
        fn worker_cgroup_enforcement(&self) -> Result<String, String> {
            self.cgroup
                .map(|()| "cgroup limits verified".into())
                .map_err(str::to_owned)
        }
        fn worker_seccomp_enforcement(&self) -> Result<String, String> {
            self.seccomp
                .map(|()| "seccomp verified".into())
                .map_err(str::to_owned)
        }
        fn os(&self) -> &'static str {
            self.os
        }
        fn arch(&self) -> &'static str {
            self.arch
        }
    }

    fn healthy_mock() -> Mock {
        Mock {
            libkrun: Ok(()),
            runtime: Ok(()),
            migrations: Ok(true),
            os: "macos",
            arch: "aarch64",
            cgroup: Ok(()),
            seccomp: Ok(()),
        }
    }

    #[test]
    fn all_required_checks_must_pass() {
        assert!(inspect(&AppConfig::default(), &healthy_mock()).overall);
    }

    #[test]
    fn serve_platform_readiness_reuses_required_hypervisor_and_worker_gates() {
        assert!(platform_readiness_with(&healthy_mock()).is_ok());
        let error = platform_readiness_with(&Mock {
            os: "linux",
            arch: "x86_64",
            seccomp: Err("pinned policy unavailable"),
            ..healthy_mock()
        })
        .expect_err("Linux seccomp is required");
        assert!(error.contains("pinned policy unavailable"));
    }

    #[test]
    fn unavailable_libkrun_probe_is_a_required_failure() {
        let report = inspect(
            &AppConfig::default(),
            &Mock {
                libkrun: Err("probe unavailable"),
                ..healthy_mock()
            },
        );
        assert!(!report.overall);
        assert_eq!(
            report
                .checks
                .iter()
                .find(|check| check.name == "libkrun_capabilities")
                .expect("libkrun check")
                .status,
            Status::Fail
        );
    }

    #[test]
    fn runtime_warning_cannot_make_doctor_healthy() {
        let report = inspect(
            &AppConfig::default(),
            &Mock {
                runtime: Err("signature unverified"),
                ..healthy_mock()
            },
        );
        assert!(!report.overall);
        let check = report
            .checks
            .iter()
            .find(|check| check.name == "runtime_bundle")
            .expect("runtime check");
        assert!(check.required);
        assert_eq!(check.status, Status::Fail);
    }

    #[test]
    fn linux_readiness_reports_required_cgroup_and_seccomp_results() {
        let report = inspect(
            &AppConfig::default(),
            &Mock {
                os: "linux",
                arch: "x86_64",
                seccomp: Err("pinned profile unavailable"),
                ..healthy_mock()
            },
        );
        assert!(!report.overall);
        let cgroup = report
            .checks
            .iter()
            .find(|check| check.name == "worker_cgroup_enforcement")
            .expect("cgroup check");
        assert!(cgroup.required);
        assert_eq!(cgroup.status, Status::Pass);
        let seccomp = report
            .checks
            .iter()
            .find(|check| check.name == "worker_seccomp_enforcement")
            .expect("seccomp check");
        assert!(seccomp.required);
        assert_eq!(seccomp.status, Status::Fail);
        assert!(seccomp.message.contains("pinned profile unavailable"));
    }
}
