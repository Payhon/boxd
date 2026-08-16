//! Host executable composition root. Command implementations live in focused modules.

mod admin_auth;
mod cli;
mod composition;
mod config;
mod console;
mod doctor;
mod embedded_runtime;
mod github;
mod init;
mod model_provider;
mod observability;
mod preview_proxy;
mod recording;
mod request_quota;
mod runtime_host;
mod runtime_image;
mod skill_catalog;
mod webhook;

fn main() {
    // The VMM worker must enter before Tokio creates any helper threads. Its
    // private-runtime re-exec uses only async-signal-safe syscalls around fork;
    // running it inside a multithreaded runtime would invalidate that contract.
    if exact_internal_worker_invocation() {
        if let Err(error) = box_runtime_libkrun::worker_entry(0) {
            eprintln!("boxd: {error}");
            std::process::exit(cli::EXIT_WORKER_RUNTIME);
        }
        return;
    }
    if internal_worker_prefix() {
        eprintln!("boxd: __vmm-worker requires the exact hidden form '--spec-fd 0'");
        std::process::exit(cli::EXIT_WORKER_USAGE);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build boxd async runtime");
    if let Err(error) = runtime.block_on(cli::run()) {
        eprintln!("boxd: {}", error.message);
        std::process::exit(error.exit_code);
    }
}

fn internal_worker_prefix() -> bool {
    std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("__vmm-worker"))
}

fn exact_internal_worker_invocation() -> bool {
    let mut arguments = std::env::args_os().skip(1);
    arguments.next().as_deref() == Some(std::ffi::OsStr::new("__vmm-worker"))
        && arguments.next().as_deref() == Some(std::ffi::OsStr::new("--spec-fd"))
        && arguments.next().as_deref() == Some(std::ffi::OsStr::new("0"))
        && arguments.next().is_none()
}

#[cfg(test)]
mod tests {
    #[test]
    fn normal_test_process_is_not_a_worker() {
        assert!(!super::exact_internal_worker_invocation());
    }
}
