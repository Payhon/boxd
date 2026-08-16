#[cfg(unix)]
#[test]
fn askpass_returns_username_or_token_without_booting_the_agent() {
    let binary = env!("CARGO_BIN_EXE_box-agent");
    let username = std::process::Command::new(binary)
        .arg("Username for 'https://github.com':")
        .env("BOXD_GIT_ASKPASS_TOKEN", "fixture-token-never-log")
        .output()
        .expect("askpass username process");
    assert!(username.status.success());
    assert_eq!(username.stdout, b"x-access-token\n");
    assert!(username.stderr.is_empty());

    let password = std::process::Command::new(binary)
        .arg("Password for 'https://x-access-token@github.com':")
        .env("BOXD_GIT_ASKPASS_TOKEN", "fixture-token-never-log")
        .output()
        .expect("askpass password process");
    assert!(password.status.success());
    assert_eq!(password.stdout, b"fixture-token-never-log\n");
    assert!(password.stderr.is_empty());
}
