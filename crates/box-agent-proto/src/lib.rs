//! Versioned guest-agent protocol generated from the checked-in protobuf contract.
pub const PROTOCOL_VERSION: u32 = 1;
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/r#box.agent.v1.rs"));
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        PROTOCOL_VERSION,
        v1::{
            BrowserFrame, BrowserRequest, ExecRequest, FileEntry, GitRequest, Handshake,
            HarnessEvent, InstallSkillRequest, RemoveSkillRequest, RunHarnessRequest, SkillFile,
            TunnelFrame,
        },
    };
    use prost::Message;

    #[test]
    fn handshake_roundtrips_through_protobuf() {
        let original = Handshake {
            protocol_version: PROTOCOL_VERSION,
            box_id: "box".into(),
            boot_nonce: vec![1, 2],
            runtime: "node".into(),
            arch: "aarch64".into(),
            agent_version: "0".into(),
            capabilities: vec!["exec".into()],
        };
        let encoded = original.encode_to_vec();
        assert_eq!(Handshake::decode(encoded.as_slice()).unwrap(), original);
    }

    #[test]
    fn exec_environment_roundtrips_through_protobuf() {
        let original = ExecRequest {
            argv: vec!["env".into()],
            cwd: "/workspace".into(),
            execution_id: "run-1".into(),
            timeout_ms: 1_000,
            max_output_bytes: 4_096,
            environment: HashMap::from([("TOKEN".into(), "secret".into())]),
        };
        let encoded = original.encode_to_vec();
        assert_eq!(ExecRequest::decode(encoded.as_slice()).unwrap(), original);
    }

    #[test]
    fn file_mtime_roundtrips_as_unix_milliseconds() {
        let original = FileEntry {
            path: "a".into(),
            directory: false,
            size: 1,
            modified_at_unix_millis: 1_700_000_000_123,
        };
        let encoded = original.encode_to_vec();
        assert_eq!(FileEntry::decode(encoded.as_slice()).unwrap(), original);
    }

    #[test]
    fn git_request_roundtrips_without_a_shell_command() {
        let original = GitRequest {
            execution_id: "git-1".into(),
            args: vec!["status".into(), "--short".into()],
            cwd: "/workspace/home/repo".into(),
            environment: HashMap::from([("GIT_TERMINAL_PROMPT".into(), "0".into())]),
            timeout_ms: 30_000,
            max_output_bytes: 4_096,
        };
        let encoded = original.encode_to_vec();
        assert_eq!(GitRequest::decode(encoded.as_slice()).unwrap(), original);
    }

    #[test]
    fn harness_request_and_event_roundtrip_through_protobuf() {
        let request = RunHarnessRequest {
            execution_id: "run-1".into(),
            command: "fixture-harness".into(),
            args: vec!["--flag".into()],
            prompt: "hello".into(),
            model: "custom".into(),
            session_id: "session-1".into(),
            cwd: "/workspace/home".into(),
            environment: HashMap::from([("TOKEN".into(), "secret".into())]),
            timeout_ms: 30_000,
            max_output_bytes: 4_096,
        };
        let encoded = request.encode_to_vec();
        assert_eq!(
            RunHarnessRequest::decode(encoded.as_slice()).unwrap(),
            request
        );

        let event = HarnessEvent {
            sequence: 2,
            event_type: "done".into(),
            payload_json: r#"{"output":"hello"}"#.into(),
            terminal: true,
            execution_id: "run-1".into(),
            stderr: Vec::new(),
        };
        let encoded = event.encode_to_vec();
        assert_eq!(HarnessEvent::decode(encoded.as_slice()).unwrap(), event);
    }

    #[test]
    fn tunnel_frame_carries_a_single_port_handshake_and_half_close() {
        let frame = TunnelFrame {
            data: b"request".to_vec(),
            port: 8080,
            eof: true,
        };
        let encoded = frame.encode_to_vec();
        assert_eq!(TunnelFrame::decode(encoded.as_slice()).unwrap(), frame);
    }

    #[test]
    fn skill_mutations_roundtrip_exact_package_paths_and_bytes() {
        let install = InstallSkillRequest {
            skill_id: "upstash/context7/context7-cli".into(),
            name: "context7-cli".into(),
            files: vec![
                SkillFile {
                    path: "SKILL.md".into(),
                    content: b"manifest".to_vec(),
                },
                SkillFile {
                    path: "references/guide.md".into(),
                    content: vec![0, 1, 255],
                },
            ],
        };
        let encoded = install.encode_to_vec();
        assert_eq!(
            InstallSkillRequest::decode(encoded.as_slice()).unwrap(),
            install
        );

        let remove = RemoveSkillRequest {
            name: "context7-cli".into(),
        };
        let encoded = remove.encode_to_vec();
        assert_eq!(
            RemoveSkillRequest::decode(encoded.as_slice()).unwrap(),
            remove
        );
    }

    #[test]
    fn browser_request_and_frame_preserve_typed_operation_fields() {
        let request = BrowserRequest {
            operation: "create_tab".into(),
            tab_id: "tab_fixture".into(),
            url: "https://example.invalid".into(),
            wait_until: "networkidle".into(),
            timeout_ms: 30_000,
            full_page: false,
            json_payload: String::new(),
        };
        let encoded = request.encode_to_vec();
        assert_eq!(BrowserRequest::decode(encoded.as_slice()).unwrap(), request);

        let frame = BrowserFrame {
            sequence: 0,
            json_payload: r#"{"id":"tab_fixture"}"#.into(),
            data: Vec::new(),
            eof: true,
        };
        let encoded = frame.encode_to_vec();
        assert_eq!(BrowserFrame::decode(encoded.as_slice()).unwrap(), frame);
    }
}
