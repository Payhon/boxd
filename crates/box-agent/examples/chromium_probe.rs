use box_agent::{BrowserBackend, ChromiumBrowserBackend};
use box_agent_proto::v1::BrowserRequest;
use serde_json::Value;

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).expect("chromium path");
    let backend = ChromiumBrowserBackend::new(path).unwrap();
    let frames = backend
        .execute(BrowserRequest {
            operation: "create_tab".into(),
            url: "https://example.com/".into(),
            wait_until: "load".into(),
            timeout_ms: 30_000,
            ..Default::default()
        })
        .await
        .unwrap();
    let tab: Value = serde_json::from_str(&frames[0].json_payload).unwrap();
    let tab_id = tab["id"].as_str().unwrap().to_owned();
    assert!(tab_id.starts_with("tab_"));
    assert!(!frames[0].json_payload.contains("webSocketDebuggerUrl"));
    let content = backend
        .execute(BrowserRequest {
            operation: "content".into(),
            tab_id: tab_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let content: Value = serde_json::from_str(&content[0].json_payload).unwrap();
    assert_eq!(content["title"], "Example Domain");
    assert!(content["text"].as_str().unwrap().contains("Example Domain"));
    let screenshot = backend
        .execute(BrowserRequest {
            operation: "screenshot".into(),
            tab_id: tab_id.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    let png = screenshot
        .into_iter()
        .flat_map(|frame| frame.data)
        .collect::<Vec<_>>();
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    backend
        .execute(BrowserRequest {
            operation: "close_tab".into(),
            tab_id,
            ..Default::default()
        })
        .await
        .unwrap();
    println!("chromium CDP basics passed");
}
