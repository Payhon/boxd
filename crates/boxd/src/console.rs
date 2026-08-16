use rust_embed::RustEmbed;
use salvo::{
    http::{HeaderValue, StatusCode},
    prelude::{Request, Response, handler},
};

#[derive(RustEmbed)]
#[folder = "../../web/console/dist"]
struct ConsoleAssets;

/// Serves an immutable embedded asset or the SPA entry point. Unknown paths
/// with a filename extension remain 404 so missing assets are never disguised
/// as successful HTML responses.
#[handler]
pub async fn embedded_console(req: &mut Request, res: &mut Response) {
    let requested = req
        .param::<String>("path")
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_owned();
    let asset_name = if requested.is_empty() {
        "index.html"
    } else {
        requested.as_str()
    };
    let direct = ConsoleAssets::get(asset_name);
    let spa_fallback = direct.is_none()
        && !asset_name
            .rsplit('/')
            .next()
            .is_some_and(|part| part.contains('.'));
    let asset = direct.or_else(|| {
        (!asset_name
            .rsplit('/')
            .next()
            .is_some_and(|part| part.contains('.')))
        .then(|| ConsoleAssets::get("index.html"))
        .flatten()
    });
    let Some(asset) = asset else {
        res.status_code(StatusCode::NOT_FOUND);
        return;
    };
    let content_type = mime_guess::from_path(if asset_name == "index.html" || spa_fallback {
        "index.html"
    } else {
        asset_name
    })
    .first_or_octet_stream();
    if let Ok(value) = HeaderValue::from_str(content_type.as_ref()) {
        res.headers_mut().insert("content-type", value);
    }
    if asset_name.starts_with("assets/") {
        res.headers_mut().insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else {
        res.headers_mut().insert(
            "cache-control",
            HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        );
    }
    let _ = res.write_body(asset.data.into_owned());
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::{Router, Service, test::TestClient};

    #[tokio::test]
    async fn embeds_entry_assets_and_spa_fallback() {
        let service = Service::new(Router::with_path("console/{**path}").get(embedded_console));
        let response = TestClient::get("http://boxd.test/console/login")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::OK));
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("text/html")
        );

        let response = TestClient::get("http://boxd.test/console/assets/missing.js")
            .send(&service)
            .await;
        assert_eq!(response.status_code, Some(StatusCode::NOT_FOUND));
    }
}
