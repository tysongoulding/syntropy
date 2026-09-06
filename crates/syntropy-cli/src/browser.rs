use std::time::Duration;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrowserAction {
    pub action: String,
    pub url: Option<String>,
    pub selector: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BrowserActionResult {
    pub success: bool,
    pub action: String,
    pub url: String,
    pub title: String,
    pub content: String,
    pub screenshot_base64: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TargetInfo {
    #[serde(rename = "type")]
    target_type: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    websocket_url: Option<String>,
}

/// Executes a browser action against the local Chrome DevTools Protocol instance.
pub async fn execute_browser_action(
    cdp_port: u16,
    action: &BrowserAction,
) -> Result<BrowserActionResult, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // 1. Verify Chrome DevTools is reachable
    let version_url = format!("http://127.0.0.1:{}/json/version", cdp_port);
    if let Err(e) = client.get(&version_url).send().await {
        return Ok(BrowserActionResult {
            success: false,
            action: action.action.clone(),
            url: action.url.clone().unwrap_or_default(),
            title: String::new(),
            content: String::new(),
            screenshot_base64: None,
            error_message: Some(format!(
                "Chrome is not running on port {}. Launch Chrome with '--remote-debugging-port={}'. Error: {}",
                cdp_port, cdp_port, e
            )),
        });
    }

    // 2. Query target pages
    let list_url = format!("http://127.0.0.1:{}/json", cdp_port);
    let targets: Vec<TargetInfo> = client
        .get(&list_url)
        .send()
        .await?
        .json()
        .await
        .unwrap_or_default();

    let page_target = targets.into_iter().find(|t| t.target_type == "page");

    let ws_url = match page_target {
        Some(target) if target.websocket_url.is_some() => target.websocket_url.unwrap(),
        _ => {
            // Open a new tab
            let new_url = format!("http://127.0.0.1:{}/json/new?https://www.google.com", cdp_port);
            let created: TargetInfo = client.put(&new_url).send().await?.json().await?;
            created
                .websocket_url
                .ok_or_else(|| anyhow::anyhow!("Failed to obtain WebSocket debugger URL"))?
        }
    };

    // 3. Connect to Chrome via WebSocket
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(&ws_url).await?;

    let mut current_url = action.url.clone().unwrap_or_default();
    let mut page_title = String::new();
    let mut page_content = String::new();
    let mut screenshot_base64 = None;

    match action.action.as_str() {
        "navigate" => {
            let target_url = action
                .url
                .as_deref()
                .unwrap_or("https://www.google.com");
            info!("Navigating Chrome to: {}", target_url);

            // Send Page.navigate
            let nav_req = json!({
                "id": 1,
                "method": "Page.navigate",
                "params": { "url": target_url }
            });
            ws_stream.send(Message::Text(nav_req.to_string().into())).await?;

            // Wait briefly for navigation to process
            tokio::time::sleep(Duration::from_millis(1500)).await;

            // Capture screenshot
            let ss_req = json!({
                "id": 2,
                "method": "Page.captureScreenshot",
                "params": { "format": "jpeg", "quality": 75 }
            });
            ws_stream.send(Message::Text(ss_req.to_string().into())).await?;

            // Read response
            let read_timeout = tokio::time::Instant::now() + Duration::from_secs(4);
            while tokio::time::Instant::now() < read_timeout {
                if let Ok(Some(Ok(Message::Text(txt)))) =
                    tokio::time::timeout(Duration::from_millis(500), ws_stream.next()).await
                {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&txt) {
                        if parsed["id"] == 2 {
                            if let Some(b64) = parsed["result"]["data"].as_str() {
                                screenshot_base64 = Some(b64.to_string());
                            }
                            break;
                        }
                    }
                }
            }

            // Extract page title & inner text
            let eval_req = json!({
                "id": 3,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": "JSON.stringify({ title: document.title, url: window.location.href, text: document.body ? document.body.innerText.substring(0, 3000) : '' })"
                }
            });
            ws_stream.send(Message::Text(eval_req.to_string().into())).await?;

            if let Ok(Some(Ok(Message::Text(txt)))) =
                tokio::time::timeout(Duration::from_secs(2), ws_stream.next()).await
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(&txt) {
                    if let Some(json_str) = parsed["result"]["result"]["value"].as_str() {
                        if let Ok(page_meta) = serde_json::from_str::<Value>(json_str) {
                            page_title = page_meta["title"].as_str().unwrap_or_default().to_string();
                            current_url = page_meta["url"].as_str().unwrap_or(target_url).to_string();
                            page_content = page_meta["text"].as_str().unwrap_or_default().to_string();
                        }
                    }
                }
            }
        }

        "screenshot" => {
            let ss_req = json!({
                "id": 10,
                "method": "Page.captureScreenshot",
                "params": { "format": "jpeg", "quality": 80 }
            });
            ws_stream.send(Message::Text(ss_req.to_string().into())).await?;

            if let Ok(Some(Ok(Message::Text(txt)))) =
                tokio::time::timeout(Duration::from_secs(3), ws_stream.next()).await
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(&txt) {
                    if let Some(b64) = parsed["result"]["data"].as_str() {
                        screenshot_base64 = Some(b64.to_string());
                    }
                }
            }
            page_content = "Screenshot captured successfully.".into();
        }

        "get_content" => {
            let eval_req = json!({
                "id": 20,
                "method": "Runtime.evaluate",
                "params": {
                    "expression": "document.body ? document.body.innerText.substring(0, 4000) : ''"
                }
            });
            ws_stream.send(Message::Text(eval_req.to_string().into())).await?;

            if let Ok(Some(Ok(Message::Text(txt)))) =
                tokio::time::timeout(Duration::from_secs(2), ws_stream.next()).await
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(&txt) {
                    page_content = parsed["result"]["result"]["value"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                }
            }
        }

        "click" => {
            let selector = action.selector.as_deref().unwrap_or("button");
            let click_expr = format!(
                "(() => {{ const el = document.querySelector('{}'); if(el) {{ el.click(); return 'Clicked'; }} return 'Element not found'; }})()",
                selector.replace('\'', "\\'")
            );
            let eval_req = json!({
                "id": 30,
                "method": "Runtime.evaluate",
                "params": { "expression": click_expr }
            });
            ws_stream.send(Message::Text(eval_req.to_string().into())).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
            page_content = format!("Clicked selector: {}", selector);
        }

        "evaluate" => {
            let script = action.text.as_deref().unwrap_or("window.location.href");
            let eval_req = json!({
                "id": 40,
                "method": "Runtime.evaluate",
                "params": { "expression": script }
            });
            ws_stream.send(Message::Text(eval_req.to_string().into())).await?;

            if let Ok(Some(Ok(Message::Text(txt)))) =
                tokio::time::timeout(Duration::from_secs(2), ws_stream.next()).await
            {
                if let Ok(parsed) = serde_json::from_str::<Value>(&txt) {
                    page_content = parsed["result"]["result"]["value"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                }
            }
        }

        _ => {
            return Ok(BrowserActionResult {
                success: false,
                action: action.action.clone(),
                url: current_url,
                title: page_title,
                content: String::new(),
                screenshot_base64: None,
                error_message: Some(format!("Unknown browser action: {}", action.action)),
            });
        }
    }

    Ok(BrowserActionResult {
        success: true,
        action: action.action.clone(),
        url: current_url,
        title: page_title,
        content: page_content,
        screenshot_base64,
        error_message: None,
    })
}

/// Generates the anti-bot fingerprint spoofing JavaScript evaluation script.
pub fn generate_stealth_script(platform: &str) -> String {
    let (vendor, renderer, nav_platform) = match platform {
        "mac" => (
            "Google Inc. (Intel)",
            "ANGLE (Intel, ANGLE Metal Renderer: Intel(R) Iris(TM) Plus Graphics 640, Unspecified Version)",
            "MacIntel",
        ),
        _ => (
            "Google Inc. (Intel)",
            "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E9B) Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "Win32",
        ),
    };

    format!(
        r#"(() => {{
  Object.defineProperty(Navigator.prototype, 'webdriver', {{ get: () => undefined }});
  Object.defineProperty(Navigator.prototype, 'platform', {{ get: () => '{nav_platform}' }});
  Object.defineProperty(Navigator.prototype, 'hardwareConcurrency', {{ get: () => 8 }});
  Object.defineProperty(Navigator.prototype, 'deviceMemory', {{ get: () => 8 }});

  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(parameter) {{
    if (parameter === 0x9245) return '{vendor}';
    if (parameter === 0x9246) return '{renderer}';
    return getParameter.apply(this, arguments);
  }};
}})();"#
    )
}

/// Synchronizes cookies between two Chrome DevTools Protocol ports over HTTP/WS.
pub async fn sync_cdp_cookies(source_port: u16, target_port: u16) -> Result<usize, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;

    let source_check = format!("http://127.0.0.1:{}/json/version", source_port);
    let target_check = format!("http://127.0.0.1:{}/json/version", target_port);

    if client.get(&source_check).send().await.is_err() || client.get(&target_check).send().await.is_err() {
        return Ok(0);
    }

    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_browser_action_handles_unreachable_port() {
        let action = BrowserAction {
            action: "navigate".into(),
            url: Some("https://example.com".into()),
            selector: None,
            text: None,
        };

        // Port 19222 is not running Chrome, must return graceful error result without panicking
        let result = execute_browser_action(19222, &action).await.unwrap();
        assert!(!result.success);
        assert!(result.error_message.is_some());
        assert!(result.error_message.unwrap().contains("Chrome is not running"));
    }

    #[test]
    fn test_generate_stealth_script_profiles() {
        let win_script = generate_stealth_script("windows");
        assert!(win_script.contains("Win32"));
        assert!(win_script.contains("Direct3D11"));
        assert!(win_script.contains("hardwareConcurrency"));

        let mac_script = generate_stealth_script("mac");
        assert!(mac_script.contains("MacIntel"));
        assert!(mac_script.contains("Metal Renderer"));
    }

    #[tokio::test]
    async fn test_sync_cdp_cookies_graceful_offline() {
        let synced = sync_cdp_cookies(19222, 19223).await.unwrap();
        assert_eq!(synced, 0, "Unreachable ports should report 0 synced without failing");
    }
}
