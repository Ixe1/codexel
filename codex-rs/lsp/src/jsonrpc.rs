use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::sync::oneshot;

#[derive(Debug, thiserror::Error)]
pub enum JsonRpcError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("request cancelled")]
    Cancelled,
    #[error("server error: {0}")]
    Server(String),
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcRequest<'a, T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<T>,
}

#[derive(Debug, Clone, Serialize)]
struct JsonRpcNotification<'a, T> {
    jsonrpc: &'static str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<T>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct JsonRpcResponse {
    #[serde(rename = "jsonrpc")]
    #[serde(default)]
    _jsonrpc: Option<String>,
    id: u64,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcResponseError>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct JsonRpcResponseError {
    #[serde(default)]
    _code: Option<i64>,
    message: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
pub enum IncomingMessage {
    Response(JsonRpcResponse),
    Notification {
        #[serde(default)]
        _jsonrpc: Option<String>,
        method: String,
        #[serde(default)]
        params: Option<Value>,
    },
    Request {
        #[serde(default)]
        _jsonrpc: Option<String>,
        #[serde(rename = "id")]
        _id: u64,
        #[serde(rename = "method")]
        _method: String,
        #[serde(default)]
        #[serde(rename = "params")]
        _params: Option<Value>,
    },
}

pub(crate) struct JsonRpcClient {
    next_id: Mutex<u64>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, JsonRpcError>>>>,
    writer: Mutex<Box<dyn AsyncWrite + Unpin + Send>>,
}

impl JsonRpcClient {
    pub(crate) fn new(writer: Box<dyn AsyncWrite + Unpin + Send>) -> Self {
        Self {
            next_id: Mutex::new(1),
            pending: Mutex::new(HashMap::new()),
            writer: Mutex::new(writer),
        }
    }

    pub(crate) async fn request<P: Serialize>(
        &self,
        method: &str,
        params: Option<P>,
    ) -> Result<Value, JsonRpcError> {
        let id = {
            let mut guard = self.next_id.lock().await;
            let id = *guard;
            *guard = guard.saturating_add(1);
            id
        };

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let msg = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        self.write_message(&msg).await?;

        match rx.await {
            Ok(res) => res,
            Err(_) => Err(JsonRpcError::Cancelled),
        }
    }

    pub(crate) async fn notify<P: Serialize>(
        &self,
        method: &str,
        params: Option<P>,
    ) -> Result<(), JsonRpcError> {
        let msg = JsonRpcNotification {
            jsonrpc: "2.0",
            method,
            params,
        };
        self.write_message(&msg).await
    }

    async fn write_message<T: Serialize>(&self, msg: &T) -> Result<(), JsonRpcError> {
        let json = serde_json::to_vec(msg)?;
        let mut writer = self.writer.lock().await;
        writer
            .write_all(format!("Content-Length: {}\r\n\r\n", json.len()).as_bytes())
            .await?;
        writer.write_all(&json).await?;
        writer.flush().await?;
        Ok(())
    }

    pub(crate) async fn handle_incoming(&self, msg: IncomingMessage) -> Result<(), JsonRpcError> {
        match msg {
            IncomingMessage::Response(resp) => {
                let tx = self.pending.lock().await.remove(&resp.id);
                if let Some(tx) = tx {
                    let result = match (resp.result, resp.error) {
                        (Some(result), None) => Ok(result),
                        (None, Some(err)) => Err(JsonRpcError::Server(err.message)),
                        _ => Err(JsonRpcError::Protocol(
                            "response missing result and error".to_string(),
                        )),
                    };
                    let _ = tx.send(result);
                }
            }
            IncomingMessage::Notification { .. } | IncomingMessage::Request { .. } => {}
        }
        Ok(())
    }
}

pub(crate) async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<IncomingMessage, JsonRpcError> {
    let content_len = read_content_length(reader).await?;
    let mut buf = vec![0u8; content_len];
    reader.read_exact(&mut buf).await?;
    let msg = serde_json::from_slice::<IncomingMessage>(&buf)?;
    Ok(msg)
}

async fn read_content_length<R: AsyncRead + Unpin>(reader: &mut R) -> Result<usize, JsonRpcError> {
    let mut header = Vec::new();
    loop {
        let line = read_header_line(reader).await?;
        if line.is_empty() {
            break;
        }
        header.push(line);
        if header.len() > 128 {
            return Err(JsonRpcError::Protocol("too many headers".to_string()));
        }
    }

    for line in header {
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or_default().trim();
        if key == "content-length" {
            return value
                .parse::<usize>()
                .map_err(|_| JsonRpcError::Protocol(format!("invalid Content-Length: {value}")));
        }
    }

    Err(JsonRpcError::Protocol(
        "missing Content-Length header".to_string(),
    ))
}

async fn read_header_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, JsonRpcError> {
    let mut buf = Vec::new();
    loop {
        let b = reader.read_u8().await?;
        buf.push(b);
        if buf.len() > 16 * 1024 {
            return Err(JsonRpcError::Protocol("header line too long".to_string()));
        }
        if buf.ends_with(b"\n") {
            break;
        }
    }
    let line = String::from_utf8_lossy(&buf);
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub(crate) fn file_uri(path: &std::path::Path) -> Result<url::Url, JsonRpcError> {
    url::Url::from_file_path(path).map_err(|_| {
        JsonRpcError::Protocol(format!("failed to create file uri for {}", path.display()))
    })
}

pub(crate) struct JsonRpcPump {
    client: Arc<JsonRpcClient>,
}

impl JsonRpcPump {
    pub(crate) fn new(client: Arc<JsonRpcClient>) -> Self {
        Self { client }
    }

    pub(crate) async fn run<R: AsyncRead + Unpin + Send + 'static>(
        self,
        mut reader: R,
        notification_tx: tokio::sync::mpsc::UnboundedSender<(String, Option<Value>)>,
    ) -> Result<(), JsonRpcError> {
        loop {
            let msg = read_message(&mut reader).await?;
            match &msg {
                IncomingMessage::Notification { method, params, .. } => {
                    let _ = notification_tx.send((method.clone(), params.clone()));
                }
                IncomingMessage::Request { .. } => {
                    // For now, ignore server->client requests (rare for LSP).
                }
                IncomingMessage::Response(_) => {}
            }
            self.client.handle_incoming(msg).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn reads_single_message() {
        let payload = br#"{"jsonrpc":"2.0","method":"foo","params":{"x":1}}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("Content-Length: {}\r\n\r\n", payload.len()).as_bytes());
        bytes.extend_from_slice(payload);
        let mut reader = BufReader::new(Cursor::new(bytes));
        let msg = read_message(&mut reader).await.unwrap();
        match msg {
            IncomingMessage::Notification { method, params, .. } => {
                assert_eq!(method, "foo");
                assert_eq!(params.unwrap()["x"], 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
