//! Helpers shared by unit tests. Compiled only for `cargo test`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A tiny HTTP/1.1 server on 127.0.0.1 that serves canned responses, so
/// registry code can be tested without the real network.
///
/// Routes are `(path, status, body)`. If a path is listed several times the
/// responses are served in order and the last one repeats. Unknown paths
/// return 404.
pub struct MockRegistry {
    pub url: String,
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

type Routes = HashMap<String, Vec<(u16, Vec<u8>)>>;

impl MockRegistry {
    pub async fn start(routes: Vec<(&str, u16, Vec<u8>)>) -> MockRegistry {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut table: Routes = HashMap::new();
        for (path, status, body) in routes {
            table
                .entry(path.to_string())
                .or_default()
                .push((status, body));
        }
        let table = Arc::new(table);
        let hits: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
        let hits_for_server = Arc::clone(&hits);

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let table = Arc::clone(&table);
                let hits = Arc::clone(&hits_for_server);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&buf);
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let count = {
                        let mut h = hits.lock().expect("lock");
                        let c = h.entry(path.clone()).or_insert(0);
                        *c += 1;
                        *c
                    };
                    let (status, body) = match table.get(&path) {
                        Some(responses) => {
                            let idx = (count - 1).min(responses.len() - 1);
                            responses[idx].clone()
                        }
                        None => (404, b"not found".to_vec()),
                    };
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(&body).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        MockRegistry {
            url: format!("http://{addr}"),
            hits,
        }
    }

    pub fn hits(&self, path: &str) -> usize {
        self.hits
            .lock()
            .expect("lock")
            .get(path)
            .copied()
            .unwrap_or(0)
    }

    pub fn total_hits(&self) -> usize {
        self.hits.lock().expect("lock").values().sum()
    }
}

/// Build a gzip-compressed tarball from `(path, contents)` pairs.
pub fn build_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (path, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, path, *data)
            .expect("append");
    }
    builder.into_inner().expect("tar").finish().expect("gzip")
}
