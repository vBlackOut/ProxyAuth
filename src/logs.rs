use crate::AppState;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use once_cell::sync::Lazy;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing_subscriber::fmt::MakeWriter;

pub static LOG_BUFFER: Lazy<Arc<Mutex<Vec<String>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

#[derive(Clone)]
pub struct ChannelWriter {
    sender: Arc<UnboundedSender<String>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = String::from_utf8_lossy(buf).to_string();
        let _ = self.sender.send(s);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct ChannelLogWriter {
    pub sender: Arc<UnboundedSender<String>>,
}

impl<'a> MakeWriter<'a> for ChannelLogWriter {
    type Writer = ChannelWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ChannelWriter {
            sender: self.sender.clone(),
        }
    }
}

pub async fn log_collector(mut rx: UnboundedReceiver<String>, max_logs: usize) {
    while let Some(log) = rx.recv().await {
        let mut logs = LOG_BUFFER.lock().unwrap();
        logs.push(log);
        if logs.len() > max_logs {
            logs.remove(0);
        }
    }
}

pub async fn get_logs(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let expected_token = &data.config.token_admin;
    let auth_header = req.headers().get("X-Auth-Token");

    match auth_header {
        Some(token) if token == expected_token => {
            let logs = LOG_BUFFER.lock().unwrap();
            HttpResponse::Ok()
                .content_type("text/plain")
                .body(logs.join(""))
        }
        _ => HttpResponse::Unauthorized().body("Invalid or missing token"),
    }
}
