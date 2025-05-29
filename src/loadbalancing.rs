use hyper::{Body, Client, Request, Response, Uri};
use hyper_rustls::HttpsConnector;
use hyper::body::to_bytes;
use thiserror::Error;
use hyper::Error as HyperError;

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("404 No found")]
    AllBackendsFailed,

    #[error(transparent)]
    Hyper(#[from] HyperError),
}

pub async fn forward_failover(
    req: Request<Body>,
    backends: &[String],
    client: &Client<HttpsConnector<hyper::client::HttpConnector>>,
) -> Result<Response<Body>, ForwardError> {

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = to_bytes(req.into_body()).await?;

    for backend in backends {
        let uri_backend: Uri = backend.parse().expect("Invalid backend URI");

        let mut parts = uri.clone().into_parts();
        parts.scheme = uri_backend.scheme().cloned();
        parts.authority = uri_backend.authority().cloned();
        parts.path_and_query = uri_backend.path_and_query().cloned();

        let full_uri = Uri::from_parts(parts).expect("Invalid full URI");

        let mut builder = Request::builder()
            .method(method.clone())
            .uri(full_uri);

        for (key, value) in headers.iter() {
            builder = builder.header(key, value);
        }

        let new_req = builder
            .body(Body::from(body_bytes.clone()))
            .expect("Error building request");

        match client.request(new_req).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                tracing::warn!("Failover: backend {} failed: {}", backend, e);
                continue;
            }
        }
    }

    Err(ForwardError::AllBackendsFailed)
}
