use thiserror::Error;
use hyper::Error as HyperError;
use hyper::body::to_bytes;
use hyper::{Body, Client, Request, Response, Uri};
use tokio::time::{timeout, Duration};
use hyper::client::connect::Connect;


#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("503 Service Unavailable")]
    AllBackendsFailed,

    #[error(transparent)]
    Hyper(#[from] HyperError),
}

pub async fn forward_failover<C>(
    req: Request<Body>,
    backends: &[String],
    client: &Client<C>,
) -> Result<Response<Body>, ForwardError>
where
    C: Connect + Clone + Send + Sync + 'static,
{
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

        let response_result = timeout(Duration::from_millis(500), client.request(new_req)).await;

        match response_result {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => {
                tracing::warn!("Failover: backend {} failed: {}", backend, e);
                continue;
            }
            Err(_) => {
                tracing::warn!("Failover: backend {} timed out", backend);
                continue;
            }
        }
    }

    Err(ForwardError::AllBackendsFailed)
}
