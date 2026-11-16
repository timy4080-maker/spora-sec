//! C-03 adapter for the pinned stage-2 client core. TLS is always verified.
use serde::{Deserialize, de::DeserializeOwned};
use spora_core::*;
use std::{io::Read, net::IpAddr, path::Path, time::Duration};

pub struct HttpTransport {
    client: reqwest::blocking::Client,
    allow_tls: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoreState {
    Stored,
    Consumed,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreResponse {
    state: StoreState,
    receipt: StorageReceipt,
}

pub fn validate_endpoint(endpoint: &str, allow_tls: bool) -> Result<()> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| Error::InvalidArgument("endpoint"))?;
    let local = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if !((url.scheme() == "http" && local) || (url.scheme() == "https" && allow_tls))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::InvalidArgument(
            "use loopback HTTP or HTTPS with explicit lab CA",
        ));
    }
    Ok(())
}

impl HttpTransport {
    pub fn new(ca: Option<&Path>) -> Result<Self> {
        let mut builder = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .connect_timeout(Duration::from_secs(1));
        if let Some(ca) = ca {
            let cert = reqwest::Certificate::from_pem(&std::fs::read(ca)?)
                .map_err(|_| Error::InvalidArgument("lab CA"))?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
        }
        Ok(Self {
            client: builder.build().map_err(|_| Error::Transport)?,
            allow_tls: ca.is_some(),
        })
    }
    fn url(&self, endpoint: &str, path: &str) -> Result<String> {
        validate_endpoint(endpoint, self.allow_tls)?;
        Ok(format!("{}{path}", endpoint.trim_end_matches('/')))
    }
    fn checked(response: &mut reqwest::blocking::Response) -> Result<()> {
        if response
            .headers()
            .get("x-spora-test-only")
            .and_then(|x| x.to_str().ok())
            != Some(TEST_SUITE)
        {
            return Err(Error::TestProfileRequired);
        }
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status().as_u16();
        if status == 429 || status >= 500 {
            let mut body = Vec::new();
            response
                .take(65_537)
                .read_to_end(&mut body)
                .map_err(|_| Error::Transport)?;
            if body.len() > 65_536 {
                return Err(Error::Binding);
            }
            return Err(http_retry_error(status, &body));
        }
        Err(match response.status().as_u16() {
            401 | 403 => Error::Unauthorized,
            404 => Error::NotFound,
            409 => Error::Conflict,
            410 => Error::Expired,
            413 => Error::InvalidArgument("envelope size"),
            422 => Error::RetentionLimit,
            423 => Error::QueueSuspended,
            429 => Error::Quota,
            500..=599 => Error::Transport,
            _ => Error::InvalidArgument("HTTP request rejected"),
        })
    }
    fn decode<T: DeserializeOwned>(mut response: reqwest::blocking::Response) -> Result<T> {
        Self::checked(&mut response)?;
        let mut data = Vec::new();
        response
            .take(10_485_761)
            .read_to_end(&mut data)
            .map_err(|_| Error::Transport)?;
        if data.len() > 10_485_760 {
            return Err(Error::Binding);
        }
        serde_json::from_slice(&data).map_err(|_| Error::Binding)
    }
    pub fn service_id(&self, endpoint: &str) -> Result<String> {
        let response = self
            .client
            .get(self.url(endpoint, "/v1/capabilities")?)
            .send()
            .map_err(|_| Error::Transport)?;
        let value: serde_json::Value = Self::decode(response)?;
        if value["contract_version"] != "0.1.0" || value["max_envelope_bytes"] != MAX_ENVELOPE {
            return Err(Error::Binding);
        }
        value["service_id"]
            .as_str()
            .filter(|x| valid_id(x))
            .map(str::to_owned)
            .ok_or(Error::Binding)
    }
    pub fn provision(&self, endpoint: &str, token: &str, queue: &QueueCreate) -> Result<()> {
        let response = self
            .client
            .post(self.url(endpoint, "/v1/queues")?)
            .bearer_auth(token)
            .json(queue)
            .send()
            .map_err(|_| Error::Transport)?;
        let value: serde_json::Value = Self::decode(response)?;
        if value["queue_id"] != queue.queue_id || value["generation"] != queue.generation {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
impl Transport for HttpTransport {
    fn put(
        &self,
        route: &Route,
        delivery: &str,
        put: &MessagePut,
        _: i64,
    ) -> Result<StorageReceipt> {
        if !valid_id(&route.queue_id) || !valid_id(delivery) {
            return Err(Error::Binding);
        }
        let response = self
            .client
            .put(self.url(
                &route.endpoint,
                &format!("/v1/queues/{}/messages/{delivery}", route.queue_id),
            )?)
            .bearer_auth(&route.write_token)
            .json(put)
            .send()
            .map_err(|_| Error::Transport)?;
        let stored: StoreResponse = Self::decode(response)?;
        // Both states prove the historical acceptance only. Neither is a device receipt.
        match stored.state {
            StoreState::Stored | StoreState::Consumed => Ok(stored.receipt),
        }
    }
    fn fetch(&self, source: &Source, after: u64, limit: usize, _: i64) -> Result<MessagePage> {
        if !valid_id(&source.queue_id) {
            return Err(Error::Binding);
        }
        Self::decode(
            self.client
                .get(self.url(
                    &source.endpoint,
                    &format!("/v1/queues/{}/messages", source.queue_id),
                )?)
                .bearer_auth(&source.read_token)
                .query(&[
                    ("generation", source.generation.clone()),
                    ("after", after.to_string()),
                    ("limit", limit.to_string()),
                ])
                .send()
                .map_err(|_| Error::Transport)?,
        )
    }
    fn consume(&self, source: &Source, delivery: &str, _: i64) -> Result<()> {
        if !valid_id(&source.queue_id) || !valid_id(delivery) {
            return Err(Error::Binding);
        }
        let response = self
            .client
            .put(self.url(
                &source.endpoint,
                &format!(
                    "/v1/queues/{}/messages/{delivery}/consumption",
                    source.queue_id
                ),
            )?)
            .bearer_auth(&source.read_token)
            .json(&GenerationRequest {
                generation: source.generation.clone(),
            })
            .send()
            .map_err(|_| Error::Transport)?;
        let mut response = response;
        Self::checked(&mut response)?;
        if response.status().as_u16() != 204 {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
