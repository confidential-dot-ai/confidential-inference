//! c8s evidence helpers for the CDS metadata provider: the evidence
//! connection, the mesh CA roots, and the discovery and allowlist checks.

use std::sync::Arc;

use crate::AttestationError;
use serde_json::Value;
use url::Url;

const MAX_PROTOCOL_DETAIL_CHARACTERS: usize = 200;

/// Build one safe detail string for an attestation error.
///
/// The string names the step that failed and the exact source line that
/// raised the error. It never carries evidence bytes, key material, a nonce,
/// or any response body: a caller reads it to learn *where* the check
/// stopped, never *what* it read. `sanitize_detail` keeps it to
/// printable ASCII and bounds its length.
fn step_detail(reason: &str, line: u32) -> String {
    sanitize_detail(&format!("{reason} (gateway attestation.rs:{line})"))
}

/// Raise `AttestationError::Invalid` with a detail that names the step.
macro_rules! attestation_invalid {
    ($($argument:tt)*) => {
        AttestationError::Invalid(step_detail(&format!($($argument)*), line!()))
    };
}

struct EvidenceResolver {
    evidence_host: String,
    connect_host: String,
}

/// # Errors
/// Return an error if the connection address cannot be resolved.
pub fn evidence_connection(
    builder: reqwest::ClientBuilder,
    url: &Url,
    connect_host: &str,
) -> Result<reqwest::ClientBuilder, String> {
    let connect_host = url::Host::parse(connect_host)
        .map_err(|_| "the c8s evidence connection host is invalid".to_owned())?;
    let connect_host = match connect_host {
        url::Host::Domain(name) => name,
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => address.to_string(),
    };
    Ok(builder.no_proxy().dns_resolver(Arc::new(EvidenceResolver {
        evidence_host: url.host_str().unwrap_or_default().to_owned(),
        connect_host,
    })))
}

impl reqwest::dns::Resolve for EvidenceResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = if name.as_str() == self.evidence_host {
            self.connect_host.clone()
        } else {
            name.as_str().to_owned()
        };
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let addresses: Vec<_> = addresses.collect();
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Keep printable ASCII only, and bound the length.
fn sanitize_detail(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                ' '
            }
        })
        .take(MAX_PROTOCOL_DETAIL_CHARACTERS)
        .collect()
}

/// Read the c8s mesh CA bundle when the pod carries one.
///
/// The `get-cert` init container writes it to `/etc/c8s/certs/ca.crt`; pods
/// under the c8s per-pod mesh have no such file. An absent file yields an
/// empty list: a `WebPKI` front door needs no extra root,
/// and the evidence client only ever ADDS these roots.
/// # Errors
/// Return an error if the optional CA file cannot be read or parsed.
pub fn mesh_ca_certificates() -> Result<Vec<reqwest::Certificate>, String> {
    let Ok(mesh_ca_pem) = std::fs::read("/etc/c8s/certs/ca.crt") else {
        return Ok(Vec::new());
    };
    let mut certificates = Vec::new();
    let mut rest: &[u8] = &mesh_ca_pem;
    while !rest.is_empty() {
        let (remaining, pem) = x509_parser::pem::parse_x509_pem(rest)
            .map_err(|_| "the c8s mesh CA bundle is invalid".to_owned())?;
        certificates.push(
            reqwest::Certificate::from_der(&pem.contents)
                .map_err(|_| "the c8s mesh CA certificate is invalid".to_owned())?,
        );
        rest = remaining;
    }
    if certificates.is_empty() {
        return Err("the c8s mesh CA bundle is empty".to_owned());
    }
    Ok(certificates)
}

/// # Errors
/// Return an error if the URL is not a valid HTTPS origin.
pub fn parse_evidence_base_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "the c8s evidence URL is invalid".to_owned())?;
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "" && url.path() != "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("the c8s evidence URL is unsafe".to_owned());
    }
    Ok(url)
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    #[tokio::test]
    async fn local_connection_keeps_public_tls_name_and_rejects_wrong_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let certificate = rcgen::generate_simple_self_signed(vec!["api.example.test".to_owned()])?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            certificate.cert.pem().into_bytes(),
            certificate.signing_key.serialize_pem().into_bytes(),
        )
        .await?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();
        let app = axum::Router::new().route(
            "/v1/discovery",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get("host")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            }),
        );
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        });
        let trust = reqwest::Certificate::from_der(certificate.cert.der())?;
        let url = Url::parse(&format!(
            "https://api.example.test:{}/v1/discovery",
            address.port()
        ))?;
        let client = evidence_connection(
            reqwest::Client::builder().add_root_certificate(trust.clone()),
            &url,
            "127.0.0.1",
        )?
        .build()?;
        let response = client.get(url.clone()).send().await?;
        assert_eq!(
            response.text().await?,
            format!("api.example.test:{}", address.port())
        );

        let wrong = Url::parse(&format!(
            "https://wrong.example.test:{}/v1/discovery",
            address.port()
        ))?;
        let client = evidence_connection(
            reqwest::Client::builder().add_root_certificate(trust),
            &wrong,
            "127.0.0.1",
        )?
        .build()?;
        assert!(
            client.get(wrong).send().await.is_err(),
            "wrong TLS name must fail"
        );
        shutdown.shutdown();
        task.await??;
        Ok(())
    }
}

pub(crate) fn validate_discovery(value: &Value) -> Result<(), AttestationError> {
    if value.get("version").and_then(Value::as_str) != Some("v1")
        || value.get("generated_at").and_then(Value::as_str).is_none()
        || value
            .pointer("/public_tls/hostname")
            .and_then(Value::as_str)
            .is_none()
        || !matches!(
            value.pointer("/public_tls/mode").and_then(Value::as_str),
            Some("webpki" | "cds" | "acme" | "tee-webpki")
        )
        || value
            .pointer("/cds_tls/certificate_pem")
            .and_then(Value::as_str)
            .is_none()
        || value
            .pointer("/cds_tls/certificate_sha256")
            .and_then(Value::as_str)
            .is_none()
        || value
            .pointer("/attestation/platform")
            .and_then(Value::as_str)
            .is_none()
        || !value
            .pointer("/attestation/evidence")
            .is_some_and(Value::is_object)
    {
        return Err(attestation_invalid!(
            "the c8s discovery document failed its shape check"
        ));
    }
    Ok(())
}

pub(crate) fn validate_allowlist(value: &Value, bytes: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if value.get("schema").and_then(Value::as_str) != Some("c8s.allowlist/v1")
        || !value.get("workloads").is_some_and(Value::is_object)
    {
        return Err(attestation_invalid!(
            "the c8s allowlist document failed its shape check"
        ));
    }
    // c8s serves the allowlist in two shapes. The branch this gateway was
    // built against (c8s 079aeb48, goal/production-attestation) serves a
    // top-level "digests" floor map. c8s main (#551) folded the floor
    // digests into per-workload entries and serves no "digests" key. Accept
    // either: a present "digests" must still be an object, and an absent one
    // is only valid when every container in every workload entry pins an
    // image digest, which is the floor data at its main-line location. CDS
    // enforces the per-container digest at ingest in both versions, so the
    // folded check rejects only documents no real CDS would serve.
    match value.get("digests") {
        Some(digests) => {
            if !digests.is_object() {
                return Err(attestation_invalid!(
                    "the c8s allowlist document failed its shape check"
                ));
            }
        }
        None => validate_folded_workload_digests(value)?,
    }
    // CDS returns the exact bytes from c8s Allowlist.Canonical(). Do not
    // re-serialize the parsed object here. serde_json uses a different object
    // key order, which changes the policy digest. A source-controlled
    // allowlist may contain one final newline; CDS does not return it.
    let canonical = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if canonical.is_empty()
        || canonical.first() != Some(&b'{')
        || canonical.last() != Some(&b'}')
        || canonical.contains(&b'\n')
        || canonical.contains(&b'\r')
    {
        return Err(attestation_invalid!(
            "the c8s allowlist document failed its shape check"
        ));
    }
    Ok(canonical.to_vec())
}

/// Require the folded digest floor of a c8s main-line allowlist: after c8s
/// #551 the document carries no top-level "digests" map, so every image
/// digest the floor admitted must instead appear as a digest pin on a
/// container in a workload entry. A container list that is null or absent
/// carries no containers to check; Go serves an empty slice as either.
fn validate_folded_workload_digests(value: &Value) -> Result<(), AttestationError> {
    let workloads =
        value
            .get("workloads")
            .and_then(Value::as_object)
            .ok_or(attestation_invalid!(
                "the folded allowlist workload digests failed their shape check"
            ))?;
    for entry in workloads.values() {
        let entry = entry.as_object().ok_or(attestation_invalid!(
            "the folded allowlist workload digests failed their shape check"
        ))?;
        for key in ["initContainers", "containers"] {
            let Some(list) = entry.get(key) else {
                continue;
            };
            let Some(containers) = list.as_array() else {
                if list.is_null() {
                    continue;
                }
                return Err(attestation_invalid!(
                    "the folded allowlist workload digests failed their shape check"
                ));
            };
            for container in containers {
                let digest =
                    container
                        .get("digest")
                        .and_then(Value::as_str)
                        .ok_or(attestation_invalid!(
                            "the folded allowlist workload digests failed their shape check"
                        ))?;
                if !valid_sha256_digest(digest) {
                    return Err(attestation_invalid!(
                        "the folded allowlist workload digests failed their shape check"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keeps_the_exact_c8s_allowlist_byte_order() {
        let source = include_bytes!("../../../c8s/allowlists/staging.json");
        let Ok(value) = serde_json::from_slice::<Value>(source) else {
            panic!("the public allowlist test fixture must contain JSON");
        };
        let Ok(canonical) = validate_allowlist(&value, source) else {
            panic!("the public allowlist test fixture must use canonical c8s bytes");
        };
        assert_eq!(
            canonical.as_slice(),
            source.strip_suffix(b"\n").unwrap_or(source)
        );

        let Ok(rust_reserialized) = serde_json::to_vec(&value) else {
            panic!("the parsed JSON test fixture must serialize");
        };
        assert_ne!(
            canonical, rust_reserialized,
            "the regression fixture must expose the key-order difference"
        );
    }

    /// The c8s main-line (#551) document shape: no top-level "digests" map.
    /// The first entry is a folded floor digest (unconstrained argv); the
    /// second pins an exact launch.
    fn main_line_allowlist() -> Value {
        let floor_digest = format!("sha256:{}", "a".repeat(64));
        let pinned_digest = format!("sha256:{}", "b".repeat(64));
        json!({
            "schema": "c8s.allowlist/v1",
            "workloads": {
                "cds-3f2a9c8b1e2f": {
                    "label": format!("ghcr.io/confidential-dot-ai/cds@{floor_digest}"),
                    "initContainers": [],
                    "containers": [{
                        "digest": floor_digest,
                        "image": format!("ghcr.io/confidential-dot-ai/cds@{floor_digest}"),
                        "command": {"policy": "any"},
                        "args": {"policy": "any"},
                    }],
                },
                "vllm-llama": {
                    "label": "docker.io/vllm/vllm-openai:v0.6.3",
                    "initContainers": [],
                    "containers": [{
                        "digest": pinned_digest,
                        "image": format!("docker.io/vllm/vllm-openai@{pinned_digest}"),
                        "command": {"policy": "exact", "argv": ["python3"]},
                        "args": {"policy": "exact", "argv": ["-m", "vllm.entrypoints.openai.api_server"]},
                    }],
                },
            }
        })
    }

    fn canonical_bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn keeps_accepting_the_branch_allowlist_shape() {
        let value = json!({"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}});
        let bytes = canonical_bytes(&value);
        let Ok(canonical) = validate_allowlist(&value, &bytes) else {
            panic!("the branch allowlist shape must stay accepted");
        };
        assert_eq!(canonical, bytes);
    }

    #[test]
    fn rejects_a_non_object_digests_field() {
        for digests in [json!([]), json!(null), json!("floor")] {
            let value = json!({"schema": "c8s.allowlist/v1", "digests": digests, "workloads": {}});
            assert!(validate_allowlist(&value, &canonical_bytes(&value)).is_err());
        }
    }

    #[test]
    fn accepts_the_c8s_main_line_allowlist_shape() {
        let value = main_line_allowlist();
        let bytes = canonical_bytes(&value);
        let Ok(canonical) = validate_allowlist(&value, &bytes) else {
            panic!("the c8s main-line allowlist shape must be accepted");
        };
        assert_eq!(canonical, bytes);

        // Go serves an empty container slice as either [] or null.
        let mut nulled = main_line_allowlist();
        nulled["workloads"]["vllm-llama"]["initContainers"] = json!(null);
        let bytes = canonical_bytes(&nulled);
        assert!(validate_allowlist(&nulled, &bytes).is_ok());
    }

    #[test]
    fn rejects_a_main_line_container_without_a_digest_pin() {
        let mut missing = main_line_allowlist();
        missing["workloads"]["vllm-llama"]["containers"][0]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("digest");
        assert!(validate_allowlist(&missing, &canonical_bytes(&missing)).is_err());

        let mut malformed = main_line_allowlist();
        malformed["workloads"]["cds-3f2a9c8b1e2f"]["containers"][0]["digest"] =
            json!("sha256:not-hex");
        assert!(validate_allowlist(&malformed, &canonical_bytes(&malformed)).is_err());
    }

    #[test]
    fn rejects_a_main_line_container_list_that_is_not_an_array() {
        let mut value = main_line_allowlist();
        value["workloads"]["vllm-llama"]["containers"] = json!({"digest": "sha256:abc"});
        assert!(validate_allowlist(&value, &canonical_bytes(&value)).is_err());
    }

    #[test]
    fn rejects_whitespace_outside_the_canonical_document() {
        let source = include_bytes!("../../../c8s/allowlists/staging.json");
        let Ok(value) = serde_json::from_slice::<Value>(source) else {
            panic!("the public allowlist test fixture must contain JSON");
        };
        let mut leading = b" ".to_vec();
        leading.extend_from_slice(source);
        assert!(validate_allowlist(&value, &leading).is_err());

        let mut two_newlines = source.to_vec();
        two_newlines.extend_from_slice(b"\n");
        assert!(validate_allowlist(&value, &two_newlines).is_err());
    }
}
