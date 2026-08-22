//! Security primitives for Phase 4 HTTPS `attach_headers` egress handling.
//!
//! This crate intentionally does not advertise an end-to-end transparent proxy.
//! It provides the independently testable pieces that the egress data plane must
//! compose: canonical rule selection, secret-safe validation, a bounded HTTP/1.1
//! request-head transformer, and per-Box TLS interception material.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use http::{HeaderName, HeaderValue};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroize;

/// Default maximum accepted HTTP request-head size.
pub const DEFAULT_MAX_HEAD_BYTES: usize = 64 * 1024;
/// Default maximum number of request headers.
pub const DEFAULT_MAX_HEADERS: usize = 128;
/// Maximum value size for one configured injected header.
pub const MAX_SECRET_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Maximum total injected header value bytes for one host rule.
pub const MAX_RULE_SECRET_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachHeadersError {
    InvalidHostPattern,
    InvalidHost,
    DuplicatePattern,
    DuplicateHeader,
    InvalidHeaderName,
    ForbiddenHeader,
    InvalidHeaderValue,
    HeaderValueTooLarge,
    RuleValuesTooLarge,
    RequestHeadTooLarge,
    TooManyHeaders,
    IncompleteRequestHead,
    MalformedRequest,
    ObsoleteLineFolding,
    AmbiguousMessageFraming,
    MissingOrDuplicateHost,
    HostMismatch,
    EmptyAllowedHostnames,
    HostNotAllowed,
    UnsupportedUpgrade,
    Certificate(String),
    Tls(String),
    Io(String),
}

impl fmt::Display for AttachHeadersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidHostPattern => "invalid attach_headers host pattern",
            Self::InvalidHost => "invalid HTTP host",
            Self::DuplicatePattern => "duplicate attach_headers host pattern",
            Self::DuplicateHeader => "duplicate attach_headers header name",
            Self::InvalidHeaderName => "invalid attach_headers header name",
            Self::ForbiddenHeader => "forbidden attach_headers header name",
            Self::InvalidHeaderValue => "invalid attach_headers header value",
            Self::HeaderValueTooLarge => "attach_headers value exceeds the per-header limit",
            Self::RuleValuesTooLarge => "attach_headers rule exceeds the aggregate value limit",
            Self::RequestHeadTooLarge => "HTTP request head exceeds the configured limit",
            Self::TooManyHeaders => "HTTP request contains too many headers",
            Self::IncompleteRequestHead => "incomplete HTTP request head",
            Self::MalformedRequest => "malformed HTTP/1.1 request",
            Self::ObsoleteLineFolding => "obsolete folded HTTP headers are forbidden",
            Self::AmbiguousMessageFraming => "ambiguous HTTP request framing is forbidden",
            Self::MissingOrDuplicateHost => "HTTP/1.1 request must contain exactly one Host header",
            Self::HostMismatch => "request Host does not match the authenticated TLS server name",
            Self::EmptyAllowedHostnames => "allowed hostname set must not be empty",
            Self::HostNotAllowed => "request hostname is not allowed for this upstream address",
            Self::UnsupportedUpgrade => "HTTP upgrade and CONNECT are not supported",
            Self::Certificate(message) | Self::Tls(message) | Self::Io(message) => message,
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AttachHeadersError {}

/// A secret header value. Formatting is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretHeaderValue(Vec<u8>);

impl SecretHeaderValue {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, AttachHeadersError> {
        let value = value.into();
        if value.len() > MAX_SECRET_HEADER_VALUE_BYTES {
            return Err(AttachHeadersError::HeaderValueTooLarge);
        }
        HeaderValue::from_bytes(&value).map_err(|_| AttachHeadersError::InvalidHeaderValue)?;
        Ok(Self(value))
    }

    /// Exposes the value only at the final request serialization boundary.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretHeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretHeaderValue([REDACTED])")
    }
}

impl fmt::Display for SecretHeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum HostPatternKind {
    Exact(String),
    Subdomains(String),
}

/// A host pattern whose canonicalization invariant can only be established by `parse`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostPattern(HostPatternKind);

impl HostPattern {
    pub fn parse(input: &str) -> Result<Self, AttachHeadersError> {
        if input.trim() != input || input.is_empty() {
            return Err(AttachHeadersError::InvalidHostPattern);
        }
        if let Some(suffix) = input.strip_prefix("*.") {
            let suffix =
                canonical_dns_name(suffix).map_err(|_| AttachHeadersError::InvalidHostPattern)?;
            if IpAddr::from_str(&suffix).is_ok() {
                return Err(AttachHeadersError::InvalidHostPattern);
            }
            return Ok(Self(HostPatternKind::Subdomains(suffix)));
        }
        if input.contains('*') {
            return Err(AttachHeadersError::InvalidHostPattern);
        }
        Ok(Self(HostPatternKind::Exact(
            canonical_host(input).map_err(|_| AttachHeadersError::InvalidHostPattern)?,
        )))
    }

    pub fn canonical(&self) -> String {
        match &self.0 {
            HostPatternKind::Exact(host) => host.clone(),
            HostPatternKind::Subdomains(suffix) => format!("*.{suffix}"),
        }
    }

    fn matches(&self, host: &str) -> bool {
        match &self.0 {
            HostPatternKind::Exact(exact) => host == exact,
            HostPatternKind::Subdomains(suffix) => {
                host.len() > suffix.len()
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
        }
    }

    fn specificity(&self) -> (u8, usize) {
        match &self.0 {
            HostPatternKind::Exact(host) => (1, host.len()),
            HostPatternKind::Subdomains(suffix) => (0, suffix.len()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttachHeaderRule {
    pattern: HostPattern,
    headers: Vec<(HeaderName, SecretHeaderValue)>,
}

impl AttachHeaderRule {
    pub fn new<I, N>(pattern: HostPattern, headers: I) -> Result<Self, AttachHeadersError>
    where
        I: IntoIterator<Item = (N, SecretHeaderValue)>,
        N: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut total = 0usize;
        let mut validated = Vec::new();
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_ref().as_bytes())
                .map_err(|_| AttachHeadersError::InvalidHeaderName)?;
            if is_forbidden_injected_header(&name) {
                return Err(AttachHeadersError::ForbiddenHeader);
            }
            if !seen.insert(name.clone()) {
                return Err(AttachHeadersError::DuplicateHeader);
            }
            total = total.saturating_add(value.expose_secret().len());
            if total > MAX_RULE_SECRET_BYTES {
                return Err(AttachHeadersError::RuleValuesTooLarge);
            }
            validated.push((name, value));
        }
        Ok(Self {
            pattern,
            headers: validated,
        })
    }

    pub fn pattern(&self) -> &HostPattern {
        &self.pattern
    }
}

#[derive(Clone, Debug, Default)]
pub struct AttachHeaderRules {
    rules: Vec<AttachHeaderRule>,
}

impl AttachHeaderRules {
    pub fn new(rules: Vec<AttachHeaderRule>) -> Result<Self, AttachHeadersError> {
        let mut patterns = HashSet::new();
        for rule in &rules {
            if !patterns.insert(rule.pattern.canonical()) {
                return Err(AttachHeadersError::DuplicatePattern);
            }
        }
        Ok(Self { rules })
    }

    pub fn matching_rule(
        &self,
        host: &str,
    ) -> Result<Option<&AttachHeaderRule>, AttachHeadersError> {
        let host = canonical_host(host)?;
        Ok(self
            .rules
            .iter()
            .filter(|rule| rule.pattern.matches(&host))
            .max_by_key(|rule| rule.pattern.specificity()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RequestHeadLimits {
    pub max_bytes: usize,
    pub max_headers: usize,
}

impl Default for RequestHeadLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_HEAD_BYTES,
            max_headers: DEFAULT_MAX_HEADERS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformedRequestHead {
    pub bytes: Vec<u8>,
    pub consumed: usize,
    pub matched_pattern: Option<String>,
}

/// Incrementally buffers and transforms exactly one HTTP/1.1 request head.
///
/// Any bytes after the terminating CRLF are left unconsumed. The egress bridge
/// owns body framing and must create a fresh transformer for the next request.
pub struct Http1RequestHeadTransformer<'a> {
    rules: &'a AttachHeaderRules,
    expected_tls_server_name: Option<String>,
    limits: RequestHeadLimits,
    buffer: Vec<u8>,
}

impl<'a> Http1RequestHeadTransformer<'a> {
    pub fn new(
        rules: &'a AttachHeaderRules,
        expected_tls_server_name: Option<&str>,
        limits: RequestHeadLimits,
    ) -> Result<Self, AttachHeadersError> {
        let expected_tls_server_name = expected_tls_server_name.map(canonical_host).transpose()?;
        Ok(Self {
            rules,
            expected_tls_server_name,
            limits,
            buffer: Vec::new(),
        })
    }

    pub fn push(
        &mut self,
        chunk: &[u8],
    ) -> Result<Option<TransformedRequestHead>, AttachHeadersError> {
        if self.buffer.len().saturating_add(chunk.len()) > self.limits.max_bytes {
            return Err(AttachHeadersError::RequestHeadTooLarge);
        }
        self.buffer.extend_from_slice(chunk);
        let Some(head_end) = find_request_head_end(&self.buffer) else {
            return Ok(None);
        };
        let head = &self.buffer[..head_end];
        let transformed = transform_complete_head(
            head,
            self.rules,
            self.expected_tls_server_name.as_deref(),
            self.limits,
        )?;
        Ok(Some(TransformedRequestHead {
            bytes: transformed.0,
            consumed: head_end,
            matched_pattern: transformed.1,
        }))
    }
}

fn transform_complete_head(
    head: &[u8],
    rules: &AttachHeaderRules,
    expected_tls_server_name: Option<&str>,
    limits: RequestHeadLimits,
) -> Result<(Vec<u8>, Option<String>), AttachHeadersError> {
    validate_crlf_and_folding(head)?;
    let mut headers = vec![httparse::EMPTY_HEADER; limits.max_headers];
    let mut request = httparse::Request::new(&mut headers);
    let status = request.parse(head).map_err(map_httparse_error)?;
    if !status.is_complete() || request.version != Some(1) {
        return Err(AttachHeadersError::MalformedRequest);
    }
    let method = request.method.ok_or(AttachHeadersError::MalformedRequest)?;
    let path = request.path.ok_or(AttachHeadersError::MalformedRequest)?;

    let host_headers: Vec<_> = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .collect();
    if host_headers.len() != 1 {
        return Err(AttachHeadersError::MissingOrDuplicateHost);
    }
    let host_text =
        std::str::from_utf8(host_headers[0].value).map_err(|_| AttachHeadersError::InvalidHost)?;
    if host_text.trim() != host_text {
        return Err(AttachHeadersError::InvalidHost);
    }
    let host = canonical_authority_host(host_text)?;
    if let Some(expected) = expected_tls_server_name
        && host != expected
    {
        return Err(AttachHeadersError::HostMismatch);
    }
    validate_request_framing(request.headers)?;

    let rule = rules.matching_rule(&host)?;
    let injected_names: HashSet<&HeaderName> = rule
        .map(|rule| rule.headers.iter().map(|(name, _)| name).collect())
        .unwrap_or_default();

    let mut result = Vec::with_capacity(head.len() + 256);
    result.extend_from_slice(method.as_bytes());
    result.push(b' ');
    result.extend_from_slice(path.as_bytes());
    result.extend_from_slice(b" HTTP/1.1\r\n");
    for header in request.headers.iter() {
        let parsed_name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| AttachHeadersError::MalformedRequest)?;
        if injected_names.contains(&parsed_name) {
            continue;
        }
        result.extend_from_slice(header.name.as_bytes());
        result.extend_from_slice(b": ");
        result.extend_from_slice(header.value);
        result.extend_from_slice(b"\r\n");
    }
    if let Some(rule) = rule {
        for (name, value) in &rule.headers {
            result.extend_from_slice(name.as_str().as_bytes());
            result.extend_from_slice(b": ");
            result.extend_from_slice(value.expose_secret());
            result.extend_from_slice(b"\r\n");
        }
    }
    result.extend_from_slice(b"\r\n");
    Ok((result, rule.map(|rule| rule.pattern.canonical())))
}

fn validate_request_framing(headers: &[httparse::Header<'_>]) -> Result<(), AttachHeadersError> {
    let content_lengths: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .collect();
    let transfer_encodings: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
        .collect();
    if content_lengths.len() > 1
        || transfer_encodings.len() > 1
        || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
    {
        return Err(AttachHeadersError::AmbiguousMessageFraming);
    }
    if let Some(header) = content_lengths.first() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| AttachHeadersError::AmbiguousMessageFraming)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AttachHeadersError::AmbiguousMessageFraming);
        }
    }
    if let Some(header) = transfer_encodings.first() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| AttachHeadersError::AmbiguousMessageFraming)?;
        if !value.trim().eq_ignore_ascii_case("chunked") {
            return Err(AttachHeadersError::AmbiguousMessageFraming);
        }
    }
    Ok(())
}

fn validate_crlf_and_folding(head: &[u8]) -> Result<(), AttachHeadersError> {
    if !head.ends_with(b"\r\n\r\n") {
        return Err(AttachHeadersError::IncompleteRequestHead);
    }
    for byte_index in 0..head.len() {
        if head[byte_index] == b'\n' && (byte_index == 0 || head[byte_index - 1] != b'\r') {
            return Err(AttachHeadersError::MalformedRequest);
        }
        if head[byte_index] == b'\r'
            && (byte_index + 1 >= head.len() || head[byte_index + 1] != b'\n')
        {
            return Err(AttachHeadersError::MalformedRequest);
        }
    }
    for line in head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err(AttachHeadersError::ObsoleteLineFolding);
        }
    }
    Ok(())
}

fn find_request_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn map_httparse_error(error: httparse::Error) -> AttachHeadersError {
    if error == httparse::Error::TooManyHeaders {
        AttachHeadersError::TooManyHeaders
    } else {
        AttachHeadersError::MalformedRequest
    }
}

fn is_forbidden_injected_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

fn canonical_dns_name(input: &str) -> Result<String, AttachHeadersError> {
    if input.is_empty() || input.len() > 253 || input.ends_with('.') {
        return Err(AttachHeadersError::InvalidHost);
    }
    let ascii = idna::domain_to_ascii_strict(input).map_err(|_| AttachHeadersError::InvalidHost)?;
    let ascii = ascii.to_ascii_lowercase();
    if ascii.is_empty()
        || ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err(AttachHeadersError::InvalidHost);
    }
    Ok(ascii)
}

fn canonical_host(input: &str) -> Result<String, AttachHeadersError> {
    if let Ok(ip) = IpAddr::from_str(input) {
        return Ok(ip.to_string());
    }
    canonical_dns_name(input)
}

fn canonical_authority_host(input: &str) -> Result<String, AttachHeadersError> {
    if let Some(bracketed) = input.strip_prefix('[') {
        let closing = bracketed.find(']').ok_or(AttachHeadersError::InvalidHost)?;
        let ip = &bracketed[..closing];
        let rest = &bracketed[closing + 1..];
        if !rest.is_empty() && (!rest.starts_with(':') || rest[1..].parse::<u16>().is_err()) {
            return Err(AttachHeadersError::InvalidHost);
        }
        return IpAddr::from_str(ip)
            .map(|ip| ip.to_string())
            .map_err(|_| AttachHeadersError::InvalidHost);
    }
    let (host, port) = match input.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(port)),
        _ => (input, None),
    };
    if let Some(port) = port {
        port.parse::<u16>()
            .map_err(|_| AttachHeadersError::InvalidHost)?;
    }
    canonical_host(host)
}

/// A non-empty, canonical set of DNS hostnames already authorized by the
/// caller for one numeric upstream address. Construction never performs DNS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedHostnames(HashSet<String>);

impl AllowedHostnames {
    pub fn new<I, S>(hostnames: I) -> Result<Self, AttachHeadersError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut canonical = HashSet::new();
        for hostname in hostnames {
            canonical.insert(canonical_dns_name(hostname.as_ref())?);
        }
        if canonical.is_empty() {
            return Err(AttachHeadersError::EmptyAllowedHostnames);
        }
        Ok(Self(canonical))
    }

    pub fn contains(&self, hostname: &str) -> Result<bool, AttachHeadersError> {
        Ok(self.0.contains(&canonical_dns_name(hostname)?))
    }

    fn require_allowed(&self, hostname: &str) -> Result<String, AttachHeadersError> {
        let hostname = canonical_dns_name(hostname)?;
        if !self.0.contains(&hostname) {
            return Err(AttachHeadersError::HostNotAllowed);
        }
        Ok(hostname)
    }
}

/// Persistable PKCS#8 private-key material whose formatting is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretPrivateKeyDer(Vec<u8>);

impl SecretPrivateKeyDer {
    pub fn new(bytes: Vec<u8>) -> Result<Self, AttachHeadersError> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(AttachHeadersError::Certificate(
                "invalid private key DER size".to_owned(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Exposes PKCS#8 bytes only at encrypted persistence/import boundaries.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretPrivateKeyDer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPrivateKeyDer([REDACTED])")
    }
}

impl fmt::Display for SecretPrivateKeyDer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretPrivateKeyDer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A generated or restored CA dedicated to one Box. Private key material is never printable.
pub struct PerBoxCertificateAuthority {
    box_id: String,
    certificate: CertificateDer<'static>,
    key_pair: KeyPair,
}

impl fmt::Debug for PerBoxCertificateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PerBoxCertificateAuthority")
            .field("box_id", &self.box_id)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl PerBoxCertificateAuthority {
    pub fn generate(box_id: impl Into<String>) -> Result<Self, AttachHeadersError> {
        let box_id = box_id.into();
        if box_id.is_empty() || box_id.len() > 128 {
            return Err(AttachHeadersError::Certificate(
                "invalid Box identifier for certificate authority".to_owned(),
            ));
        }
        let key_pair = KeyPair::generate().map_err(certificate_error)?;
        let mut params = CertificateParams::default();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, format!("boxd Box {box_id} egress CA"));
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let certificate = params
            .self_signed(&key_pair)
            .map_err(certificate_error)?
            .der()
            .clone();
        Ok(Self {
            box_id,
            certificate,
            key_pair,
        })
    }

    /// Restores a CA after restart and fails closed unless the certificate is a
    /// currently valid self-signed CA, permits certificate signing, and matches
    /// the supplied PKCS#8 private key.
    pub fn from_der(
        box_id: impl Into<String>,
        certificate_der: Vec<u8>,
        private_key_der: SecretPrivateKeyDer,
    ) -> Result<Self, AttachHeadersError> {
        let box_id = validate_box_id(box_id.into())?;
        let certificate = CertificateDer::from(certificate_der);
        let key_pair =
            KeyPair::try_from(private_key_der.expose_secret()).map_err(certificate_error)?;
        validate_imported_ca(&certificate, &key_pair)?;
        // Prove rcgen can reconstruct all issuer metadata before accepting the secret.
        Issuer::from_ca_cert_der(&certificate, &key_pair).map_err(certificate_error)?;
        Ok(Self {
            box_id,
            certificate,
            key_pair,
        })
    }

    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    pub fn certificate_pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.certificate.as_ref()))
    }

    pub fn private_key_der(&self) -> SecretPrivateKeyDer {
        // A generated rcgen key is always valid PKCS#8 and smaller than the cap.
        SecretPrivateKeyDer::new(self.key_pair.serialize_der())
            .expect("generated CA private key must satisfy the persistence boundary")
    }

    fn certified_key(&self, server_name: &str) -> Result<Arc<CertifiedKey>, AttachHeadersError> {
        let server_name = canonical_dns_name(server_name)?;
        let leaf_key = KeyPair::generate().map_err(certificate_error)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(certificate_error)?;
        params.subject_alt_names = vec![SanType::DnsName(
            server_name.try_into().map_err(certificate_error)?,
        )];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let issuer = Issuer::from_ca_cert_der(&self.certificate, &self.key_pair)
            .map_err(certificate_error)?;
        let leaf = params
            .signed_by(&leaf_key, &issuer)
            .map_err(certificate_error)?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = any_supported_type(&private_key)
            .map_err(|error| AttachHeadersError::Tls(format!("unsupported leaf key: {error}")))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![leaf.der().clone(), self.certificate.clone()],
            signing_key,
        )))
    }
}

fn validate_box_id(box_id: String) -> Result<String, AttachHeadersError> {
    if box_id.is_empty() || box_id.len() > 128 {
        return Err(AttachHeadersError::Certificate(
            "invalid Box identifier for certificate authority".to_owned(),
        ));
    }
    Ok(box_id)
}

fn validate_imported_ca(
    certificate_der: &CertificateDer<'_>,
    key_pair: &KeyPair,
) -> Result<(), AttachHeadersError> {
    let (remaining, certificate) = X509Certificate::from_der(certificate_der.as_ref())
        .map_err(|_| AttachHeadersError::Certificate("invalid CA certificate DER".to_owned()))?;
    if !remaining.is_empty()
        || !certificate.tbs_certificate.is_ca()
        || certificate.tbs_certificate.subject != certificate.tbs_certificate.issuer
        || !certificate.validity().is_valid()
    {
        return Err(AttachHeadersError::Certificate(
            "certificate is not a valid self-signed CA".to_owned(),
        ));
    }
    let key_usage = certificate
        .tbs_certificate
        .key_usage()
        .map_err(|_| AttachHeadersError::Certificate("invalid CA key usage".to_owned()))?
        .ok_or_else(|| AttachHeadersError::Certificate("CA key usage is missing".to_owned()))?;
    if !key_usage.value.key_cert_sign() {
        return Err(AttachHeadersError::Certificate(
            "certificate does not permit certificate signing".to_owned(),
        ));
    }
    if certificate.public_key().subject_public_key.data.as_ref() != key_pair.public_key_raw() {
        return Err(AttachHeadersError::Certificate(
            "CA certificate and private key do not match".to_owned(),
        ));
    }
    certificate.verify_signature(None).map_err(|_| {
        AttachHeadersError::Certificate("CA self-signature verification failed".to_owned())
    })?;
    Ok(())
}

fn certificate_error(error: impl fmt::Display) -> AttachHeadersError {
    AttachHeadersError::Certificate(format!("certificate operation failed: {error}"))
}

pub struct DynamicServerCertificateResolver {
    authority: Arc<PerBoxCertificateAuthority>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl fmt::Debug for DynamicServerCertificateResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicServerCertificateResolver")
            .field("authority", &self.authority)
            .field("cache", &"[certificate cache]")
            .finish()
    }
}

impl DynamicServerCertificateResolver {
    pub fn new(authority: Arc<PerBoxCertificateAuthority>) -> Self {
        Self {
            authority,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn certificate_for_server_name(
        &self,
        server_name: &str,
    ) -> Result<Arc<CertifiedKey>, AttachHeadersError> {
        let server_name = canonical_dns_name(server_name)?;
        let mut cache = self.cache.lock().map_err(|_| {
            AttachHeadersError::Tls("dynamic certificate cache lock poisoned".to_owned())
        })?;
        if let Some(key) = cache.get(&server_name) {
            return Ok(Arc::clone(key));
        }
        let key = self.authority.certified_key(&server_name)?;
        cache.insert(server_name, Arc::clone(&key));
        Ok(key)
    }
}

impl ResolvesServerCert for DynamicServerCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.certificate_for_server_name(client_hello.server_name()?)
            .ok()
    }
}

/// Builds a TLS server config for guest-facing MITM connections.
///
/// ALPN is deliberately restricted to HTTP/1.1 because the request transformer
/// does not understand HTTP/2 framing.
pub fn mitm_server_config(resolver: Arc<DynamicServerCertificateResolver>) -> Arc<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports rustls safe protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Builds an upstream TLS config backed by public WebPKI roots.
pub fn upstream_client_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    upstream_client_config_with_roots(roots)
}

/// Builds an upstream TLS config with caller-supplied roots (useful for private PKI/tests).
/// Standard rustls WebPKI verification remains enabled; no dangerous verifier is installed.
pub fn upstream_client_config_with_roots(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports rustls safe protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// A bounded TLS MITM bridge for one HTTP/1.1 request/response exchange.
///
/// The caller owns target policy evaluation and TCP dialing, including the
/// post-DNS CIDR decision. This bridge binds guest SNI and HTTP `Host` to
/// `server_name`, validates upstream TLS with rustls WebPKI, injects the most
/// specific rule, streams a `Content-Length` body, and closes the upstream
/// connection after the response.
///
/// Chunked request bodies, upgrades, and multiple requests per TLS connection
/// are intentionally unsupported here. The data plane must not advertise full
/// HTTPS `attach_headers` until those cases and guest CA lifecycle are wired.
pub struct Http1TlsMitmProxy {
    server_config: Arc<ServerConfig>,
    upstream_config: Arc<ClientConfig>,
    rules: Arc<AttachHeaderRules>,
    limits: RequestHeadLimits,
}

impl fmt::Debug for Http1TlsMitmProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1TlsMitmProxy")
            .field("rules", &self.rules)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Http1TlsMitmProxy {
    pub fn new(
        server_config: Arc<ServerConfig>,
        upstream_config: Arc<ClientConfig>,
        rules: Arc<AttachHeaderRules>,
        limits: RequestHeadLimits,
    ) -> Self {
        Self {
            server_config,
            upstream_config,
            rules,
            limits,
        }
    }

    pub async fn proxy_single_http1_tls_connection<Guest, Upstream>(
        &self,
        guest_transport: Guest,
        upstream_transport: Upstream,
        server_name: &str,
    ) -> Result<(), AttachHeadersError>
    where
        Guest: AsyncRead + AsyncWrite + Unpin + Send,
        Upstream: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let allowed_hostnames = AllowedHostnames::new([server_name])?;
        self.proxy_single_http1_tls_connection_for_allowed_hostnames(
            guest_transport,
            upstream_transport,
            &allowed_hostnames,
        )
        .await
    }

    /// Proxies one TLS exchange using the actual guest ClientHello SNI.
    ///
    /// `allowed_hostnames` must be the caller's still-valid policy result for
    /// the already-connected numeric upstream address. This method performs no DNS.
    pub async fn proxy_single_http1_tls_connection_for_allowed_hostnames<Guest, Upstream>(
        &self,
        guest_transport: Guest,
        upstream_transport: Upstream,
        allowed_hostnames: &AllowedHostnames,
    ) -> Result<(), AttachHeadersError>
    where
        Guest: AsyncRead + AsyncWrite + Unpin + Send,
        Upstream: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut guest_tls = TlsAcceptor::from(Arc::clone(&self.server_config))
            .accept(guest_transport)
            .await
            .map_err(|error| {
                AttachHeadersError::Tls(format!("guest TLS handshake failed: {error}"))
            })?;
        let server_name = guest_tls
            .get_ref()
            .1
            .server_name()
            .ok_or(AttachHeadersError::HostNotAllowed)?;
        let server_name = allowed_hostnames.require_allowed(server_name)?;

        let upstream_server_name = rustls::pki_types::ServerName::try_from(server_name.clone())
            .map_err(|_| AttachHeadersError::InvalidHost)?;
        let mut upstream_tls = TlsConnector::from(Arc::clone(&self.upstream_config))
            .connect(upstream_server_name, upstream_transport)
            .await
            .map_err(|error| {
                AttachHeadersError::Tls(format!("upstream TLS validation failed: {error}"))
            })?;
        proxy_single_http1_exchange(
            &mut guest_tls,
            &mut upstream_tls,
            &self.rules,
            self.limits,
            Some(&server_name),
            allowed_hostnames,
        )
        .await
    }
}

/// Plain HTTP/1.1 attach-header bridge. The caller supplies an already-approved,
/// already-connected numeric upstream transport and the hostnames authorized for it.
#[derive(Clone, Debug)]
pub struct Http1AttachHeadersProxy {
    rules: Arc<AttachHeaderRules>,
    limits: RequestHeadLimits,
}

impl Http1AttachHeadersProxy {
    pub fn new(rules: Arc<AttachHeaderRules>, limits: RequestHeadLimits) -> Self {
        Self { rules, limits }
    }

    pub async fn proxy_single_http1_connection<Guest, Upstream>(
        &self,
        mut guest_transport: Guest,
        mut upstream_transport: Upstream,
        allowed_hostnames: &AllowedHostnames,
    ) -> Result<(), AttachHeadersError>
    where
        Guest: AsyncRead + AsyncWrite + Unpin + Send,
        Upstream: AsyncRead + AsyncWrite + Unpin + Send,
    {
        proxy_single_http1_exchange(
            &mut guest_transport,
            &mut upstream_transport,
            &self.rules,
            self.limits,
            None,
            allowed_hostnames,
        )
        .await
    }
}

async fn proxy_single_http1_exchange<Guest, Upstream>(
    guest: &mut Guest,
    upstream: &mut Upstream,
    rules: &AttachHeaderRules,
    limits: RequestHeadLimits,
    expected_host: Option<&str>,
    allowed_hostnames: &AllowedHostnames,
) -> Result<(), AttachHeadersError>
where
    Guest: AsyncRead + AsyncWrite + Unpin + Send,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send,
{
    // A single-byte read avoids consuming body or pipelined bytes before
    // request framing has been validated. The head remains bounded.
    let mut transformer = Http1RequestHeadTransformer::new(rules, expected_host, limits)?;
    let transformed = loop {
        let mut byte = [0u8; 1];
        let read = guest
            .read(&mut byte)
            .await
            .map_err(|error| io_error("read guest request head", error))?;
        if read == 0 {
            return Err(AttachHeadersError::IncompleteRequestHead);
        }
        if let Some(transformed) = transformer.push(&byte)? {
            break transformed;
        }
    };
    let metadata = request_metadata(&transformed.bytes)?;
    allowed_hostnames.require_allowed(&metadata.host)?;
    let upstream_head = force_connection_close(&transformed.bytes)?;
    upstream
        .write_all(&upstream_head)
        .await
        .map_err(|error| io_error("write upstream request head", error))?;

    if let Some(content_length) = metadata.content_length {
        let mut body = (&mut *guest).take(content_length);
        let copied = tokio::io::copy(&mut body, &mut *upstream)
            .await
            .map_err(|error| io_error("stream request body", error))?;
        if copied != content_length {
            return Err(AttachHeadersError::Io(
                "guest closed before the declared request body completed".to_owned(),
            ));
        }
    }
    upstream
        .flush()
        .await
        .map_err(|error| io_error("flush upstream request", error))?;

    tokio::io::copy(&mut *upstream, &mut *guest)
        .await
        .map_err(|error| io_error("stream upstream response", error))?;
    guest
        .shutdown()
        .await
        .map_err(|error| io_error("close guest connection", error))?;
    Ok(())
}

#[derive(Debug)]
struct RequestMetadata {
    host: String,
    content_length: Option<u64>,
}

fn request_metadata(head: &[u8]) -> Result<RequestMetadata, AttachHeadersError> {
    let mut headers = vec![httparse::EMPTY_HEADER; DEFAULT_MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(head).map_err(map_httparse_error)?;
    if request.method == Some("CONNECT")
        || request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("upgrade"))
        || request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("connection")
                && header.value.split(|byte| *byte == b',').any(|token| {
                    std::str::from_utf8(token)
                        .is_ok_and(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                })
        })
    {
        return Err(AttachHeadersError::UnsupportedUpgrade);
    }
    if request
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(AttachHeadersError::AmbiguousMessageFraming);
    }
    let host = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .ok_or(AttachHeadersError::MissingOrDuplicateHost)
        .and_then(|header| {
            std::str::from_utf8(header.value)
                .map_err(|_| AttachHeadersError::InvalidHost)
                .and_then(canonical_authority_host)
        })?;
    let content_length = request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .map(|header| {
            std::str::from_utf8(header.value)
                .map_err(|_| AttachHeadersError::AmbiguousMessageFraming)?
                .parse::<u64>()
                .map_err(|_| AttachHeadersError::AmbiguousMessageFraming)
        })
        .transpose()?;
    Ok(RequestMetadata {
        host,
        content_length,
    })
}

fn force_connection_close(head: &[u8]) -> Result<Vec<u8>, AttachHeadersError> {
    let text = std::str::from_utf8(head).map_err(|_| AttachHeadersError::MalformedRequest)?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or(AttachHeadersError::MalformedRequest)?
        .split("\r\n");
    let request_line = lines.next().ok_or(AttachHeadersError::MalformedRequest)?;
    let mut result = Vec::with_capacity(head.len() + 24);
    result.extend_from_slice(request_line.as_bytes());
    result.extend_from_slice(b"\r\n");
    for line in lines {
        let name = line
            .split_once(':')
            .map(|(name, _)| name)
            .ok_or(AttachHeadersError::MalformedRequest)?;
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        result.extend_from_slice(line.as_bytes());
        result.extend_from_slice(b"\r\n");
    }
    result.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(result)
}

fn io_error(action: &str, error: std::io::Error) -> AttachHeadersError {
    AttachHeadersError::Io(format!("{action} failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::{RootCertStore, pki_types::ServerName};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    fn secret(value: &str) -> SecretHeaderValue {
        SecretHeaderValue::new(value.as_bytes().to_vec()).expect("valid test secret")
    }

    fn rules() -> AttachHeaderRules {
        AttachHeaderRules::new(vec![
            AttachHeaderRule::new(
                HostPattern::parse("*.example.com").expect("wildcard"),
                [("authorization", secret("Bearer wildcard-secret"))],
            )
            .expect("wildcard rule"),
            AttachHeaderRule::new(
                HostPattern::parse("api.example.com").expect("exact"),
                [("authorization", secret("Bearer exact-secret"))],
            )
            .expect("exact rule"),
            AttachHeaderRule::new(
                HostPattern::parse("*.shared.example").expect("shared wildcard"),
                [("authorization", secret("Bearer shared-secret"))],
            )
            .expect("shared wildcard rule"),
        ])
        .expect("rules")
    }

    #[test]
    fn patterns_are_canonical_and_most_specific_wins() {
        let rules = rules();
        let exact = rules
            .matching_rule("API.Example.COM")
            .expect("host")
            .expect("exact match");
        assert_eq!(exact.pattern().canonical(), "api.example.com");
        let wildcard = rules
            .matching_rule("www.example.com")
            .expect("host")
            .expect("wildcard match");
        assert_eq!(wildcard.pattern().canonical(), "*.example.com");
        assert!(rules.matching_rule("example.com").expect("host").is_none());
    }

    #[test]
    fn allowed_hostnames_are_non_empty_canonical_and_exact() {
        assert_eq!(
            AllowedHostnames::new(Vec::<String>::new()).expect_err("empty"),
            AttachHeadersError::EmptyAllowedHostnames
        );
        let allowed = AllowedHostnames::new(["API.Shared.Example", "alias.shared.example"])
            .expect("allowed hosts");
        assert!(allowed.contains("api.shared.example").expect("canonical"));
        assert!(!allowed.contains("other.shared.example").expect("canonical"));
    }

    #[test]
    fn secret_formatting_is_redacted_and_forbidden_headers_fail() {
        let value = secret("fixture-never-print");
        assert_eq!(value.to_string(), "[REDACTED]");
        assert!(!format!("{value:?}").contains("fixture-never-print"));
        let result = AttachHeaderRule::new(
            HostPattern::parse("api.example.com").expect("host"),
            [("Content-Length", value)],
        );
        assert_eq!(
            result.expect_err("forbidden"),
            AttachHeadersError::ForbiddenHeader
        );
    }

    #[tokio::test]
    async fn restored_ca_rejects_bad_material_and_can_issue_after_restart() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let generated = PerBoxCertificateAuthority::generate("restart-box").expect("CA");
            let certificate = generated.certificate_der();
            let private_key = generated.private_key_der();
            assert_eq!(private_key.to_string(), "[REDACTED]");
            assert!(format!("{private_key:?}").contains("[REDACTED]"));

            let other = PerBoxCertificateAuthority::generate("other-box").expect("other CA");
            assert!(
                PerBoxCertificateAuthority::from_der(
                    "restart-box",
                    certificate.as_ref().to_vec(),
                    other.private_key_der(),
                )
                .is_err()
            );

            let leaf_key = KeyPair::generate().expect("leaf key");
            let leaf_certificate = CertificateParams::default()
                .self_signed(&leaf_key)
                .expect("leaf certificate");
            assert!(
                PerBoxCertificateAuthority::from_der(
                    "restart-box",
                    leaf_certificate.der().as_ref().to_vec(),
                    SecretPrivateKeyDer::new(leaf_key.serialize_der()).expect("private key"),
                )
                .is_err()
            );

            let restored = Arc::new(
                PerBoxCertificateAuthority::from_der(
                    "restart-box",
                    certificate.as_ref().to_vec(),
                    private_key,
                )
                .expect("restored CA"),
            );
            let resolver = Arc::new(DynamicServerCertificateResolver::new(restored));
            let acceptor = TlsAcceptor::from(mitm_server_config(resolver));
            let (client_io, server_io) = tokio::io::duplex(4096);
            let server = tokio::spawn(async move {
                let mut tls = acceptor.accept(server_io).await.expect("server handshake");
                let mut request = [0u8; 4];
                tls.read_exact(&mut request).await.expect("request");
                assert_eq!(&request, b"ping");
                tls.write_all(b"pong").await.expect("response");
                tls.shutdown().await.expect("server close notify");
            });

            let mut roots = RootCertStore::empty();
            roots.add(certificate).expect("root");
            let connector = TlsConnector::from(upstream_client_config_with_roots(roots));
            let name = ServerName::try_from("api.example.com")
                .expect("server name")
                .to_owned();
            let mut client = connector
                .connect(name, client_io)
                .await
                .expect("restored CA leaf validates");
            client.write_all(b"ping").await.expect("write");
            let mut response = [0u8; 4];
            client.read_exact(&mut response).await.expect("read");
            assert_eq!(&response, b"pong");
            server.await.expect("server task");
        })
        .await
        .expect("CA restart test timed out");
    }

    #[test]
    fn transformer_injects_exact_rule_and_overwrites_guest_value() {
        let rules = rules();
        let mut transformer = Http1RequestHeadTransformer::new(
            &rules,
            Some("api.example.com"),
            RequestHeadLimits::default(),
        )
        .expect("transformer");
        let request =
            b"GET /v1 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: attacker\r\n\r\nbody";
        let transformed = transformer.push(request).expect("valid").expect("complete");
        let text = String::from_utf8(transformed.bytes).expect("ascii");
        assert!(text.contains("authorization: Bearer exact-secret\r\n"));
        assert!(!text.contains("attacker"));
        assert_eq!(transformed.consumed, request.len() - 4);
        assert_eq!(
            transformed.matched_pattern.as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn transformer_does_not_inject_non_matching_host() {
        let rules = rules();
        let mut transformer = Http1RequestHeadTransformer::new(
            &rules,
            Some("unrelated.test"),
            RequestHeadLimits::default(),
        )
        .expect("transformer");
        let transformed = transformer
            .push(b"GET / HTTP/1.1\r\nHost: unrelated.test\r\n\r\n")
            .expect("valid")
            .expect("complete");
        assert_eq!(transformed.matched_pattern, None);
        assert!(
            !String::from_utf8(transformed.bytes)
                .expect("ascii")
                .contains("authorization")
        );
    }

    #[test]
    fn transformer_rejects_smuggling_obs_fold_and_oversize() {
        let rules = rules();
        let cases: &[(&[u8], AttachHeadersError)] = &[
            (
                b"POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
                AttachHeadersError::AmbiguousMessageFraming,
            ),
            (
                b"GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Test: one\r\n two\r\n\r\n",
                AttachHeadersError::ObsoleteLineFolding,
            ),
        ];
        for (request, expected) in cases {
            let mut transformer = Http1RequestHeadTransformer::new(
                &rules,
                Some("api.example.com"),
                RequestHeadLimits::default(),
            )
            .expect("transformer");
            assert_eq!(transformer.push(request).expect_err("rejected"), *expected);
        }
        let mut transformer = Http1RequestHeadTransformer::new(
            &rules,
            None,
            RequestHeadLimits {
                max_bytes: 16,
                max_headers: 4,
            },
        )
        .expect("transformer");
        assert_eq!(
            transformer
                .push(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .expect_err("oversize"),
            AttachHeadersError::RequestHeadTooLarge
        );
        let mut transformer = Http1RequestHeadTransformer::new(
            &rules,
            None,
            RequestHeadLimits {
                max_bytes: DEFAULT_MAX_HEAD_BYTES,
                max_headers: 1,
            },
        )
        .expect("transformer");
        assert_eq!(
            transformer
                .push(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Extra: value\r\n\r\n")
                .expect_err("too many headers"),
            AttachHeadersError::TooManyHeaders
        );
        assert_eq!(
            request_metadata(
                b"GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
            )
            .expect_err("upgrade rejected"),
            AttachHeadersError::UnsupportedUpgrade
        );
        assert_eq!(
            request_metadata(
                b"POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .expect_err("chunked rejected"),
            AttachHeadersError::AmbiguousMessageFraming
        );
    }

    async fn run_local_https_mitm(host: &str) -> String {
        let host = host.to_owned();
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            let authority = Arc::new(PerBoxCertificateAuthority::generate("box-test").expect("CA"));
            let resolver = Arc::new(DynamicServerCertificateResolver::new(Arc::clone(
                &authority,
            )));

            let upstream_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind upstream");
            let upstream_address = upstream_listener.local_addr().expect("upstream addr");
            let upstream_acceptor = TlsAcceptor::from(mitm_server_config(Arc::clone(&resolver)));
            let upstream_task = tokio::spawn(async move {
                let (tcp, _) = upstream_listener.accept().await.expect("upstream accept");
                let mut tls = upstream_acceptor.accept(tcp).await.expect("upstream TLS");
                let mut buffer = vec![0u8; 4096];
                let read = tls.read(&mut buffer).await.expect("upstream read");
                let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                tls.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .expect("upstream response");
                tls.shutdown().await.expect("upstream TLS close notify");
                request
            });

            let proxy_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
            let proxy_address = proxy_listener.local_addr().expect("proxy addr");
            let guest_server_config = mitm_server_config(Arc::clone(&resolver));
            let mut roots = RootCertStore::empty();
            roots.add(authority.certificate_der()).expect("add test CA");
            let proxy = Arc::new(Http1TlsMitmProxy::new(
                guest_server_config,
                upstream_client_config_with_roots(roots.clone()),
                Arc::new(rules()),
                RequestHeadLimits::default(),
            ));
            let allowed_hostnames =
                AllowedHostnames::new([host.clone(), "alias.shared.example".to_owned()])
                    .expect("allowed hostnames");
            let proxy_task = tokio::spawn(async move {
                let (tcp, _) = proxy_listener.accept().await.expect("proxy accept");
                let upstream_tcp = tokio::net::TcpStream::connect(upstream_address)
                    .await
                    .expect("connect upstream");
                proxy
                    .proxy_single_http1_tls_connection_for_allowed_hostnames(
                        tcp,
                        upstream_tcp,
                        &allowed_hostnames,
                    )
                    .await
                    .expect("proxy exchange");
            });

            let guest_connector = TlsConnector::from(upstream_client_config_with_roots(roots));
            let guest_tcp = tokio::net::TcpStream::connect(proxy_address)
                .await
                .expect("connect proxy");
            let server_name = ServerName::try_from(host.clone())
                .expect("server name")
                .to_owned();
            let mut guest_tls = guest_connector
                .connect(server_name, guest_tcp)
                .await
                .expect("guest validates per-Box CA");
            guest_tls
                .write_all(
                    format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .expect("guest request");
            let mut response = Vec::new();
            guest_tls
                .read_to_end(&mut response)
                .await
                .expect("guest response");
            assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 204"));

            proxy_task.await.expect("proxy task");
            upstream_task.await.expect("upstream task")
        })
        .await
        .expect("local HTTPS MITM test timed out")
    }

    #[tokio::test]
    async fn local_https_mitm_injects_only_for_matching_host_and_validates_upstream() {
        let upstream_request = run_local_https_mitm("api.example.com").await;
        assert!(upstream_request.contains("authorization: Bearer exact-secret\r\n"));

        let non_matching_request = run_local_https_mitm("unrelated.test").await;
        assert!(!non_matching_request.contains("authorization:"));

        let shared_ip_request = run_local_https_mitm("api.shared.example").await;
        assert!(shared_ip_request.contains("authorization: Bearer shared-secret\r\n"));
    }

    #[tokio::test]
    async fn tls_actual_sni_must_be_allowed_even_for_a_shared_upstream() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let authority =
                Arc::new(PerBoxCertificateAuthority::generate("shared-ip-box").expect("authority"));
            let resolver = Arc::new(DynamicServerCertificateResolver::new(Arc::clone(
                &authority,
            )));
            let mut roots = RootCertStore::empty();
            roots.add(authority.certificate_der()).expect("root");
            let proxy = Arc::new(Http1TlsMitmProxy::new(
                mitm_server_config(resolver),
                upstream_client_config_with_roots(roots.clone()),
                Arc::new(rules()),
                RequestHeadLimits::default(),
            ));
            let allowed = AllowedHostnames::new(["api.shared.example", "alias.shared.example"])
                .expect("allowed");
            let (guest_client, guest_proxy) = tokio::io::duplex(4096);
            let (upstream_proxy, _upstream_peer) = tokio::io::duplex(4096);
            let proxy_task = tokio::spawn(async move {
                proxy
                    .proxy_single_http1_tls_connection_for_allowed_hostnames(
                        guest_proxy,
                        upstream_proxy,
                        &allowed,
                    )
                    .await
            });

            let connector = TlsConnector::from(upstream_client_config_with_roots(roots));
            let disallowed_name = ServerName::try_from("other.shared.example")
                .expect("server name")
                .to_owned();
            let _guest_tls = connector
                .connect(disallowed_name, guest_client)
                .await
                .expect("guest handshake uses dynamically issued certificate");
            assert_eq!(
                proxy_task.await.expect("proxy task").expect_err("rejected"),
                AttachHeadersError::HostNotAllowed
            );
        })
        .await
        .expect("shared-IP TLS test timed out");
    }

    async fn run_plain_http_proxy(
        host: &str,
        allowed: AllowedHostnames,
    ) -> Result<String, AttachHeadersError> {
        let host = host.to_owned();
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            let proxy =
                Http1AttachHeadersProxy::new(Arc::new(rules()), RequestHeadLimits::default());
            let (mut guest_client, guest_proxy) = tokio::io::duplex(4096);
            let (upstream_proxy, mut upstream_server) = tokio::io::duplex(4096);
            let proxy_task = tokio::spawn(async move {
                proxy
                    .proxy_single_http1_connection(guest_proxy, upstream_proxy, &allowed)
                    .await
            });
            guest_client
                .write_all(
                    format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .expect("guest request");

            let mut request_buffer = vec![0u8; 4096];
            let read = upstream_server
                .read(&mut request_buffer)
                .await
                .expect("upstream read");
            if read == 0 {
                return proxy_task
                    .await
                    .expect("proxy task")
                    .map(|()| String::new());
            }
            let request = String::from_utf8_lossy(&request_buffer[..read]).into_owned();
            upstream_server
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .expect("response");
            upstream_server.shutdown().await.expect("upstream close");
            let mut response = Vec::new();
            guest_client
                .read_to_end(&mut response)
                .await
                .expect("guest response");
            assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 204"));
            proxy_task.await.expect("proxy task")?;
            Ok(request)
        })
        .await
        .expect("plain HTTP proxy test timed out")
    }

    #[tokio::test]
    async fn plain_http_uses_host_allowlist_for_shared_ip_and_injects_only_when_allowed() {
        let allowed =
            AllowedHostnames::new(["api.shared.example", "alias.shared.example"]).expect("allowed");
        let request = run_plain_http_proxy("api.shared.example", allowed)
            .await
            .expect("allowed request");
        assert!(request.contains("authorization: Bearer shared-secret\r\n"));

        let allowed =
            AllowedHostnames::new(["api.shared.example", "alias.shared.example"]).expect("allowed");
        assert_eq!(
            run_plain_http_proxy("other.shared.example", allowed)
                .await
                .expect_err("shared-IP hostname rejected"),
            AttachHeadersError::HostNotAllowed
        );
    }

    #[tokio::test]
    async fn upstream_tls_rejects_untrusted_certificate() {
        let authority = Arc::new(PerBoxCertificateAuthority::generate("untrusted").expect("CA"));
        let resolver = Arc::new(DynamicServerCertificateResolver::new(authority));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let acceptor = TlsAcceptor::from(mitm_server_config(resolver));
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let _ = acceptor.accept(tcp).await;
        });
        let connector =
            TlsConnector::from(upstream_client_config_with_roots(RootCertStore::empty()));
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let server_name = ServerName::try_from("api.example.com")
            .expect("server name")
            .to_owned();
        assert!(connector.connect(server_name, tcp).await.is_err());
        server.await.expect("server task");
    }
}
