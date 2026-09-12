//! Local OCI image identity: classify an engine image id and resolve it to an
//! OCI *config* digest through the cryptographic descriptor chain.
//!
//! Docker 29 reports a manifest digest in container `.Image` / list `ImageID`
//! and in `ImageInspect.Id`. That value must not be relabelled as a config
//! digest. The config digest is taken from the local image archive's linked
//! descriptors, or from legacy Docker's config-id behaviour when no
//! descriptor class is present.

use std::collections::{BTreeMap, VecDeque};
use std::io::Read;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{normalize_prefixed_sha256, SHA256_HEX_BYTES};

/// Filtered `docker image inspect --format` query. It never requests Config,
/// Env, Identity, RepoTags, or RepoDigests. Serializing only Descriptor keeps
/// this compatible with Docker 29's map representation and legacy typed
/// representations alike.
pub const IMAGE_DESCRIPTOR_DOCKER_FORMAT: &str =
    "{{.Id}}\t{{if .Descriptor}}{{json .Descriptor}}{{else}}null{{end}}";

pub const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const DOCKER_INDEX_MEDIA_TYPE: &str =
    "application/vnd.docker.distribution.manifest.list.v2+json";
pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
pub const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
pub const DOCKER_CONFIG_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";

const MAX_OCI_JSON_BYTES: u64 = 1024 * 1024;
const MAX_OCI_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_OCI_METADATA_MEMBERS: usize = 64;
const MAX_OCI_ARCHIVE_MEMBERS: usize = 4096;
const MAX_INDEX_DEPTH: u8 = 4;
const MAX_IMAGE_DESCRIPTOR_JSON_BYTES: usize = 4 * 1024;

const INDEX_MEDIA: &[&str] = &[OCI_INDEX_MEDIA_TYPE, DOCKER_INDEX_MEDIA_TYPE];
const MANIFEST_MEDIA: &[&str] = &[OCI_MANIFEST_MEDIA_TYPE, DOCKER_MANIFEST_MEDIA_TYPE];
const CONFIG_MEDIA: &[&str] = &[OCI_CONFIG_MEDIA_TYPE, DOCKER_CONFIG_MEDIA_TYPE];

/// Class of the engine-reported image identity. Never inferred from the digest
/// spelling: two sha256 strings of different classes are incomparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageIdentityClass {
    Config,
    Manifest,
    Index,
}

/// Bounded in-process map from an immutable engine image identity to a proven
/// config digest. Identity change is a miss; there is no wall-clock TTL.
#[derive(Debug, Clone)]
pub struct ImageConfigDigestCache {
    max_entries: usize,
    entries: BTreeMap<String, ImageConfigDigestCacheEntry>,
    order: VecDeque<String>,
}

#[derive(Debug, Clone)]
struct ImageConfigDigestCacheEntry {
    config_digest: String,
    identity_class: Option<ImageIdentityClass>,
}

impl ImageConfigDigestCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn get(&self, identity: &str) -> Option<&str> {
        self.entries
            .get(identity)
            .map(|entry| entry.config_digest.as_str())
    }

    pub fn insert(&mut self, identity: String, config: String) {
        self.insert_with_class(identity, config, None);
    }

    pub fn insert_with_class(
        &mut self,
        identity: String,
        config: String,
        identity_class: Option<ImageIdentityClass>,
    ) {
        if self.entries.contains_key(&identity) {
            self.order.retain(|existing| existing != &identity);
            self.entries.insert(
                identity.clone(),
                ImageConfigDigestCacheEntry {
                    config_digest: config,
                    identity_class,
                },
            );
            self.order.push_back(identity);
            return;
        }
        while self.entries.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(identity.clone());
        self.entries.insert(
            identity,
            ImageConfigDigestCacheEntry {
                config_digest: config,
                identity_class,
            },
        );
    }

    pub fn get_with_class(&self, identity: &str) -> Option<(&str, Option<ImageIdentityClass>)> {
        self.entries
            .get(identity)
            .map(|entry| (entry.config_digest.as_str(), entry.identity_class))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Filtered facts from [`IMAGE_DESCRIPTOR_DOCKER_FORMAT`]. The current wire
/// form is `<image-id>\t<descriptor-json>`; `null` represents no descriptor.
/// The previous three-field form remains accepted for legacy callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDescriptorMeasurement {
    pub image_id: String,
    pub media_type: Option<String>,
    pub descriptor_digest: Option<String>,
}

pub fn parse_image_descriptor_format(raw: &str) -> Result<ImageDescriptorMeasurement, String> {
    let line = raw.trim_end_matches(['\n', '\r']);
    if line.is_empty() || line.lines().count() != 1 {
        return Err("image descriptor measurement must be exactly one filtered line".to_string());
    }
    let fields: Vec<&str> = line.split('\t').collect();
    let image_id = normalize_prefixed_sha256(fields[0])
        .ok_or_else(|| "image identity is not a sha256 digest".to_string())?;
    let (media_type, descriptor_digest) = match fields.len() {
        2 => parse_descriptor_json(fields[1])?,
        3 => parse_descriptor_fields(fields[1], fields[2])?,
        _ => {
            return Err(
                "image descriptor measurement must contain two or three filtered fields"
                    .to_string(),
            )
        }
    };
    validate_descriptor_measurement(&image_id, media_type, descriptor_digest)
}

fn parse_descriptor_fields(
    media_type: &str,
    digest: &str,
) -> Result<(Option<String>, Option<String>), String> {
    let media_type = optional_descriptor_field(media_type);
    let descriptor_digest = match optional_descriptor_field(digest) {
        None => None,
        Some(value) => Some(
            normalize_prefixed_sha256(&value)
                .ok_or_else(|| "image descriptor digest is not a sha256 digest".to_string())?,
        ),
    };
    Ok((media_type, descriptor_digest))
}

fn parse_descriptor_json(raw: &str) -> Result<(Option<String>, Option<String>), String> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "<no value>" || raw == "null" {
        return Ok((None, None));
    }
    if raw.len() > MAX_IMAGE_DESCRIPTOR_JSON_BYTES {
        return Err("image descriptor JSON exceeds the size bound".to_string());
    }
    let value: Value =
        serde_json::from_str(raw).map_err(|_| "image descriptor JSON is invalid".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "image descriptor JSON is not an object".to_string())?;
    let media_type = descriptor_json_string(object, "mediaType", "MediaType")?;
    let descriptor_digest = descriptor_json_string(object, "digest", "Digest")?
        .map(|value| {
            normalize_prefixed_sha256(&value)
                .ok_or_else(|| "image descriptor digest is not a sha256 digest".to_string())
        })
        .transpose()?;
    if media_type.is_none() && descriptor_digest.is_none() {
        return Err("image descriptor JSON has no public descriptor fields".to_string());
    }
    Ok((media_type, descriptor_digest))
}

fn descriptor_json_string(
    object: &serde_json::Map<String, Value>,
    lower: &str,
    legacy: &str,
) -> Result<Option<String>, String> {
    if object.contains_key(lower) && object.contains_key(legacy) {
        return Err(format!(
            "image descriptor JSON contains both {lower} and {legacy}"
        ));
    }
    let value = object.get(lower).or_else(|| object.get(legacy));
    match value {
        None => Ok(None),
        Some(Value::String(value)) => Ok(optional_descriptor_field(value)),
        Some(_) => Err(format!("image descriptor field {lower} is not a string")),
    }
}

fn validate_descriptor_measurement(
    image_id: &str,
    media_type: Option<String>,
    descriptor_digest: Option<String>,
) -> Result<ImageDescriptorMeasurement, String> {
    if let Some(media_type) = &media_type {
        let descriptor_digest = descriptor_digest.as_ref().ok_or_else(|| {
            "image descriptor digest is required when a media type is present".to_string()
        })?;
        if descriptor_digest != &image_id {
            return Err("image descriptor digest must equal the image id".to_string());
        }
        if classify_media_type(media_type).is_none() {
            return Err("image descriptor media type is not an OCI digest class".to_string());
        }
    } else if descriptor_digest.is_some() {
        return Err("image descriptor digest is present without a media type".to_string());
    }
    Ok(ImageDescriptorMeasurement {
        image_id: image_id.to_string(),
        media_type,
        descriptor_digest,
    })
}

/// Classify a measured descriptor. Missing media type is legacy config-id
/// behaviour. Unknown media types fail closed instead of being compared untyped.
pub fn classify_image_identity(
    measurement: &ImageDescriptorMeasurement,
) -> Result<ImageIdentityClass, String> {
    match measurement.media_type.as_deref() {
        None => Ok(ImageIdentityClass::Config),
        Some(media_type) => classify_media_type(media_type)
            .ok_or_else(|| "image descriptor media type is not an OCI digest class".to_string()),
    }
}

pub fn classify_media_type(media_type: &str) -> Option<ImageIdentityClass> {
    if CONFIG_MEDIA.contains(&media_type) {
        Some(ImageIdentityClass::Config)
    } else if MANIFEST_MEDIA.contains(&media_type) {
        Some(ImageIdentityClass::Manifest)
    } else if INDEX_MEDIA.contains(&media_type) {
        Some(ImageIdentityClass::Index)
    } else {
        None
    }
}

/// Resolve a config digest from a `docker save` metadata stream.
///
/// `platform` is required only when the identity is an index. A running
/// container's Descriptor that already names one manifest does not select by
/// platform. `None` as class means classify from the archive itself.
pub fn resolve_config_digest_from_image_archive<R: Read>(
    reader: R,
    identity: &str,
    class: Option<ImageIdentityClass>,
    platform: Option<(&str, &str)>,
) -> Result<String, String> {
    let identity = normalize_prefixed_sha256(identity)
        .ok_or_else(|| "image identity is not a sha256 digest".to_string())?;
    if class == Some(ImageIdentityClass::Config) {
        return Ok(identity);
    }
    let store = read_metadata_store(reader)?;
    resolve_from_store(&store, &identity, class, platform)
}

fn optional_descriptor_field(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value == "<no value>" {
        None
    } else {
        Some(value.to_string())
    }
}

#[derive(Default)]
struct MetadataStore {
    blobs: BTreeMap<String, Vec<u8>>,
    index_json: Option<Vec<u8>>,
    classic_manifest: Option<Vec<u8>>,
    classic_configs: BTreeMap<String, Vec<u8>>,
    stored_members: usize,
    stored_bytes: usize,
}

fn read_metadata_store<R: Read>(reader: R) -> Result<MetadataStore, String> {
    let mut archive = tar::Archive::new(reader);
    let mut store = MetadataStore::default();
    let mut seen = 0usize;
    let entries = archive
        .entries()
        .map_err(|_| "image archive is not a readable tar stream".to_string())?;
    for entry in entries {
        seen += 1;
        if seen > MAX_OCI_ARCHIVE_MEMBERS {
            return Err("image archive exceeds the member bound".to_string());
        }
        let mut entry = entry.map_err(|_| "image archive member is unreadable".to_string())?;
        let header = entry.header().clone();
        let path = entry
            .path()
            .map_err(|_| "image archive member path is unreadable".to_string())?
            .to_string_lossy()
            .into_owned();
        let Some(name) = readable_archive_name(&path) else {
            continue;
        };
        if header.entry_type().is_symlink()
            || header.entry_type().is_hard_link()
            || !header.entry_type().is_file()
        {
            return Err("image archive metadata member is not a regular file".to_string());
        }
        let size = header
            .size()
            .map_err(|_| "image archive member size is invalid".to_string())?;
        if size > MAX_OCI_JSON_BYTES {
            continue;
        }
        if store.stored_members >= MAX_OCI_METADATA_MEMBERS && !store.needs_named(&name) {
            continue;
        }
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|_| "image archive member is unreadable".to_string())?;
        if data.len() as u64 != size {
            return Err("image archive member size does not match contents".to_string());
        }
        store.insert(name, data)?;
    }
    Ok(store)
}

impl MetadataStore {
    fn needs_named(&self, name: &str) -> bool {
        name == "index.json" || name == "manifest.json"
    }

    fn insert(&mut self, name: String, data: Vec<u8>) -> Result<(), String> {
        let added = data.len();
        if self.stored_bytes.saturating_add(added) > MAX_OCI_METADATA_BYTES {
            return Err("image archive metadata exceeds the retained-size bound".to_string());
        }
        if name == "index.json" {
            if self.index_json.is_some() {
                return Err("image archive contains duplicate index metadata".to_string());
            }
            self.index_json = Some(data);
        } else if name == "manifest.json" {
            if self.classic_manifest.is_some() {
                return Err(
                    "image archive contains duplicate classic manifest metadata".to_string()
                );
            }
            self.classic_manifest = Some(data);
        } else if let Some(digest) = classic_config_digest_name(&name) {
            if self.classic_configs.contains_key(&digest) {
                return Err("image archive contains duplicate classic config metadata".to_string());
            }
            let hashed = sha256_digest(&data);
            if hashed != digest {
                return Err(
                    "classic image config bytes do not match the content digest".to_string()
                );
            }
            self.classic_configs.insert(digest, data);
        } else if let Some(digest) = blob_digest_from_name(&name) {
            let hashed = sha256_digest(&data);
            if hashed != digest {
                return Err("image blob bytes do not match the content digest".to_string());
            }
            if self.blobs.contains_key(&digest) {
                return Err("image archive contains duplicate blob metadata".to_string());
            }
            self.blobs.insert(digest, data);
        } else {
            return Ok(());
        }
        self.stored_members += 1;
        self.stored_bytes += added;
        Ok(())
    }
}

fn resolve_from_store(
    store: &MetadataStore,
    identity: &str,
    class: Option<ImageIdentityClass>,
    platform: Option<(&str, &str)>,
) -> Result<String, String> {
    if class == Some(ImageIdentityClass::Config) {
        return Ok(identity.to_string());
    }
    if let Some(raw) = store.blobs.get(identity) {
        let document = parse_json(raw)?;
        match blob_class(&document)? {
            ImageIdentityClass::Manifest => {
                if class.is_some() && class != Some(ImageIdentityClass::Manifest) {
                    return Err(
                        "image identity class does not match the local descriptor".to_string()
                    );
                }
                return config_digest_from_manifest(store, &document);
            }
            ImageIdentityClass::Index => {
                if class.is_some() && class != Some(ImageIdentityClass::Index) {
                    return Err(
                        "image identity class does not match the local descriptor".to_string()
                    );
                }
                return config_digest_from_index(store, &document, platform, 0);
            }
            ImageIdentityClass::Config => {
                return Err("image identity blob is a config, not a descriptor".to_string());
            }
        }
    }
    if class == Some(ImageIdentityClass::Manifest) || class == Some(ImageIdentityClass::Index) {
        return Err("typed image identity blob is missing from the local archive".to_string());
    }
    if let Some(raw) = store.index_json.as_ref() {
        if sha256_digest(raw) != identity {
            return classic_config_digest(store, identity);
        }
        let document = parse_json(raw)?;
        if let Ok(config) = config_digest_from_index(store, &document, platform, 0) {
            return Ok(config);
        }
    }
    classic_config_digest(store, identity)
}

fn config_digest_from_manifest(store: &MetadataStore, manifest: &Value) -> Result<String, String> {
    let config = manifest
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(|| "image manifest does not name a config descriptor".to_string())?;
    let media_type = config
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or_else(|| "image config descriptor is missing a media type".to_string())?;
    if !CONFIG_MEDIA.contains(&media_type) {
        return Err("image config descriptor is not a config media type".to_string());
    }
    let digest = normalize_prefixed_sha256(
        config
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| "image config descriptor is missing a digest".to_string())?,
    )
    .ok_or_else(|| "image config descriptor digest is not a sha256 digest".to_string())?;
    let size = json_size(config.get("size"))?;
    let raw = store
        .blobs
        .get(&digest)
        .ok_or_else(|| "image config blob is missing from the local archive".to_string())?;
    if raw.len() as u64 != size || sha256_digest(raw) != digest {
        return Err("image config blob does not match its descriptor".to_string());
    }
    let parsed = parse_json(raw)?;
    if !parsed.is_object() {
        return Err("image config blob is not a JSON object".to_string());
    }
    Ok(digest)
}

fn config_digest_from_index(
    store: &MetadataStore,
    document: &Value,
    platform: Option<(&str, &str)>,
    depth: u8,
) -> Result<String, String> {
    let selected =
        collect_platform_manifests(store, document, &mut BTreeMap::new(), depth, platform)?;
    if selected.is_empty() {
        return Err("image index has no unique platform manifest".to_string());
    }
    if selected.len() != 1 {
        return Err("image index has an ambiguous platform manifest".to_string());
    }
    let (digest, size) = &selected[0];
    let raw = store.blobs.get(digest).ok_or_else(|| {
        "selected image manifest blob is missing from the local archive".to_string()
    })?;
    if raw.len() as u64 != *size || sha256_digest(raw) != *digest {
        return Err("selected image manifest blob does not match its descriptor".to_string());
    }
    let manifest = parse_json(raw)?;
    config_digest_from_manifest(store, &manifest)
}

fn collect_platform_manifests(
    store: &MetadataStore,
    document: &Value,
    seen: &mut BTreeMap<String, ()>,
    depth: u8,
    platform: Option<(&str, &str)>,
) -> Result<Vec<(String, u64)>, String> {
    if depth > MAX_INDEX_DEPTH {
        return Err("image index descriptor chain exceeds the depth bound".to_string());
    }
    let manifests = document
        .get("manifests")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| "image index does not name manifests".to_string())?;
    let mut selected = Vec::new();
    let mut unsigned = Vec::new();
    let mut saw_platform = false;
    for item in manifests {
        let descriptor = item
            .as_object()
            .ok_or_else(|| "image index member is not a descriptor".to_string())?;
        let media_type = descriptor
            .get("mediaType")
            .and_then(Value::as_str)
            .ok_or_else(|| "image descriptor is missing a media type".to_string())?;
        let digest = normalize_prefixed_sha256(
            descriptor
                .get("digest")
                .and_then(Value::as_str)
                .ok_or_else(|| "image descriptor is missing a digest".to_string())?,
        )
        .ok_or_else(|| "image descriptor digest is not a sha256 digest".to_string())?;
        let size = json_size(descriptor.get("size"))?;
        if seen.insert(digest.clone(), ()).is_some() {
            return Err("image descriptor chain contains a repeated digest".to_string());
        }
        if INDEX_MEDIA.contains(&media_type) {
            let raw = store.blobs.get(&digest).ok_or_else(|| {
                "nested image index blob is missing from the local archive".to_string()
            })?;
            if raw.len() as u64 != size || sha256_digest(raw) != digest {
                return Err("nested image index blob does not match its descriptor".to_string());
            }
            let inner = parse_json(raw)?;
            selected.extend(collect_platform_manifests(
                store,
                &inner,
                seen,
                depth + 1,
                platform,
            )?);
            continue;
        }
        if !MANIFEST_MEDIA.contains(&media_type) {
            continue;
        }
        match descriptor.get("platform") {
            None => unsigned.push((digest, size)),
            Some(Value::Null) => unsigned.push((digest, size)),
            Some(value) => {
                saw_platform = true;
                if platform_matches(value, platform)? {
                    selected.push((digest, size));
                }
            }
        }
    }
    if !selected.is_empty() {
        return Ok(selected);
    }
    if !saw_platform && unsigned.len() == 1 {
        return Ok(unsigned);
    }
    Ok(Vec::new())
}

fn platform_matches(value: &Value, wanted: Option<(&str, &str)>) -> Result<bool, String> {
    let Some((os, architecture)) = wanted else {
        return Err("image index requires an explicit platform to select a manifest".to_string());
    };
    let platform = value
        .as_object()
        .ok_or_else(|| "image platform descriptor is not an object".to_string())?;
    Ok(platform.get("os").and_then(Value::as_str) == Some(os)
        && platform.get("architecture").and_then(Value::as_str) == Some(architecture))
}

fn classic_config_digest(store: &MetadataStore, identity: &str) -> Result<String, String> {
    let raw = store.classic_manifest.as_ref().ok_or_else(|| {
        "image archive has no typed descriptor chain for the identity".to_string()
    })?;
    let entries = parse_json(raw)?;
    let entries = entries
        .as_array()
        .filter(|items| items.len() == 1)
        .ok_or_else(|| "classic image manifest must contain exactly one entry".to_string())?;
    let entry = entries[0]
        .as_object()
        .ok_or_else(|| "classic image manifest entry is not an object".to_string())?;
    let config_name = entry
        .get("Config")
        .and_then(Value::as_str)
        .ok_or_else(|| "classic image manifest does not name a config".to_string())?;
    let digest = classic_config_digest_name(config_name)
        .ok_or_else(|| "classic image config name is not a content digest".to_string())?;
    if digest != identity {
        return Err("classic image config digest does not match the image identity".to_string());
    }
    let raw = store
        .classic_configs
        .get(&digest)
        .ok_or_else(|| "classic image config blob is missing from the local archive".to_string())?;
    if sha256_digest(raw) != digest {
        return Err("classic image config blob does not match its digest".to_string());
    }
    Ok(digest)
}

fn blob_class(document: &Value) -> Result<ImageIdentityClass, String> {
    if let Some(media_type) = document.get("mediaType").and_then(Value::as_str) {
        return classify_media_type(media_type)
            .ok_or_else(|| "image blob media type is not an OCI digest class".to_string());
    }
    let config = document.get("config");
    if config.and_then(|value| value.get("digest")).is_some()
        && config.and_then(|value| value.get("mediaType")).is_some()
    {
        return Ok(ImageIdentityClass::Manifest);
    }
    if document
        .get("manifests")
        .and_then(Value::as_array)
        .is_some()
    {
        return Ok(ImageIdentityClass::Index);
    }
    Err("image blob is not a typed OCI descriptor".to_string())
}

fn parse_json(raw: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(raw).map_err(|_| "image metadata is not typed JSON".to_string())
}

fn json_size(value: Option<&Value>) -> Result<u64, String> {
    let value = value.ok_or_else(|| "image descriptor is missing a size".to_string())?;
    let size = value
        .as_u64()
        .ok_or_else(|| "image descriptor size is not a non-negative integer".to_string())?;
    if size > MAX_OCI_JSON_BYTES {
        return Err("image descriptor size exceeds the JSON bound".to_string());
    }
    Ok(size)
}

fn sha256_digest(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn readable_archive_name(name: &str) -> Option<String> {
    if name.contains('\0') || name.starts_with('/') || name.contains('\\') {
        return None;
    }
    let mut parts = Vec::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return None;
    }
    let normalized = parts.join("/");
    if normalized == "index.json" || normalized == "manifest.json" {
        return Some(normalized);
    }
    if blob_digest_from_name(&normalized).is_some() {
        return Some(normalized);
    }
    if classic_config_digest_name(&normalized).is_some() {
        return Some(normalized);
    }
    None
}

fn blob_digest_from_name(name: &str) -> Option<String> {
    let hex = name.strip_prefix("blobs/sha256/")?;
    if hex.len() == SHA256_HEX_BYTES
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Some(format!("sha256:{hex}"))
    } else {
        None
    }
}

fn classic_config_digest_name(name: &str) -> Option<String> {
    let hex = name.strip_suffix(".json")?;
    if hex.len() == SHA256_HEX_BYTES
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !name.contains('/')
    {
        Some(format!("sha256:{hex}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn json_bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    fn config_bytes() -> Vec<u8> {
        json_bytes(&serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []}
        }))
    }

    fn manifest_bytes(config_digest: &str, config_size: u64) -> Vec<u8> {
        json_bytes(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": config_size
            },
            "layers": []
        }))
    }

    fn index_bytes(entries: &[Value]) -> Vec<u8> {
        json_bytes(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": entries
        }))
    }

    fn descriptor(media: &str, digest: &str, size: u64, platform: Option<(&str, &str)>) -> Value {
        let mut value = serde_json::json!({
            "mediaType": media,
            "digest": digest,
            "size": size
        });
        if let Some((os, architecture)) = platform {
            value["platform"] = serde_json::json!({"os": os, "architecture": architecture});
        }
        value
    }

    fn tar_from(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        buf
    }

    fn docker29_chain() -> (Vec<u8>, String, String) {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let manifest = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_digest = sha256_digest(&manifest);
        let index = index_bytes(&[descriptor(
            OCI_MANIFEST_MEDIA_TYPE,
            &manifest_digest,
            manifest.len() as u64,
            Some(("linux", "amd64")),
        )]);
        let archive = tar_from(&[
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#),
            ("index.json", &index),
            (&format!("blobs/sha256/{}", &config_digest[7..]), &config),
            (
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                &manifest,
            ),
        ]);
        (archive, manifest_digest, config_digest)
    }

    #[test]
    fn docker29_manifest_identity_resolves_config_and_keeps_classes_distinct() {
        let (archive, manifest, config) = docker29_chain();
        assert_ne!(manifest, config);
        let measurement = parse_image_descriptor_format(&format!(
            "{manifest}\t{OCI_MANIFEST_MEDIA_TYPE}\t{manifest}\n"
        ))
        .unwrap();
        assert_eq!(
            classify_image_identity(&measurement).unwrap(),
            ImageIdentityClass::Manifest
        );
        let resolved = resolve_config_digest_from_image_archive(
            Cursor::new(archive),
            &manifest,
            Some(ImageIdentityClass::Manifest),
            None,
        )
        .unwrap();
        assert_eq!(resolved, config);
        assert_ne!(resolved, manifest);
    }

    #[test]
    fn docker29_lowercase_descriptor_json_is_measured() {
        let image_id = format!("sha256:{}", "b".repeat(64));
        let descriptor = serde_json::json!({
            "mediaType": DOCKER_MANIFEST_MEDIA_TYPE,
            "digest": image_id,
            "size": 123,
        });
        let raw = format!("{image_id}\t{descriptor}\n");
        let measurement = parse_image_descriptor_format(&raw).unwrap();
        assert_eq!(measurement.image_id, image_id);
        assert_eq!(
            measurement.media_type,
            Some(DOCKER_MANIFEST_MEDIA_TYPE.to_string())
        );
        assert_eq!(measurement.descriptor_digest, Some(image_id.clone()));
        assert_eq!(
            classify_image_identity(&measurement).unwrap(),
            ImageIdentityClass::Manifest
        );
    }

    #[test]
    fn descriptor_json_supports_legacy_nil_and_typed_layouts() {
        let image_id = format!("sha256:{}", "c".repeat(64));
        let nil = parse_image_descriptor_format(&format!("{image_id}\tnull\n")).unwrap();
        assert_eq!(
            classify_image_identity(&nil).unwrap(),
            ImageIdentityClass::Config
        );

        let descriptor = serde_json::json!({
            "MediaType": DOCKER_MANIFEST_MEDIA_TYPE,
            "Digest": image_id,
            "Size": 123,
        });
        let typed = format!("{image_id}\t{descriptor}\n");
        let measurement = parse_image_descriptor_format(&typed).unwrap();
        assert_eq!(
            classify_image_identity(&measurement).unwrap(),
            ImageIdentityClass::Manifest
        );
    }

    #[test]
    fn tampered_manifest_blob_fails_closed() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let manifest = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_digest = sha256_digest(&manifest);
        let mut tampered = manifest.clone();
        tampered[0] ^= 0x7f;
        assert_ne!(sha256_digest(&tampered), manifest_digest);
        let archive = tar_from(&[
            (
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                &tampered,
            ),
            (&format!("blobs/sha256/{}", &config_digest[7..]), &config),
        ]);
        assert!(resolve_config_digest_from_image_archive(
            Cursor::new(archive),
            &manifest_digest,
            Some(ImageIdentityClass::Manifest),
            None,
        )
        .is_err());
    }

    #[test]
    fn tampered_config_pointer_fails_closed() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let other = json_bytes(&serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {"User": "nobody"},
            "rootfs": {"type": "layers", "diff_ids": []}
        }));
        assert_ne!(sha256_digest(&other), config_digest);
        let manifest = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_digest = sha256_digest(&manifest);
        let archive = tar_from(&[
            (
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                &manifest,
            ),
            (&format!("blobs/sha256/{}", &config_digest[7..]), &other),
        ]);
        assert!(resolve_config_digest_from_image_archive(
            Cursor::new(archive),
            &manifest_digest,
            Some(ImageIdentityClass::Manifest),
            None,
        )
        .is_err());
    }

    #[test]
    fn stale_cache_does_not_reuse_a_previous_identity() {
        let mut cache = ImageConfigDigestCache::new(2);
        let first = format!("sha256:{}", "1".repeat(64));
        let second = format!("sha256:{}", "2".repeat(64));
        let third = format!("sha256:{}", "3".repeat(64));
        let config_a = format!("sha256:{}", "a".repeat(64));
        let config_b = format!("sha256:{}", "b".repeat(64));
        let config_c = format!("sha256:{}", "c".repeat(64));
        cache.insert(first.clone(), config_a.clone());
        assert_eq!(cache.get(&first), Some(config_a.as_str()));
        assert_eq!(cache.get(&second), None, "a new identity must miss");
        cache.insert(second.clone(), config_b.clone());
        assert_eq!(cache.get(&second), Some(config_b.as_str()));
        cache.insert(third.clone(), config_c.clone());
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.get(&first),
            None,
            "bounded cache must evict the oldest identity"
        );
        assert_eq!(cache.get(&second), Some(config_b.as_str()));
        assert_eq!(cache.get(&third), Some(config_c.as_str()));
        assert_ne!(cache.get(&second), Some(config_a.as_str()));
    }

    #[test]
    fn ambiguous_platform_index_fails_closed() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let manifest_a = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_b = json_bytes(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": config.len()
            },
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": format!("sha256:{}", "d".repeat(64)), "size": 1}]
        }));
        let digest_a = sha256_digest(&manifest_a);
        let digest_b = sha256_digest(&manifest_b);
        assert_ne!(digest_a, digest_b);
        let index = index_bytes(&[
            descriptor(
                OCI_MANIFEST_MEDIA_TYPE,
                &digest_a,
                manifest_a.len() as u64,
                Some(("linux", "amd64")),
            ),
            descriptor(
                OCI_MANIFEST_MEDIA_TYPE,
                &digest_b,
                manifest_b.len() as u64,
                Some(("linux", "amd64")),
            ),
        ]);
        let index_digest = sha256_digest(&index);
        let archive = tar_from(&[
            (&format!("blobs/sha256/{}", &index_digest[7..]), &index),
            (&format!("blobs/sha256/{}", &digest_a[7..]), &manifest_a),
            (&format!("blobs/sha256/{}", &digest_b[7..]), &manifest_b),
            (&format!("blobs/sha256/{}", &config_digest[7..]), &config),
        ]);
        let err = resolve_config_digest_from_image_archive(
            Cursor::new(archive),
            &index_digest,
            Some(ImageIdentityClass::Index),
            Some(("linux", "amd64")),
        )
        .unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn unique_platform_index_resolves_config() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let manifest = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_digest = sha256_digest(&manifest);
        let index = index_bytes(&[descriptor(
            OCI_MANIFEST_MEDIA_TYPE,
            &manifest_digest,
            manifest.len() as u64,
            Some(("linux", "amd64")),
        )]);
        let index_digest = sha256_digest(&index);
        let archive = tar_from(&[
            ("index.json", &index),
            (&format!("blobs/sha256/{}", &index_digest[7..]), &index),
            (
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                &manifest,
            ),
            (&format!("blobs/sha256/{}", &config_digest[7..]), &config),
        ]);
        let resolved = resolve_config_digest_from_image_archive(
            Cursor::new(archive),
            &index_digest,
            Some(ImageIdentityClass::Index),
            Some(("linux", "amd64")),
        )
        .unwrap();
        assert_eq!(resolved, config_digest);
        assert_ne!(resolved, index_digest);
        assert_ne!(resolved, manifest_digest);
    }

    #[test]
    fn unrelated_index_json_cannot_resolve_a_missing_identity() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let manifest = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_digest = sha256_digest(&manifest);
        let index = index_bytes(&[descriptor(
            OCI_MANIFEST_MEDIA_TYPE,
            &manifest_digest,
            manifest.len() as u64,
            Some(("linux", "amd64")),
        )]);
        let unrelated_identity = format!("sha256:{}", "e".repeat(64));
        assert_ne!(sha256_digest(&index), unrelated_identity);
        let archive = tar_from(&[
            ("index.json", &index),
            (
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                &manifest,
            ),
            (&format!("blobs/sha256/{}", &config_digest[7..]), &config),
        ]);

        assert!(resolve_config_digest_from_image_archive(
            Cursor::new(archive),
            &unrelated_identity,
            None,
            Some(("linux", "amd64")),
        )
        .is_err());
    }

    #[test]
    fn legacy_config_id_without_descriptor_is_preserved() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let classic = json_bytes(&serde_json::json!([{
            "Config": format!("{}.json", &config_digest[7..]),
            "Layers": []
        }]));
        let archive = tar_from(&[
            ("manifest.json", &classic),
            (&format!("{}.json", &config_digest[7..]), &config),
        ]);
        let measurement = parse_image_descriptor_format(&format!("{config_digest}\t\t\n")).unwrap();
        assert_eq!(
            classify_image_identity(&measurement).unwrap(),
            ImageIdentityClass::Config
        );
        assert_eq!(
            resolve_config_digest_from_image_archive(
                Cursor::new(archive),
                &config_digest,
                Some(ImageIdentityClass::Config),
                None,
            )
            .unwrap(),
            config_digest
        );
        let archive = tar_from(&[
            ("manifest.json", &classic),
            (&format!("{}.json", &config_digest[7..]), &config),
        ]);
        assert_eq!(
            resolve_config_digest_from_image_archive(
                Cursor::new(archive),
                &config_digest,
                None,
                None,
            )
            .unwrap(),
            config_digest
        );
    }

    #[test]
    fn unknown_media_type_is_not_compared_untyped() {
        let id = format!("sha256:{}", "b".repeat(64));
        assert!(parse_image_descriptor_format(&format!(
            "{id}\tapplication/vnd.unknown.thing\t{id}\n"
        ))
        .is_err());
    }

    #[test]
    fn symlink_metadata_member_fails_closed() {
        let config = config_bytes();
        let config_digest = sha256_digest(&config);
        let manifest = manifest_bytes(&config_digest, config.len() as u64);
        let manifest_digest = sha256_digest(&manifest);
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            let mut header = tar::Header::new_gnu();
            header.set_path("index.json").unwrap();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("blobs/sha256/deadbeef").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, &[] as &[u8]).unwrap();
            builder.finish().unwrap();
        }
        assert!(resolve_config_digest_from_image_archive(
            Cursor::new(buf),
            &manifest_digest,
            Some(ImageIdentityClass::Manifest),
            None,
        )
        .is_err());
    }
}
