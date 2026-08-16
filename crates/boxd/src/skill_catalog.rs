use async_trait::async_trait;
use box_core::{DomainError, DomainErrorKind, validate_skill_id};
use box_service::{SkillCatalog, SkillPackage, SkillPackageFile};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use url::Url;

const CONTEXT7_ORIGIN: &str = "https://context7.com";
const GITHUB_API_ORIGIN: &str = "https://api.github.com";
const GITHUB_RAW_ORIGIN: &str = "https://raw.githubusercontent.com";
const MAX_SKILLS: usize = 16;
const MAX_FILES: usize = 128;
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct Context7Catalog {
    client: reqwest::Client,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogSkill {
    name: String,
    url: String,
    project: Option<String>,
    version_commit_sha: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogResponse {
    project: Option<String>,
    skills: Option<Vec<CatalogSkill>>,
    error: Option<String>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
}

#[derive(Deserialize)]
struct TreeResponse {
    tree: Vec<TreeEntry>,
    truncated: bool,
}

#[derive(Deserialize)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
}

struct GitHubLocation {
    owner: String,
    repo: String,
    directory: String,
}

impl Context7Catalog {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(12))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("boxd-context7-skills/0.0.0")
            .build()
            .map_err(|error| format!("Context7 HTTP client initialization failed: {error}"))?;
        Ok(Self { client })
    }

    fn unavailable(message: impl Into<String>) -> DomainError {
        DomainError {
            kind: DomainErrorKind::Unavailable,
            code: "skill_catalog_unavailable",
            message: message.into(),
        }
    }

    fn not_found() -> DomainError {
        DomainError {
            kind: DomainErrorKind::NotFound,
            code: "skill_not_found",
            message: "skill was not found in the Context7 catalog".into(),
        }
    }

    fn project(value: &str) -> box_core::Result<String> {
        let normalized = value.strip_prefix('/').unwrap_or(value);
        let parts = normalized.split('/').collect::<Vec<_>>();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || part.len() > 128
                    || matches!(*part, "." | "..")
                    || !part.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric()
                            || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
                    })
            })
        {
            return Err(DomainError::validation("invalid skill project"));
        }
        Ok(format!("/{normalized}"))
    }

    async fn list_metadata(&self, project: &str) -> box_core::Result<Vec<CatalogSkill>> {
        let project = Self::project(project)?;
        let response = self
            .client
            .get(format!("{CONTEXT7_ORIGIN}/api/v2/skills"))
            .query(&[("project", project.as_str())])
            .send()
            .await
            .map_err(|error| Self::unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(Self::unavailable(format!(
                "Context7 catalog returned HTTP {}",
                response.status()
            )));
        }
        let payload: CatalogResponse = response
            .json()
            .await
            .map_err(|error| Self::unavailable(error.to_string()))?;
        if let Some(error) = payload.error {
            return Err(Self::unavailable(payload.message.unwrap_or(error)));
        }
        if payload.project.as_deref() != Some(project.as_str()) {
            return Err(Self::unavailable("Context7 catalog project mismatch"));
        }
        let skills = payload.skills.unwrap_or_default();
        if skills.len() > MAX_SKILLS {
            return Err(DomainError::validation(
                "skill project contains more than 16 installable skills",
            ));
        }
        Ok(skills)
    }

    fn github_location(url: &str, project: &str) -> box_core::Result<GitHubLocation> {
        let url = Url::parse(url).map_err(|_| Self::unavailable("invalid catalog skill URL"))?;
        let segments = url
            .path_segments()
            .ok_or_else(|| Self::unavailable("invalid catalog skill URL"))?
            .collect::<Vec<_>>();
        let (owner, repo, branch, file_parts) = match url.host_str() {
            Some("raw.githubusercontent.com")
                if segments.len() >= 7 && segments[2] == "refs" && segments[3] == "heads" =>
            {
                (segments[0], segments[1], segments[4], &segments[5..])
            }
            Some("github.com") if segments.len() >= 6 && segments[2] == "tree" => {
                (segments[0], segments[1], segments[3], &segments[4..])
            }
            _ => return Err(Self::unavailable("catalog skill URL is not a GitHub tree")),
        };
        if format!("/{owner}/{repo}") != project
            || file_parts.last().copied() != Some("SKILL.md")
            || branch.is_empty()
        {
            return Err(Self::unavailable("catalog skill source identity mismatch"));
        }
        let directory = file_parts[..file_parts.len() - 1].join("/");
        if directory.is_empty() {
            return Err(Self::unavailable("catalog skill directory is empty"));
        }
        Ok(GitHubLocation {
            owner: owner.into(),
            repo: repo.into(),
            directory,
        })
    }

    async fn full_commit(
        &self,
        location: &GitHubLocation,
        commit: &str,
    ) -> box_core::Result<String> {
        if commit.len() < 7
            || commit.len() > 40
            || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Self::unavailable("catalog omitted a valid source commit"));
        }
        let response = self
            .client
            .get(format!(
                "{GITHUB_API_ORIGIN}/repos/{}/{}/commits/{commit}",
                location.owner, location.repo
            ))
            .send()
            .await
            .map_err(|error| Self::unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(Self::unavailable(format!(
                "GitHub commit lookup returned HTTP {}",
                response.status()
            )));
        }
        let commit: CommitResponse = response
            .json()
            .await
            .map_err(|error| Self::unavailable(error.to_string()))?;
        if commit.sha.len() != 40 || !commit.sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Self::unavailable(
                "GitHub returned an invalid commit identity",
            ));
        }
        Ok(commit.sha.to_ascii_lowercase())
    }

    async fn download(
        &self,
        project: &str,
        metadata: CatalogSkill,
        pinned_commit: Option<&str>,
        pinned_digest: Option<&str>,
    ) -> box_core::Result<SkillPackage> {
        let expected_name = validate_skill_id(&format!(
            "{}/{}",
            project.trim_start_matches('/'),
            metadata.name
        ))?;
        if expected_name != metadata.name
            || metadata
                .project
                .as_deref()
                .is_some_and(|value| value != project)
        {
            return Err(Self::unavailable("Context7 skill identity mismatch"));
        }
        let location = Self::github_location(&metadata.url, project)?;
        let requested_commit = pinned_commit
            .map(str::to_owned)
            .or(metadata.version_commit_sha)
            .ok_or_else(|| Self::unavailable("Context7 skill has no source commit"))?;
        let commit = self.full_commit(&location, &requested_commit).await?;
        if pinned_commit.is_some_and(|expected| !commit.eq_ignore_ascii_case(expected)) {
            return Err(Self::unavailable("pinned skill commit mismatch"));
        }
        let response = self
            .client
            .get(format!(
                "{GITHUB_API_ORIGIN}/repos/{}/{}/git/trees/{commit}?recursive=1",
                location.owner, location.repo
            ))
            .send()
            .await
            .map_err(|error| Self::unavailable(error.to_string()))?;
        if !response.status().is_success() {
            return Err(Self::unavailable(format!(
                "GitHub tree lookup returned HTTP {}",
                response.status()
            )));
        }
        let tree: TreeResponse = response
            .json()
            .await
            .map_err(|error| Self::unavailable(error.to_string()))?;
        if tree.truncated {
            return Err(Self::unavailable("GitHub returned a truncated skill tree"));
        }
        let prefix = format!("{}/", location.directory);
        let mut paths = Vec::new();
        for entry in tree.tree {
            let Some(relative) = entry.path.strip_prefix(&prefix) else {
                continue;
            };
            if relative.is_empty() || entry.kind == "tree" {
                continue;
            }
            if entry.kind != "blob" || !matches!(entry.mode.as_str(), "100644" | "100755") {
                return Err(Self::unavailable("skill tree contains a non-regular entry"));
            }
            validate_relative_path(relative)?;
            paths.push((relative.to_owned(), entry.path));
        }
        paths.sort_by(|left, right| left.0.cmp(&right.0));
        if paths.is_empty() || paths.len() > MAX_FILES || paths[0].0 != "SKILL.md" {
            return Err(Self::unavailable("skill package file set is invalid"));
        }
        let mut files = Vec::with_capacity(paths.len());
        let mut total = 0usize;
        for (relative, source_path) in paths {
            let mut url = Url::parse(GITHUB_RAW_ORIGIN).expect("constant GitHub raw URL");
            url.path_segments_mut()
                .expect("GitHub raw URL supports path segments")
                .extend([
                    location.owner.as_str(),
                    location.repo.as_str(),
                    commit.as_str(),
                ])
                .extend(source_path.split('/'));
            let response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|error| Self::unavailable(error.to_string()))?;
            if !response.status().is_success() {
                return Err(Self::unavailable(format!(
                    "GitHub skill download returned HTTP {}",
                    response.status()
                )));
            }
            let content = response
                .bytes()
                .await
                .map_err(|error| Self::unavailable(error.to_string()))?
                .to_vec();
            total = total
                .checked_add(content.len())
                .ok_or_else(|| Self::unavailable("skill package size overflow"))?;
            if content.len() > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES {
                return Err(DomainError::validation("skill package exceeds size limit"));
            }
            files.push(SkillPackageFile {
                path: relative,
                content,
            });
        }
        validate_frontmatter_name(&files[0].content, &metadata.name)?;
        let digest = package_digest(&files);
        if pinned_digest.is_some_and(|expected| !digest.eq_ignore_ascii_case(expected)) {
            return Err(Self::unavailable("pinned skill content digest mismatch"));
        }
        Ok(SkillPackage {
            skill_id: format!("{}/{}/{}", location.owner, location.repo, metadata.name),
            name: metadata.name,
            source_commit: commit,
            content_sha256: digest,
            files,
        })
    }
}

#[async_trait]
impl SkillCatalog for Context7Catalog {
    async fn resolve(&self, skill_id: &str) -> box_core::Result<SkillPackage> {
        let name = validate_skill_id(skill_id)?;
        let project = Self::project(
            skill_id
                .rsplit_once('/')
                .map(|(project, _)| project)
                .ok_or_else(|| DomainError::validation("invalid skill id"))?,
        )?;
        let metadata = self
            .list_metadata(&project)
            .await?
            .into_iter()
            .find(|skill| skill.name == name)
            .ok_or_else(Self::not_found)?;
        self.download(&project, metadata, None, None).await
    }

    async fn resolve_pinned(
        &self,
        skill_id: &str,
        source_commit: &str,
        content_sha256: &str,
    ) -> box_core::Result<SkillPackage> {
        let name = validate_skill_id(skill_id)?;
        let project = Self::project(
            skill_id
                .rsplit_once('/')
                .map(|(project, _)| project)
                .ok_or_else(|| DomainError::validation("invalid skill id"))?,
        )?;
        let metadata = self
            .list_metadata(&project)
            .await?
            .into_iter()
            .find(|skill| skill.name == name)
            .ok_or_else(Self::not_found)?;
        self.download(
            &project,
            metadata,
            Some(source_commit),
            Some(content_sha256),
        )
        .await
    }

    async fn resolve_project(&self, project: &str) -> box_core::Result<Vec<SkillPackage>> {
        let project = Self::project(project)?;
        let metadata = self.list_metadata(&project).await?;
        if metadata.is_empty() {
            return Err(Self::not_found());
        }
        let mut packages = Vec::with_capacity(metadata.len());
        for skill in metadata {
            packages.push(self.download(&project, skill, None, None).await?);
        }
        Ok(packages)
    }
}

fn validate_relative_path(path: &str) -> box_core::Result<()> {
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.as_bytes().contains(&0)
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(Context7Catalog::unavailable("invalid skill file path"));
    }
    Ok(())
}

fn validate_frontmatter_name(content: &[u8], expected: &str) -> box_core::Result<()> {
    let content = std::str::from_utf8(content)
        .map_err(|_| Context7Catalog::unavailable("SKILL.md is not UTF-8"))?;
    let mut lines = content.lines();
    if lines.next() != Some("---") {
        return Err(Context7Catalog::unavailable(
            "SKILL.md frontmatter is missing",
        ));
    }
    let mut name = None;
    for line in lines {
        if line == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix("name:") {
            name = Some(value.trim().trim_matches(['\'', '"']));
        }
    }
    if name != Some(expected) {
        return Err(Context7Catalog::unavailable("SKILL.md name mismatch"));
    }
    Ok(())
}

fn package_digest(files: &[SkillPackageFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update((file.path.len() as u64).to_be_bytes());
        hasher.update(file.path.as_bytes());
        hasher.update((file.content.len() as u64).to_be_bytes());
        hasher.update(&file.content);
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_paths_frontmatter_and_stable_digest() {
        validate_relative_path("references/guide.md").unwrap();
        assert!(validate_relative_path("../escape").is_err());
        validate_frontmatter_name(
            b"---\nname: safe-skill\ndescription: ok\n---\n",
            "safe-skill",
        )
        .unwrap();
        assert!(validate_frontmatter_name(b"---\nname: other\n---\n", "safe-skill").is_err());
        let files = vec![SkillPackageFile {
            path: "SKILL.md".into(),
            content: b"content".to_vec(),
        }];
        assert_eq!(package_digest(&files), package_digest(&files));
    }

    #[test]
    fn accepts_only_matching_context7_github_skill_sources() {
        let location = Context7Catalog::github_location(
            "https://raw.githubusercontent.com/upstash/context7/refs/heads/master/skills/context7-cli/SKILL.md",
            "/upstash/context7",
        )
        .unwrap();
        assert_eq!(location.owner, "upstash");
        assert_eq!(location.repo, "context7");
        assert_eq!(location.directory, "skills/context7-cli");
        assert!(Context7Catalog::github_location(
            "https://raw.githubusercontent.com/attacker/context7/refs/heads/master/skills/context7-cli/SKILL.md",
            "/upstash/context7",
        )
        .is_err());
        assert!(
            Context7Catalog::github_location(
                "https://example.com/upstash/context7/skills/context7-cli/SKILL.md",
                "/upstash/context7",
            )
            .is_err()
        );
        assert_eq!(
            Context7Catalog::project("upstash/context7").unwrap(),
            "/upstash/context7"
        );
        assert!(Context7Catalog::project("upstash/context7/extra").is_err());
    }
}
