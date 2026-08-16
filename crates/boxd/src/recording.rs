use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use async_trait::async_trait;
use box_browser::BrowserRecording;
use box_core::{DomainError, DomainErrorKind};
use box_service::{BrowserRecordingArtifacts, BrowserRecordingCapture, BrowserRecordingStorage};
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    process::Command,
};

const FRAME_INTERVAL: Duration = Duration::from_millis(100);
const RECORDING_IDLE_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const MAX_PLAYLIST_BYTES: u64 = 1024 * 1024;
const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SEGMENTS: usize = 512;

fn unavailable(message: impl Into<String>) -> DomainError {
    DomainError {
        kind: DomainErrorKind::Unavailable,
        code: "recording_unavailable",
        message: message.into(),
    }
}

fn resolve_executable(raw: &str) -> Result<PathBuf, String> {
    let configured = Path::new(raw);
    let candidate = if configured.is_absolute() {
        configured.to_owned()
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join(configured))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| format!("recording ffmpeg executable '{raw}' was not found in PATH"))?
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|error| format!("cannot resolve recording ffmpeg executable: {error}"))?;
    let metadata = canonical
        .metadata()
        .map_err(|error| format!("cannot inspect recording ffmpeg executable: {error}"))?;
    if !metadata.is_file() {
        return Err("recording ffmpeg path is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o111 == 0 || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
            return Err(
                "recording ffmpeg executable must be executable, non-writable by group/other, and singly linked"
                    .into(),
            );
        }
    }
    Ok(canonical)
}

#[derive(Clone)]
pub struct FfmpegRecordingStorage {
    root: PathBuf,
    ffmpeg: PathBuf,
    max_file_bytes: u64,
    idle_timeout: Duration,
}

impl FfmpegRecordingStorage {
    pub fn new(root: &Path, ffmpeg: &str, max_file_bytes: u64) -> Result<Self, String> {
        if max_file_bytes == 0 {
            return Err("recording file quota must be positive".into());
        }
        std::fs::create_dir_all(root).map_err(|error| {
            format!(
                "cannot create recording storage {}: {error}",
                root.display()
            )
        })?;
        let root = root
            .canonicalize()
            .map_err(|error| format!("cannot resolve recording storage: {error}"))?;
        if !root.is_dir() {
            return Err("recording storage is not a directory".into());
        }
        Ok(Self {
            root,
            ffmpeg: resolve_executable(ffmpeg)?,
            max_file_bytes,
            idle_timeout: RECORDING_IDLE_TIMEOUT,
        })
    }

    fn directory(&self, recording: &BrowserRecording) -> PathBuf {
        self.root
            .join(recording.account_id.to_string())
            .join(recording.tenant_id.to_string())
            .join(recording.box_id.to_string())
            .join(recording.id.to_string())
    }

    fn relative_directory(&self, recording: &BrowserRecording) -> PathBuf {
        PathBuf::from(recording.account_id.to_string())
            .join(recording.tenant_id.to_string())
            .join(recording.box_id.to_string())
            .join(recording.id.to_string())
    }

    async fn checked_read(
        &self,
        recording: &BrowserRecording,
        expected_relative: Option<&str>,
        fallback_name: &str,
        max_bytes: u64,
    ) -> box_core::Result<Vec<u8>> {
        let directory = self.directory(recording);
        let expected = self.relative_directory(recording).join(fallback_name);
        let relative = expected_relative
            .map(PathBuf::from)
            .unwrap_or_else(|| expected.clone());
        if relative != expected {
            return Err(unavailable("recording artifact identity is invalid"));
        }
        let path = self.root.join(&relative);
        let canonical = path
            .canonicalize()
            .map_err(|_| unavailable("recording artifact is missing"))?;
        let canonical_directory = directory
            .canonicalize()
            .map_err(|_| unavailable("recording directory is missing"))?;
        if canonical.parent() != Some(canonical_directory.as_path()) {
            return Err(unavailable("recording artifact escaped its directory"));
        }
        let metadata = canonical
            .metadata()
            .map_err(|_| unavailable("recording artifact metadata is unavailable"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(unavailable("recording artifact identity is invalid"));
            }
        }
        if metadata.len() == 0 || metadata.len() > max_bytes {
            return Err(unavailable("recording artifact exceeds its size limit"));
        }
        tokio::fs::read(canonical)
            .await
            .map_err(|_| unavailable("recording artifact read failed"))
    }

    async fn run_remux(&self, playlist: &Path, mp4: &Path) -> bool {
        let mut command = Command::new(&self.ffmpeg);
        command
            .args(["-hide_banner", "-loglevel", "error", "-y", "-i"])
            .arg(playlist)
            .args(["-c", "copy", "-movflags", "+faststart"])
            .arg(mp4)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        tokio::time::timeout(Duration::from_secs(90), child.wait())
            .await
            .is_ok_and(|result| result.is_ok_and(|status| status.success()))
    }

    async fn abort_encoder(child: &mut tokio::process::Child, staging: &Path) {
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        let _ = tokio::fs::remove_dir_all(staging).await;
    }
}

#[async_trait]
impl BrowserRecordingStorage for FfmpegRecordingStorage {
    async fn capture(
        &self,
        mut request: BrowserRecordingCapture,
    ) -> box_core::Result<BrowserRecordingArtifacts> {
        let relative = PathBuf::from(request.context.account_id.to_string())
            .join(request.context.tenant_id.to_string())
            .join(request.box_id.to_string())
            .join(request.recording_id.to_string());
        let final_directory = self.root.join(&relative);
        if final_directory.exists() {
            return Err(unavailable("recording destination already exists"));
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| unavailable("recording staging randomness unavailable"))?;
        let staging = final_directory.with_extension(format!("tmp-{}", hex::encode(random)));
        tokio::fs::create_dir_all(&staging)
            .await
            .map_err(|_| unavailable("recording staging creation failed"))?;
        let playlist = staging.join("playlist.m3u8");
        let segment_pattern = staging.join("segment-%05d.ts");
        let mut command = Command::new(&self.ffmpeg);
        command
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-f",
                "image2pipe",
                "-framerate",
                "10",
                "-vcodec",
                "mjpeg",
                "-i",
                "pipe:0",
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "veryfast",
                "-vf",
                "scale=trunc(iw/2)*2:trunc(ih/2)*2",
                "-pix_fmt",
                "yuv420p",
                "-g",
                "20",
                "-keyint_min",
                "20",
                "-sc_threshold",
                "0",
                "-f",
                "hls",
                "-hls_time",
                "2",
                "-hls_list_size",
                "0",
                "-hls_playlist_type",
                "vod",
                "-hls_segment_filename",
            ])
            .arg(segment_pattern)
            .arg(&playlist)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                let _ = tokio::fs::remove_dir_all(&staging).await;
                return Err(unavailable("recording encoder failed to start"));
            }
        };
        let Some(stdin) = child.stdin.take() else {
            Self::abort_encoder(&mut child, &staging).await;
            return Err(unavailable("recording encoder stdin unavailable"));
        };
        let stderr = child.stderr.take().map(|stderr| {
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let _ = stderr.take(64 * 1024).read_to_end(&mut bytes).await;
                bytes
            })
        });
        let mut input = BufWriter::new(stdin);
        let mut latest = None;
        let mut frame_count = 0_u64;
        let mut ticker = tokio::time::interval(FRAME_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let deadline = tokio::time::sleep(request.max_duration);
        let idle = tokio::time::sleep(self.idle_timeout);
        tokio::pin!(deadline);
        tokio::pin!(idle);
        let reason = loop {
            tokio::select! {
                biased;
                changed = request.stop.changed() => {
                    if changed.is_err() || *request.stop.borrow() {
                        break Ok("requested");
                    }
                }
                _ = &mut deadline => {
                    break Ok("max_duration");
                }
                _ = &mut idle => {
                    break Ok("idle");
                }
                frame = request.frames.next() => match frame {
                    Some(Ok(frame)) => {
                        if frame.len() < 4 || !frame.starts_with(&[0xff, 0xd8]) || !frame.ends_with(&[0xff, 0xd9]) {
                            break Err(unavailable("recording received an invalid JPEG frame"));
                        }
                        latest = Some(frame);
                        idle.as_mut().reset(tokio::time::Instant::now() + self.idle_timeout);
                    }
                    Some(Err(error)) => {
                        break Err(error);
                    }
                    None => {
                        break Ok("browser_disconnected");
                    }
                },
                _ = ticker.tick() => {
                    if let Some(frame) = &latest {
                        match tokio::time::timeout(Duration::from_secs(5), input.write_all(frame)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => break Err(unavailable("recording encoder write failed")),
                            Err(_) => break Err(unavailable("recording encoder write timed out")),
                        }
                        frame_count = frame_count.saturating_add(1);
                    }
                }
            }
        };
        let reason = match reason {
            Ok(reason) => reason,
            Err(error) => {
                drop(input);
                Self::abort_encoder(&mut child, &staging).await;
                return Err(error);
            }
        };
        if input.flush().await.is_err() {
            drop(input);
            Self::abort_encoder(&mut child, &staging).await;
            return Err(unavailable("recording encoder flush failed"));
        }
        drop(input);
        let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => {
                Self::abort_encoder(&mut child, &staging).await;
                return Err(unavailable("recording encoder wait failed"));
            }
            Err(_) => {
                Self::abort_encoder(&mut child, &staging).await;
                return Err(unavailable("recording encoder shutdown timed out"));
            }
        };
        let stderr = match stderr {
            Some(stderr) => stderr.await.unwrap_or_default(),
            None => Vec::new(),
        };
        if frame_count == 0 {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(unavailable("recording received no browser frames"));
        }
        if !status.success() {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            let detail = String::from_utf8_lossy(&stderr)
                .lines()
                .take(4)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(unavailable(if detail.is_empty() {
                "recording encoder exited unsuccessfully".into()
            } else {
                format!("recording encoder exited unsuccessfully: {detail}")
            }));
        }

        let mut segments = Vec::new();
        let mut entries = tokio::fs::read_dir(&staging)
            .await
            .map_err(|_| unavailable("recording output scan failed"))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|_| unavailable("recording output scan failed"))?
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("segment-") && name.ends_with(".ts") {
                segments.push(entry.path());
            }
        }
        segments.sort();
        if segments.is_empty() || segments.len() > MAX_SEGMENTS {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(unavailable("recording segment count is invalid"));
        }
        let transport_stream = staging.join("recording.ts");
        let mut transport_output = BufWriter::new(
            tokio::fs::File::create(&transport_stream)
                .await
                .map_err(|_| unavailable("recording transport stream creation failed"))?,
        );
        let mut hls_size = tokio::fs::metadata(&playlist)
            .await
            .map_err(|_| unavailable("recording playlist is missing"))?
            .len();
        for segment in &segments {
            let metadata = tokio::fs::metadata(segment)
                .await
                .map_err(|_| unavailable("recording segment metadata failed"))?;
            if metadata.len() == 0 || metadata.len() > MAX_SEGMENT_BYTES {
                let _ = tokio::fs::remove_dir_all(&staging).await;
                return Err(unavailable("recording segment exceeds its size limit"));
            }
            hls_size = hls_size
                .checked_add(metadata.len())
                .ok_or_else(|| unavailable("recording size overflow"))?;
            if hls_size > self.max_file_bytes / 2 {
                let _ = tokio::fs::remove_dir_all(&staging).await;
                return Err(unavailable("recording exceeds its file quota"));
            }
            let mut input = tokio::fs::File::open(segment)
                .await
                .map_err(|_| unavailable("recording segment read failed"))?;
            tokio::io::copy(&mut input, &mut transport_output)
                .await
                .map_err(|_| unavailable("recording transport stream assembly failed"))?;
        }
        transport_output
            .flush()
            .await
            .map_err(|_| unavailable("recording transport stream flush failed"))?;
        drop(transport_output);
        let mp4 = staging.join("recording.mp4");
        let mp4_ok = self.run_remux(&playlist, &mp4).await;
        let mp4_size = if mp4_ok {
            let size = tokio::fs::metadata(&mp4)
                .await
                .map_err(|_| unavailable("recording MP4 metadata failed"))?
                .len();
            if size == 0 || size > self.max_file_bytes {
                let _ = tokio::fs::remove_file(&mp4).await;
                None
            } else {
                Some(size)
            }
        } else {
            let _ = tokio::fs::remove_file(&mp4).await;
            None
        };
        let download_size = if let Some(size) = mp4_size {
            tokio::fs::remove_file(&transport_stream)
                .await
                .map_err(|_| unavailable("recording transport stream cleanup failed"))?;
            size
        } else {
            tokio::fs::metadata(&transport_stream)
                .await
                .map_err(|_| unavailable("recording transport stream metadata failed"))?
                .len()
        };
        let total_size = hls_size
            .checked_add(download_size)
            .ok_or_else(|| unavailable("recording size overflow"))?;
        if total_size > self.max_file_bytes {
            let _ = tokio::fs::remove_dir_all(&staging).await;
            return Err(unavailable("recording exceeds its file quota"));
        }
        tokio::fs::rename(&staging, &final_directory)
            .await
            .map_err(|_| unavailable("recording publication failed"))?;
        let playlist_path = relative.join("playlist.m3u8");
        let download_path = relative.join(if mp4_size.is_some() {
            "recording.mp4"
        } else {
            "recording.ts"
        });
        Ok(BrowserRecordingArtifacts {
            playlist_path: playlist_path.to_string_lossy().into_owned(),
            download_path: Some(download_path.to_string_lossy().into_owned()),
            size_bytes: total_size,
            segment_count: u32::try_from(segments.len())
                .map_err(|_| unavailable("recording segment count overflow"))?,
            mp4_size_bytes: mp4_size,
            stopped_reason: reason.into(),
        })
    }

    async fn read_playlist(&self, recording: &BrowserRecording) -> box_core::Result<Vec<u8>> {
        self.checked_read(
            recording,
            recording.playlist_path.as_deref(),
            "playlist.m3u8",
            MAX_PLAYLIST_BYTES,
        )
        .await
    }

    async fn read_segment(
        &self,
        recording: &BrowserRecording,
        segment: &str,
    ) -> box_core::Result<Vec<u8>> {
        box_browser::validate_recording_segment_name(segment)?;
        let relative = self
            .relative_directory(recording)
            .join(segment)
            .to_string_lossy()
            .into_owned();
        self.checked_read(recording, Some(&relative), segment, self.max_file_bytes)
            .await
    }

    async fn read_download(
        &self,
        recording: &BrowserRecording,
    ) -> box_core::Result<(Vec<u8>, bool)> {
        let mp4 = recording.mp4_size_bytes.is_some();
        let name = if mp4 { "recording.mp4" } else { "recording.ts" };
        self.checked_read(
            recording,
            recording.download_path.as_deref(),
            name,
            self.max_file_bytes,
        )
        .await
        .map(|bytes| (bytes, mp4))
    }

    async fn delete(&self, recording: &BrowserRecording) -> box_core::Result<()> {
        let directory = self.directory(recording);
        if !directory.exists() {
            return Ok(());
        }
        let canonical = directory
            .canonicalize()
            .map_err(|_| unavailable("recording cleanup path is invalid"))?;
        if !canonical.starts_with(&self.root) || canonical == self.root {
            return Err(unavailable("recording cleanup escaped its root"));
        }
        tokio::fs::remove_dir_all(canonical)
            .await
            .map_err(|_| unavailable("recording cleanup failed"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use box_browser::BrowserRecording;
    use box_core::{AccountContext, AccountId, BoxId, TenantId, UtcEpochMillis};
    use futures_util::stream;
    use std::{os::unix::fs::PermissionsExt, sync::Arc};
    use tokio::sync::watch;

    #[tokio::test]
    async fn bounded_capture_publishes_playlist_and_mp4_under_scoped_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let ffmpeg = temporary.path().join("fixture-ffmpeg");
        std::fs::write(
            &ffmpeg,
            r#"#!/bin/sh
last=""
for value in "$@"; do last="$value"; done
case " $* " in
  *" -f hls "*)
    cat >/dev/null
    directory=$(dirname "$last")
    printf '#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:1.0,\nsegment-00000.ts\n#EXT-X-ENDLIST\n' > "$last"
    printf 'fixture-ts' > "$directory/segment-00000.ts"
    ;;
  *) printf 'fixture-mp4' > "$last" ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&ffmpeg, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = temporary.path().join("recordings");
        let mut storage =
            FfmpegRecordingStorage::new(&root, ffmpeg.to_str().unwrap(), 1024 * 1024).unwrap();
        storage.idle_timeout = Duration::from_millis(150);
        let context = AccountContext {
            account_id: AccountId::new(),
            tenant_id: TenantId::new(),
        };
        let box_id = BoxId::new();
        let mut recording =
            BrowserRecording::new(context, box_id, 10, UtcEpochMillis::from_millis(1)).unwrap();
        let (_stop, receiver) = watch::channel(false);
        let artifacts = storage
            .capture(BrowserRecordingCapture {
                context,
                box_id,
                recording_id: recording.id,
                frames: Box::pin(
                    stream::iter(vec![Ok(vec![0xff, 0xd8, 1, 2, 0xff, 0xd9])])
                        .chain(stream::pending()),
                ),
                stop: receiver,
                max_duration: Duration::from_secs(2),
                markers: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            })
            .await
            .unwrap();
        assert_eq!(artifacts.segment_count, 1);
        assert_eq!(artifacts.stopped_reason, "idle");
        assert_eq!(artifacts.mp4_size_bytes, Some(11));
        recording.playlist_path = Some(artifacts.playlist_path);
        recording.download_path = artifacts.download_path;
        recording.mp4_size_bytes = artifacts.mp4_size_bytes;
        assert!(
            String::from_utf8(storage.read_playlist(&recording).await.unwrap())
                .unwrap()
                .contains("segment-00000.ts")
        );
        let (download, mp4) = storage.read_download(&recording).await.unwrap();
        assert!(mp4);
        assert_eq!(download, b"fixture-mp4");
        storage.delete(&recording).await.unwrap();
        assert!(!storage.directory(&recording).exists());
    }
}
