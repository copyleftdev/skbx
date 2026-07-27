use anyhow::{Context, Result, bail};
use file_rotate::{ContentLimit, FileRotate, compression::Compression, suffix::AppendCount};
use skbx_contract::{
    CONTRACT_VERSION, CaptureEnd, CaptureSegmentEnd, CaptureSegmentStart, CaptureStart, Envelope,
    Reliability, StopReason, TraceEvent,
};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const MIN_ROTATION_BYTES: u64 = 64 * 1024;
const FOOTER_RESERVE_BYTES: u64 = 1024;
const BUFFER_BYTES: usize = 256 * 1024;

pub struct SegmentedTraceWriter {
    writer: BufWriter<FileRotate<AppendCount>>,
    path: PathBuf,
    start: CaptureStart,
    max_bytes: u64,
    current_bytes: u64,
    segment_index: u32,
    segment_first_seq: u64,
    segment_events: u64,
    max_age: Option<Duration>,
}

impl SegmentedTraceWriter {
    pub fn new(
        path: &Path,
        start: &CaptureStart,
        max_bytes: u64,
        max_backups: u32,
        max_age_days: u32,
        compress: bool,
    ) -> Result<Self> {
        if max_bytes < MIN_ROTATION_BYTES {
            bail!("--output-max-bytes must be at least {MIN_ROTATION_BYTES}");
        }
        if max_backups == 0 {
            bail!("--output-max-backups must be greater than zero when rotation is enabled");
        }
        let path = normalized_path(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create output directory {}", parent.display()))?;
        }
        let max_age = (max_age_days != 0)
            .then(|| Duration::from_secs(u64::from(max_age_days) * 24 * 60 * 60));
        prune_expired_segments(&path, max_age)?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("create output {}", path.display()))?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(true);
        let rotation = FileRotate::new(
            &path,
            AppendCount::new(max_backups as usize),
            ContentLimit::None,
            if compress {
                Compression::OnRotate(0)
            } else {
                Compression::None
            },
            Some(options),
        );
        let mut output = Self {
            writer: BufWriter::with_capacity(BUFFER_BYTES, rotation),
            path,
            start: start.clone(),
            max_bytes,
            current_bytes: 0,
            segment_index: 0,
            segment_first_seq: 0,
            segment_events: 0,
            max_age,
        };
        let header = output.header_bytes(0, 0)?;
        output.ensure_segment_capacity(header.len(), 0)?;
        output.write_bytes(&header)?;
        output
            .writer
            .flush()
            .context("flush initial trace segment header")?;
        Ok(output)
    }

    pub fn write_event(
        &mut self,
        event: &TraceEvent,
        reliability_at_boundary: impl FnOnce() -> Result<Reliability>,
    ) -> Result<()> {
        let expected = self.segment_first_seq.saturating_add(self.segment_events);
        if event.seq != expected {
            bail!(
                "segmented output expected event seq {expected}, found {}",
                event.seq
            );
        }
        let bytes = envelope_bytes(&Envelope::Event(event.clone()))?;
        if self.current_bytes + bytes.len() as u64 + FOOTER_RESERVE_BYTES > self.max_bytes {
            if self.segment_events == 0 {
                bail!(
                    "event {} cannot fit within --output-max-bytes {}",
                    event.seq,
                    self.max_bytes
                );
            }
            let next_index = self
                .segment_index
                .checked_add(1)
                .context("trace segment index exceeds u32")?;
            let next_header = self.header_bytes(next_index, event.seq)?;
            self.ensure_segment_capacity(next_header.len(), bytes.len())?;
            let reliability = reliability_at_boundary()?;
            self.finish_segment(reliability, StopReason::Rotation, Some(event.seq))?;
            self.writer.flush().context("flush rotated trace segment")?;
            self.writer
                .get_mut()
                .rotate()
                .context("rotate trace segment")?;
            prune_expired_segments(&self.path, self.max_age)?;
            self.segment_index = next_index;
            self.segment_first_seq = event.seq;
            self.segment_events = 0;
            self.current_bytes = 0;
            self.write_bytes(&next_header)?;
        }
        self.write_bytes(&bytes)?;
        self.segment_events += 1;
        Ok(())
    }

    pub fn finish(
        mut self,
        final_end: &CaptureEnd,
        segment_reliability: Reliability,
    ) -> Result<()> {
        self.finish_segment(segment_reliability, final_end.stop_reason.clone(), None)?;
        self.writer.flush().context("flush final trace segment")
    }

    fn header_bytes(&self, index: u32, first_seq: u64) -> Result<Vec<u8>> {
        let mut start = self.start.clone();
        start.segment = Some(CaptureSegmentStart { index, first_seq });
        envelope_bytes(&Envelope::CaptureStart(start))
    }

    fn finish_segment(
        &mut self,
        reliability: Reliability,
        stop_reason: StopReason,
        next_seq: Option<u64>,
    ) -> Result<()> {
        let end = CaptureEnd {
            schema: CONTRACT_VERSION.into(),
            capture_id: self.start.capture_id.clone(),
            events: self.segment_events,
            complete: reliability.complete(),
            reliability,
            stop_reason,
            segment: Some(CaptureSegmentEnd {
                index: self.segment_index,
                first_seq: self.segment_first_seq,
                next_seq,
            }),
        };
        let bytes = envelope_bytes(&Envelope::CaptureEnd(end))?;
        if self.current_bytes + bytes.len() as u64 > self.max_bytes {
            bail!(
                "trace segment footer exceeds --output-max-bytes {}",
                self.max_bytes
            );
        }
        self.write_bytes(&bytes)
    }

    fn ensure_segment_capacity(&self, header_len: usize, event_len: usize) -> Result<()> {
        let required = header_len as u64 + event_len as u64 + FOOTER_RESERVE_BYTES;
        if required > self.max_bytes {
            bail!(
                "trace header and event require {required} bytes, exceeding --output-max-bytes {}",
                self.max_bytes
            );
        }
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer
            .write_all(bytes)
            .context("write trace segment")?;
        self.current_bytes += bytes.len() as u64;
        Ok(())
    }
}

fn envelope_bytes(envelope: &Envelope) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    serde_json::to_writer(&mut bytes, envelope).context("serialize trace envelope")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn normalized_path(path: &Path) -> PathBuf {
    if path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        path.to_owned()
    } else {
        Path::new(".").join(path)
    }
}

fn prune_expired_segments(path: &Path, max_age: Option<Duration>) -> Result<()> {
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .context("rotation age exceeds the system clock range")?;
    prune_segments_before(path, cutoff)
}

fn prune_segments_before(path: &Path, cutoff: SystemTime) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("rotating output path has no file name")?
        .to_string_lossy();
    let prefix = format!("{file_name}.");
    for entry in std::fs::read_dir(parent)
        .with_context(|| format!("scan rotated segments in {}", parent.display()))?
    {
        let entry = entry.with_context(|| format!("read entry in {}", parent.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name.strip_prefix(&prefix) else {
            continue;
        };
        let suffix = suffix.strip_suffix(".gz").unwrap_or(suffix);
        if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) || suffix == "0" {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("inspect rotated segment {}", entry.path().display()))?;
        if metadata.is_file()
            && metadata
                .modified()
                .with_context(|| format!("read mtime for {}", entry.path().display()))?
                < cutoff
        {
            std::fs::remove_file(entry.path())
                .with_context(|| format!("remove expired segment {}", entry.path().display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use skbx_contract::{
        CaptureFilters, CaptureLimits, FunctionRef, MatchOrigin, PacketMeta, TraceEvent,
    };
    use std::io::Cursor;

    fn start() -> CaptureStart {
        CaptureStart {
            schema: CONTRACT_VERSION.into(),
            capture_id: "segmented".into(),
            started_unix_ns: 1,
            started_monotonic_ns: 2,
            kernel_release: "test".into(),
            probes: vec!["ip_rcv".into()],
            identity_hooks: Vec::new(),
            attachment_backend: "kprobe".into(),
            timestamp_mode: "none".into(),
            output_tunnel: false,
            metadata_projections: Vec::new(),
            btf_dump_types: Vec::new(),
            bpf_programs: Vec::new(),
            segment: None,
            filters: CaptureFilters::default(),
            limits: CaptureLimits {
                duration_seconds: 1,
                max_events: 20,
                route_cache_entries: 16,
            },
        }
    }

    fn event(seq: u64, payload_bytes: usize) -> TraceEvent {
        TraceEvent {
            schema: CONTRACT_VERSION.into(),
            capture_id: "segmented".into(),
            seq,
            handle: format!("event:{seq:024x}"),
            timestamp_ns: seq + 10,
            presentation_timestamp: None,
            cpu: 0,
            pid: 1,
            command: "x".repeat(payload_bytes),
            skb: format!("0x{:x}", seq + 1),
            identity: format!("0x{:x}", seq + 1),
            function: FunctionRef {
                address: "0x1000".into(),
                symbol: Some("ip_rcv".into()),
            },
            association: Default::default(),
            match_origin: MatchOrigin::Filter,
            caller: None,
            stack: Vec::new(),
            parameters: ["0x0".into(), "0x0".into()],
            drop_reason: None,
            bpf_map: None,
            metadata: Vec::new(),
            btf_dumps: Vec::new(),
            bpf_program: None,
            bpf_program_phase: None,
            bpf_program_action: None,
            packet: PacketMeta::default(),
            tuple: None,
            tunnel_tuple: None,
        }
    }

    fn final_end(events: u64) -> CaptureEnd {
        CaptureEnd {
            schema: CONTRACT_VERSION.into(),
            capture_id: "segmented".into(),
            events,
            reliability: Reliability::default(),
            complete: true,
            stop_reason: StopReason::EventLimit,
            segment: None,
        }
    }

    #[test]
    fn retained_segments_are_bounded_and_independently_replayable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let mut writer =
            SegmentedTraceWriter::new(&path, &start(), MIN_ROTATION_BYTES, 2, 0, false).unwrap();
        for seq in 0..10 {
            writer
                .write_event(&event(seq, 22_000), || Ok(Reliability::default()))
                .unwrap();
        }
        writer
            .finish(&final_end(10), Reliability::default())
            .unwrap();

        let paths = [
            path.clone(),
            path.with_extension("jsonl.1"),
            path.with_extension("jsonl.2"),
        ];
        for path in paths {
            let bytes = std::fs::read(&path).unwrap();
            assert!(bytes.len() as u64 <= MIN_ROTATION_BYTES);
            let summary = skbx_core::replay(Cursor::new(bytes)).unwrap();
            assert!(summary.complete);
            assert!(summary.events > 0);
            assert!(summary.segment.is_some());
        }
        assert!(!path.with_extension("jsonl.3").exists());
    }

    #[test]
    fn rotated_segments_can_be_gzip_compressed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        let mut writer =
            SegmentedTraceWriter::new(&path, &start(), MIN_ROTATION_BYTES, 2, 0, true).unwrap();
        for seq in 0..3 {
            writer
                .write_event(&event(seq, 40_000), || Ok(Reliability::default()))
                .unwrap();
        }
        writer
            .finish(&final_end(3), Reliability::default())
            .unwrap();

        assert_eq!(
            &std::fs::read(path.with_extension("jsonl.1.gz")).unwrap()[..2],
            &[0x1f, 0x8b]
        );
        assert!(
            skbx_core::replay(crate::open_trace(&path.with_extension("jsonl.1.gz")).unwrap())
                .is_ok()
        );
        assert!(skbx_core::replay(Cursor::new(std::fs::read(path).unwrap())).is_ok());
    }

    #[test]
    fn age_pruning_targets_only_numeric_rotated_siblings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        std::fs::write(&path, b"active").unwrap();
        std::fs::write(path.with_extension("jsonl.1"), b"old").unwrap();
        std::fs::write(path.with_extension("jsonl.2.gz"), b"old").unwrap();
        std::fs::write(path.with_extension("jsonl.backup"), b"unrelated").unwrap();

        prune_segments_before(&path, SystemTime::now() + Duration::from_secs(1)).unwrap();

        assert!(path.exists());
        assert!(!path.with_extension("jsonl.1").exists());
        assert!(!path.with_extension("jsonl.2.gz").exists());
        assert!(path.with_extension("jsonl.backup").exists());
    }
}
