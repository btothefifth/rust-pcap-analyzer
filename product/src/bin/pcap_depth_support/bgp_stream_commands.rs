//! Incremental source/evidence commands for the opt-in depth executable.
use super::{parse_peer_relationship, usage};
use pcap_evidence::{json::Json, Error, Result};
use pcap_evidence_product::deep::{self, bgp_mrt_stream_store::MrtStreamLimits, Limits};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

fn new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn write_json(path: &Path, value: Json) -> Result<()> {
    let mut file = new_file(path)?;
    file.write_all(value.encode_bounded_line(1024 * 1024)?.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn publish_link(workspace: &Path, name: &str) -> Result<()> {
    // Retain both links monotonically. They share storage, and publication
    // never deletes a pathname or turns a completed manifest into an unlink
    // error. Inspection/retirement remains an explicit workspace-owner action.
    let partial = workspace.join(format!("{name}.partial"));
    fs::hard_link(&partial, workspace.join(name))?;
    Ok(())
}

fn validate_storage(limits: &MrtStreamLimits) -> Result<()> {
    limits.validate()?;
    // Explicit admission for this command family, including input/store and
    // bounded export coexistence. This is not a filesystem quota.
    if limits.source_bytes == 0
        || limits.source_bytes > 8 * 1024 * 1024 * 1024
        || limits.store_bytes == 0
        || limits.store_bytes > 16 * 1024 * 1024 * 1024
        || limits.records == 0
        || limits.records > 10_000_000
        || limits.record_bytes == 0
        || limits.record_bytes > 16 * 1024 * 1024
        || limits.work == 0
        || limits.work > 1024 * 1024 * 1024 * 1024
        || limits.output_bytes == 0
        || limits.output_bytes > 256 * 1024 * 1024
    {
        return Err(usage());
    }
    Ok(())
}

pub(super) fn import(v: &[String]) -> Result<()> {
    let input = PathBuf::from(v.get(2).ok_or_else(usage)?);
    let mut workspace = None;
    let mut source_id = None;
    let mut checkpoint_id = None;
    let mut limits = MrtStreamLimits {
        output_bytes: 64 * 1024 * 1024,
        ..MrtStreamLimits::default()
    };
    let mut seen = BTreeSet::new();
    let mut at = 3;
    while at < v.len() {
        let flag = v[at].as_str();
        if !seen.insert(flag) {
            return Err(usage());
        }
        let value = v.get(at + 1).ok_or_else(usage)?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--source-id" => source_id = Some(value.clone()),
            "--checkpoint" => checkpoint_id = Some(value.clone()),
            "--max-source-bytes" => limits.source_bytes = value.parse().map_err(|_| usage())?,
            "--max-store-bytes" => limits.store_bytes = value.parse().map_err(|_| usage())?,
            "--max-record-bytes" => limits.record_bytes = value.parse().map_err(|_| usage())?,
            "--max-records" => limits.records = value.parse().map_err(|_| usage())?,
            "--max-work" => limits.work = value.parse().map_err(|_| usage())?,
            _ => return Err(usage()),
        }
        at += 2;
    }
    validate_storage(&limits)?;
    let source = deep::bgp_mrt::MrtSource {
        source_id: source_id.ok_or_else(usage)?,
        checkpoint_id: checkpoint_id.ok_or_else(usage)?,
    };
    let workspace = workspace.ok_or_else(usage)?;
    let file = File::open(input)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limits.source_bytes {
        return Err(Error::limit("mrt_stream_source"));
    }
    fs::create_dir(&workspace)?;
    let output = new_file(&workspace.join("bgp.mrt-stream.partial"))?;
    let mut output = BufWriter::new(output);
    let receipt = deep::bgp_mrt_stream_store::write_stream(
        &mut BufReader::new(file),
        &mut output,
        metadata.len(),
        source,
        &limits,
    )?;
    output.flush()?;
    output.get_ref().sync_all()?;
    write_json(&workspace.join("receipt.json.partial"), receipt.json())?;
    publish_link(&workspace, "bgp.mrt-stream")?;
    publish_link(&workspace, "receipt.json")?;
    Ok(())
}

pub(super) fn export(v: &[String]) -> Result<()> {
    use deep::bgp_evidence::{AsnRole, AsnSelector, EvidenceLimits, TimeBasis, WindowQuery};
    let mut paths = vec![PathBuf::from(v.get(2).ok_or_else(usage)?)];
    let mut workspace = None;
    let mut stream = MrtStreamLimits {
        output_bytes: 64 * 1024 * 1024,
        ..MrtStreamLimits::default()
    };
    let mut evidence = EvidenceLimits {
        output_bytes: 64 * 1024 * 1024,
        ..EvidenceLimits::default()
    };
    let mut relationship = None;
    let mut asn = None;
    let mut role = None;
    let mut basis = None;
    let mut scope = None;
    let mut start = None;
    let mut end = None;
    let mut seen = BTreeSet::new();
    let mut at = 3;
    while at < v.len() {
        let flag = v[at].as_str();
        if flag != "--with-store" && !seen.insert(flag) {
            return Err(usage());
        }
        let value = v.get(at + 1).ok_or_else(usage)?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--with-store" => {
                if paths.len() >= evidence.checkpoints {
                    return Err(Error::limit("bgp_evidence_checkpoints"));
                }
                paths.push(PathBuf::from(value));
            }
            "--peer-relationship" => relationship = Some(parse_peer_relationship(value)?),
            "--max-source-bytes" => stream.source_bytes = value.parse().map_err(|_| usage())?,
            "--max-store-bytes" => stream.store_bytes = value.parse().map_err(|_| usage())?,
            "--max-record-bytes" => stream.record_bytes = value.parse().map_err(|_| usage())?,
            "--max-records" => stream.records = value.parse().map_err(|_| usage())?,
            "--max-work" => stream.work = value.parse().map_err(|_| usage())?,
            "--max-output-bytes" => {
                stream.output_bytes = value.parse().map_err(|_| usage())?;
                evidence.output_bytes =
                    usize::try_from(stream.output_bytes).map_err(|_| usage())?;
            }
            "--asn" => asn = Some(value.parse::<u32>().map_err(|_| usage())?),
            "--asn-role" => {
                role = Some(match value.as_str() {
                    "origin" => AsnRole::Origin,
                    "path-member" => AsnRole::PathMember,
                    _ => return Err(usage()),
                })
            }
            "--time-basis" => {
                basis = Some(match value.as_str() {
                    "mrt-record" => TimeBasis::MrtRecordTime,
                    "rib-originated" => TimeBasis::RibOriginatedTime,
                    "observation" => TimeBasis::ObservationTime,
                    _ => return Err(usage()),
                })
            }
            "--clock-scope" => scope = Some(value.clone()),
            "--start-ns" => start = Some(value.parse::<i128>().map_err(|_| usage())?),
            "--end-ns" => end = Some(value.parse::<i128>().map_err(|_| usage())?),
            _ => return Err(usage()),
        }
        at += 2;
    }
    validate_storage(&stream)?;
    evidence.source_bytes = stream.source_bytes;
    evidence.store_bytes = stream.store_bytes;
    evidence.work = stream.work;
    if evidence.output_bytes == 0 || evidence.output_bytes > 256 * 1024 * 1024 {
        return Err(usage());
    }
    let selector = if v[1] == "window" {
        let start_ns = start.ok_or_else(usage)?;
        let end_ns = end.ok_or_else(usage)?;
        if start_ns >= end_ns {
            return Err(usage());
        }
        Some(WindowQuery {
            asn: Some(AsnSelector {
                asn: asn.ok_or_else(usage)?,
                role: role.ok_or_else(usage)?,
            }),
            time_basis: basis.ok_or_else(usage)?,
            clock_scope: scope.filter(|v| !v.trim().is_empty()).ok_or_else(usage)?,
            start_ns,
            end_ns,
        })
    } else {
        if asn.is_some()
            || role.is_some()
            || basis.is_some()
            || scope.is_some()
            || start.is_some()
            || end.is_some()
        {
            return Err(usage());
        }
        None
    };
    let workspace = workspace.ok_or_else(usage)?;
    fs::create_dir(&workspace)?;
    let mut output = BufWriter::new(new_file(&workspace.join("evidence.ndjson.partial"))?);
    let limits = Limits {
        input_bytes: stream.record_bytes,
        ..Limits::default()
    };
    let manifest = deep::bgp_evidence::export_sequence(
        &paths,
        &stream,
        &limits,
        &evidence,
        &deep::bgp_mrt_store::MrtReplayOptions {
            peer_relationship: relationship,
        },
        selector.as_ref(),
        &mut output,
    )?;
    output.flush()?;
    output.get_ref().sync_all()?;
    write_json(
        &workspace.join("sequence.json.partial"),
        manifest.sequence.json(),
    )?;
    write_json(&workspace.join("manifest.json.partial"), manifest.json())?;
    publish_link(&workspace, "evidence.ndjson")?;
    publish_link(&workspace, "sequence.json")?;
    publish_link(&workspace, "manifest.json")?;
    Ok(())
}
