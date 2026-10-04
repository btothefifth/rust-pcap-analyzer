//! Actual opt-in pipeline. Does not change the established pcap-product default.
#![forbid(unsafe_code)]
#[path = "pcap_depth_support/bgp_stream_commands.rs"]
mod bgp_stream_commands;
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256, Error, ErrorCode, Result,
};
use pcap_evidence_product::{
    deep::{self, sink::DeepSink, Context, Limits},
    output::{ByteBudget, ProductSink},
    registry,
};
use pcap_evidence_stream::{analyze_reader, NdjsonSink, StreamConfig};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};
fn usage() -> Error {
    Error::new(ErrorCode::Usage,0,"arguments","pcap-depth bgp import-mrt-stream MRT --workspace NEW_DIR --source-id ID --checkpoint ID [STREAM_LIMITS] | bgp chronology STORE [--with-store STORE] --workspace NEW_DIR [--peer-relationship unknown|internal|external] [STREAM_LIMITS] | bgp window STORE [--with-store STORE] --workspace NEW_DIR --asn N --asn-role origin|path-member --time-basis mrt-record|rib-originated|observation --clock-scope SOURCE_ID|all-source-clocks --start-ns I --end-ns I [STREAM_LIMITS] | analyze CAPTURE --workspace NEW_DIR [--format ndjson|tlv] [--ua-security-none] [--max-bgp-journal-bytes N] | decode PROTOCOL UNIT [--function N] [--fcs] [--ua-security-none] | bgp import-mrt MRT --workspace NEW_DIR --source-id ID --checkpoint ID [--peer-relationship unknown|internal|external] [--max-mrt-bytes N] [--max-journal-bytes N] | bgp import-bmp BMP --workspace NEW_DIR --source-id ID --checkpoint ID [--peer-relationship unknown|internal|external] [--max-bmp-bytes N] [--max-journal-bytes N] | bgp policy STORE --policy-profile PROFILE --output NEW_FILE [FILTERS] [--peer-relationship unknown|internal|external] | bgp associate STORE --with-store STORE --comparison-namespace ID --clock-policy same-clock|ignore [--clock-basis BASIS] [--peer-relationship unknown|internal|external] [--other-peer-relationship unknown|internal|external] --output NEW_FILE | bgp replay|state|export STORE --output NEW_FILE [--peer-relationship unknown|internal|external] [--max-journal-bytes N] [--max-output-bytes N] | bgp query STORE --output NEW_FILE [--session ID] [--prefix CIDR] [--afi N] [--safi N] [--peer ID] [--source ID] [--checkpoint ID] [--status active|withdrawn|unresolved|collector_candidate] [--peer-relationship unknown|internal|external] [--max-journal-bytes N] [--max-output-bytes N] | STREAM_LIMITS: --max-source-bytes N --max-store-bytes N --max-record-bytes N --max-records N --max-work N (exports also --max-output-bytes N)")
}

fn parse_peer_relationship(value: &str) -> Result<deep::bgp::PeerRelationship> {
    match value {
        "unknown" => Ok(deep::bgp::PeerRelationship::Unknown),
        "internal" => Ok(deep::bgp::PeerRelationship::Internal),
        "external" => Ok(deep::bgp::PeerRelationship::External),
        _ => Err(usage()),
    }
}
fn run(v: &[String]) -> Result<()> {
    if v.len() < 3 {
        return Err(usage());
    }
    let mut context = Context::default();
    let mut i = 3;
    let mut seen = std::collections::BTreeSet::new();
    while i < v.len() {
        if !seen.insert(v[i].as_str()) {
            return Err(usage());
        }
        match v[i].as_str() {
            "--function" => {
                i += 1;
                context.function = v.get(i).ok_or_else(usage)?.parse().map_err(|_| usage())?;
            }
            "--fcs" => context.fcs_present = true,
            "--ua-security-none" => context.ua_security_none = true,
            _ => return Err(usage()),
        }
        i += 1;
    }
    if v[0] == "decode" {
        let file = File::open(&v[2])?;
        if !file.metadata()?.is_file() {
            return Err(usage());
        }
        let l = Limits::default();
        let mut bytes = Vec::new();
        file.take(l.input_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > l.input_bytes {
            return Err(Error::limit("protocol_unit"));
        }
        let raw = EvidenceBytes::from_packet(
            &bytes,
            PacketId {
                capture: sha256::digest(&bytes),
                frame: 1,
                record_offset: 0,
            },
            0,
        );
        let result = deep::decode(&v[1], &raw, &context, &l)?;
        let output = Json::object([
            ("input_domain", "standalone_protocol_unit_not_pcap".into()),
            ("source_sha256", sha256::hex(&sha256::digest(&bytes)).into()),
            ("report", result.json()),
        ]);
        std::io::stdout()
            .lock()
            .write_all(output.encode_bounded_line(l.output_bytes)?.as_bytes())?;
        return Ok(());
    }
    Err(usage())
}
fn analyze(v: &[String]) -> Result<()> {
    if v.len() < 4 || v[0] != "analyze" || v[2] != "--workspace" {
        return Err(usage());
    }
    let workspace = Path::new(&v[3]);
    let input = Path::new(&v[1]);
    let mut context = Context::default();
    let mut format = "ndjson";
    let mut max_index = 1024u64 * 1024 * 1024;
    let mut max_output = 8u64 * 1024 * 1024 * 1024;
    let mut max_bgp_journal = 8u64 * 1024 * 1024 * 1024;
    let mut i = 4;
    let mut seen = std::collections::BTreeSet::new();
    while i < v.len() {
        let flag = v[i].as_str();
        if !seen.insert(flag) {
            return Err(usage());
        }
        match flag {
            "--format" => {
                i += 1;
                format = v.get(i).ok_or_else(usage)?.as_str();
            }
            "--ua-security-none" => context.ua_security_none = true,
            "--max-index-bytes" => {
                i += 1;
                max_index = v.get(i).ok_or_else(usage)?.parse().map_err(|_| usage())?;
            }
            "--max-output-bytes" => {
                i += 1;
                max_output = v.get(i).ok_or_else(usage)?.parse().map_err(|_| usage())?;
            }
            "--max-bgp-journal-bytes" => {
                i += 1;
                max_bgp_journal = v.get(i).ok_or_else(usage)?.parse().map_err(|_| usage())?;
            }
            _ => return Err(usage()),
        }
        i += 1;
    }
    if !["ndjson", "tlv"].contains(&format)
        || max_index < 64
        || max_output == 0
        || max_bgp_journal < 128
    {
        return Err(usage());
    }
    let f = File::open(input)?;
    if !f.metadata()?.is_file() {
        return Err(usage());
    }
    fs::create_dir(workspace)?;
    let out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(workspace.join(if format == "tlv" {
            "events.tlv.partial"
        } else {
            "events.ndjson.partial"
        }))?;
    let mut writer = ByteBudget {
        inner: BufWriter::new(out),
        remaining: max_output,
    };
    let config = StreamConfig {
        max_detectors: 64,
        ..StreamConfig::default()
    };
    let registry = registry::registry(&config, "ics-full")?;
    let mut bgp_receipt = None;
    let result = (|| -> Result<()> {
        if format == "ndjson" {
            let mut output = NdjsonSink::new(&mut writer, "depth", config.max_event_bytes)?;
            {
                let mut sink = DeepSink::new(
                    &mut output,
                    File::open(input)?,
                    &workspace.join("packets.map"),
                    max_index,
                    Limits::default(),
                    context.clone(),
                )?;
                sink.enable_bgp_journal(&workspace.join("bgp.journal.partial"), max_bgp_journal)?;
                let mut product = ProductSink {
                    inner: &mut sink,
                    source: File::open(input)?,
                    packets: 0,
                    maximum: u64::MAX,
                    profile: "ics-full".into(),
                    emitted: 0,
                };
                analyze_reader(BufReader::new(f), config.clone(), &registry, &mut product)?;
                bgp_receipt = sink.finish()?;
            }
            output.finish()?;
        } else {
            #[cfg(feature = "binary")]
            {
                let mut output = pcap_evidence_product::tlv::TlvSink::new(
                    &mut writer,
                    "depth".to_string(),
                    config.max_event_bytes,
                )?;
                {
                    let mut sink = DeepSink::new(
                        &mut output,
                        File::open(input)?,
                        &workspace.join("packets.map"),
                        max_index,
                        Limits::default(),
                        context.clone(),
                    )?;
                    sink.enable_bgp_journal(
                        &workspace.join("bgp.journal.partial"),
                        max_bgp_journal,
                    )?;
                    let mut product = ProductSink {
                        inner: &mut sink,
                        source: File::open(input)?,
                        packets: 0,
                        maximum: u64::MAX,
                        profile: "ics-full".into(),
                        emitted: 0,
                    };
                    analyze_reader(BufReader::new(f), config.clone(), &registry, &mut product)?;
                    bgp_receipt = sink.finish()?;
                }
                output.finish()?;
            }
            #[cfg(not(feature = "binary"))]
            {
                return Err(Error::new(
                    ErrorCode::Usage,
                    0,
                    "feature",
                    "binary feature disabled",
                ));
            }
        }
        writer.flush()?;
        writer.inner.get_ref().sync_all()?;
        Ok(())
    })();
    let status = Json::object([
        ("schema", "pcap-evidence.depth-run.v1".into()),
        (
            "status",
            if result.is_ok() {
                "complete_source_read"
            } else {
                "incomplete"
            }
            .into(),
        ),
        ("all_protocol_gaps_closed", false.into()),
        (
            "source_binding",
            "requires_terminal_event_and_source_verification".into(),
        ),
        (
            "bgp_journal",
            bgp_receipt
                .as_ref()
                .map_or(Json::Null, deep::bgp_store::JournalReceipt::json),
        ),
    ]);
    let receipt_partial = workspace.join("receipt.json.partial");
    let mut manifest = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_partial)?;
    manifest.write_all(status.encode().as_bytes())?;
    manifest.sync_all()?;
    if result.is_ok() {
        let name = if format == "tlv" {
            "events.tlv"
        } else {
            "events.ndjson"
        };
        fs::hard_link(
            workspace.join(format!("{name}.partial")),
            workspace.join(name),
        )?;
        fs::remove_file(workspace.join(format!("{name}.partial")))?;
        fs::hard_link(
            workspace.join("bgp.journal.partial"),
            workspace.join("bgp.journal"),
        )?;
        fs::remove_file(workspace.join("bgp.journal.partial"))?;
    }
    fs::hard_link(&receipt_partial, workspace.join("receipt.json"))?;
    fs::remove_file(receipt_partial)?;
    result
}

fn partial_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".partial");
    PathBuf::from(value)
}

fn publish(
    path: &Path,
    maximum: u64,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let partial = partial_path(path);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    let mut writer = ByteBudget {
        inner: BufWriter::new(file),
        remaining: maximum,
    };
    write(&mut writer)?;
    writer.flush()?;
    writer.inner.get_ref().sync_all()?;
    fs::hard_link(&partial, path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::new(
                ErrorCode::OutputExists,
                0,
                "bgp_output",
                "output already exists",
            )
        } else {
            Error::io(error)
        }
    })?;
    fs::remove_file(partial)?;
    Ok(())
}

const MAX_MRT_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

fn bounded_usize(value: u64, field: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::limit(field))
}

fn scaled(value: usize, multiplier: usize, floor: usize, field: &'static str) -> Result<usize> {
    value
        .checked_mul(multiplier)
        .map(|value| value.max(floor))
        .ok_or_else(|| Error::limit(field))
}

fn mrt_profiles(maximum: u64) -> Result<(deep::bgp_mrt::MrtLimits, Limits)> {
    if maximum == 0 || maximum > MAX_MRT_SOURCE_BYTES {
        return Err(usage());
    }
    let input = bounded_usize(maximum, "bgp_mrt_input")?;
    let records = input.saturating_div(12).saturating_add(1).min(1_000_000);
    let entries = input.saturating_div(8).saturating_add(1).min(1_000_000);
    let output = scaled(input, 32, 16 * 1024 * 1024, "bgp_mrt_output")?;
    let retained = scaled(input, 16, 16 * 1024 * 1024, "bgp_mrt_retained")?;
    let work = scaled(input, 64, 32 * 1024 * 1024, "bgp_mrt_work")?;
    let mrt = deep::bgp_mrt::MrtLimits {
        input_bytes: input,
        records,
        peers: entries,
        rib_entries: entries,
        prefix_bytes: 16,
        path_attributes: 65_535,
        retained_bytes: scaled(input, 8, 8 * 1024 * 1024, "bgp_mrt_retained")?,
        work: scaled(input, 32, 32 * 1024 * 1024, "bgp_mrt_work")?,
        output_bytes: output,
    };
    let state = Limits {
        input_bytes: input.max(1024 * 1024),
        fields: 65_536,
        elements: entries.max(1024),
        depth: 64,
        spans: records.max(4096),
        active: entries.clamp(128, 65_536),
        retained_bytes: retained,
        work,
        output_bytes: output,
    };
    state.validate()?;
    Ok((mrt, state))
}

fn import_mrt(v: &[String]) -> Result<()> {
    if v.len() < 9 || v[0] != "bgp" || v[1] != "import-mrt" {
        return Err(usage());
    }
    let input = PathBuf::from(&v[2]);
    let mut workspace = None;
    let mut source_id = None;
    let mut checkpoint_id = None;
    let mut peer_relationship = None;
    let mut max_mrt = MAX_MRT_SOURCE_BYTES;
    let mut max_store = 128u64 * 1024 * 1024;
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 3;
    while i < v.len() {
        let flag = v[i].as_str();
        if !seen.insert(flag) {
            return Err(usage());
        }
        i += 1;
        let value = v.get(i).ok_or_else(usage)?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--source-id" => source_id = Some(value.clone()),
            "--checkpoint" => checkpoint_id = Some(value.clone()),
            "--peer-relationship" => peer_relationship = Some(parse_peer_relationship(value)?),
            "--max-mrt-bytes" => max_mrt = value.parse().map_err(|_| usage())?,
            "--max-journal-bytes" => max_store = value.parse().map_err(|_| usage())?,
            _ => return Err(usage()),
        }
        i += 1;
    }
    let workspace = workspace.ok_or_else(usage)?;
    let source_id = source_id.ok_or_else(usage)?;
    let checkpoint_id = checkpoint_id.ok_or_else(usage)?;
    let (mrt_limits, limits) = mrt_profiles(max_mrt)?;
    if max_store < 128 {
        return Err(usage());
    }
    let bytes = deep::bgp_mrt_store::read_source(&input, max_mrt)?;
    fs::create_dir(&workspace)?;
    let partial = workspace.join("bgp.mrt.partial");
    let archive = deep::bgp_mrt_store::create_with_options(
        &partial,
        &bytes,
        deep::bgp_mrt::MrtSource {
            source_id,
            checkpoint_id,
        },
        max_store,
        mrt_limits,
        limits,
        deep::bgp_mrt_store::MrtReplayOptions { peer_relationship },
    )?;
    let receipt = Json::object([
        ("schema", "pcap-evidence.bgp.mrt-import-receipt.v2".into()),
        ("store", archive.receipt.json()),
        (
            "collector_candidates",
            archive.candidates.len().to_string().into(),
        ),
        (
            "bgp4mp_route_candidates",
            archive.bgp4mp_candidates.len().to_string().into(),
        ),
        (
            "bgp4mp_events",
            archive.bgp4mp_events.len().to_string().into(),
        ),
        (
            "bgp4mp_peer_relationship",
            peer_relationship
                .map_or("unknown", deep::bgp::PeerRelationship::as_str)
                .into(),
        ),
        (
            "bgp4mp_peer_relationship_basis",
            if peer_relationship.is_some() {
                "explicit_configuration"
            } else {
                "default_unknown"
            }
            .into(),
        ),
        (
            "unsupported_rib_entries",
            archive.unsupported_rib_entries.to_string().into(),
        ),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
    ]);
    let receipt_partial = workspace.join("receipt.json.partial");
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_partial)?;
    receipt_file.write_all(receipt.encode_bounded(1024 * 1024)?.as_bytes())?;
    receipt_file.sync_all()?;
    fs::hard_link(&partial, workspace.join("bgp.mrt"))?;
    fs::remove_file(partial)?;
    fs::hard_link(&receipt_partial, workspace.join("receipt.json"))?;
    fs::remove_file(receipt_partial)?;
    Ok(())
}

fn import_bmp(v: &[String]) -> Result<()> {
    if v.len() < 9 {
        return Err(usage());
    }
    let input = PathBuf::from(&v[2]);
    let mut workspace = None;
    let mut source_id = None;
    let mut checkpoint = None;
    let mut peer_relationship = None;
    let mut max_bmp = 8 * 1024 * 1024;
    let mut max_store = 128 * 1024 * 1024;
    let mut seen = std::collections::BTreeSet::new();
    let mut index = 3;
    while index < v.len() {
        let flag = v[index].as_str();
        if !seen.insert(flag) {
            return Err(usage());
        }
        let value = v.get(index + 1).ok_or_else(usage)?;
        match flag {
            "--workspace" => workspace = Some(PathBuf::from(value)),
            "--source-id" => source_id = Some(value.clone()),
            "--checkpoint" => checkpoint = Some(value.clone()),
            "--peer-relationship" => peer_relationship = Some(parse_peer_relationship(value)?),
            "--max-bmp-bytes" => max_bmp = value.parse().map_err(|_| usage())?,
            "--max-journal-bytes" => max_store = value.parse().map_err(|_| usage())?,
            _ => return Err(usage()),
        }
        index += 2;
    }
    let workspace = workspace.ok_or_else(usage)?;
    let source = deep::bgp_bmp::BmpSource {
        source_id: source_id.ok_or_else(usage)?,
        checkpoint_id: checkpoint.ok_or_else(usage)?,
    };
    let (mrt, limits) = mrt_profiles(max_bmp)?;
    let bmp_limits = deep::bgp_persisted::bmp_profile(&mrt);
    let bytes = deep::bgp_bmp_store::read_source(&input, max_bmp)?;
    fs::create_dir(&workspace)?;
    let partial = workspace.join("bgp.bmp.partial");
    let archive = deep::bgp_bmp_store::create_with_options(
        &partial,
        &bytes,
        source,
        max_store,
        bmp_limits,
        limits.clone(),
        deep::bgp_bmp_store::BmpReplayOptions { peer_relationship },
    )?;
    let receipt = Json::object([
        ("schema", "pcap-evidence.bgp.bmp-import-receipt.v1".into()),
        ("store", archive.receipt.json()),
        ("source_authenticated", false.into()),
        ("endpoint_state_claimed", false.into()),
    ])
    .encode_bounded(limits.output_bytes)?;
    let receipt_partial = workspace.join("receipt.json.partial");
    let mut receipt_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt_partial)?;
    receipt_file.write_all(receipt.as_bytes())?;
    receipt_file.sync_all()?;
    fs::hard_link(&partial, workspace.join("bgp.bmp"))?;
    fs::remove_file(partial)?;
    fs::hard_link(&receipt_partial, workspace.join("receipt.json"))?;
    fs::remove_file(receipt_partial)?;
    Ok(())
}

fn persisted_magic(path: &Path, maximum: u64) -> Result<[u8; 8]> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(Error::limit("bgp_store_disk"));
    }
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::new(
                ErrorCode::Truncated,
                0,
                "bgp_store_magic",
                "persisted BGP store is truncated",
            )
        } else {
            Error::io(error)
        }
    })?;
    Ok(magic)
}

fn bgp(v: &[String]) -> Result<()> {
    if v.len() < 4 || v[0] != "bgp" {
        return Err(usage());
    }
    let command = v[1].as_str();
    if command == "import-mrt-stream" {
        return bgp_stream_commands::import(v);
    }
    if matches!(command, "chronology" | "window") {
        return bgp_stream_commands::export(v);
    }
    if command == "import-bmp" {
        return import_bmp(v);
    }
    if command == "import-mrt" {
        return import_mrt(v);
    }
    if !matches!(
        command,
        "replay" | "state" | "query" | "export" | "policy" | "associate"
    ) {
        return Err(usage());
    }
    let journal = PathBuf::from(&v[2]);
    let mut output = None;
    let mut session = None;
    let mut filters = deep::bgp_persisted::Query::default();
    let mut rich_query = false;
    let mut profile = None;
    let mut other_store = None;
    let mut namespace = None;
    let mut clock_policy = None;
    let mut clock_basis = None;
    let mut peer_relationship = None;
    let mut other_peer_relationship = None;
    let mut maximum = 8u64 * 1024 * 1024 * 1024;
    let mut max_output = 8u64 * 1024 * 1024 * 1024;
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 3;
    while i < v.len() {
        let flag = v[i].as_str();
        if !seen.insert(flag) {
            return Err(usage());
        }
        i += 1;
        let value = v.get(i).ok_or_else(usage)?;
        match flag {
            "--output" => output = Some(PathBuf::from(value)),
            "--session" => {
                session = Some(value.clone());
                filters.session = Some(value.clone());
            }
            "--prefix" => {
                filters.prefix = Some(value.clone());
                rich_query = true;
            }
            "--afi" => {
                filters.afi = Some(value.parse().map_err(|_| usage())?);
                rich_query = true;
            }
            "--safi" => {
                filters.safi = Some(value.parse().map_err(|_| usage())?);
                rich_query = true;
            }
            "--peer" => {
                filters.peer = Some(value.clone());
                rich_query = true;
            }
            "--source" => {
                filters.source = Some(value.clone());
                rich_query = true;
            }
            "--checkpoint" => {
                filters.checkpoint = Some(value.clone());
                rich_query = true;
            }
            "--status" => {
                filters.status = Some(value.clone());
                rich_query = true;
            }
            "--policy-profile" => profile = Some(PathBuf::from(value)),
            "--with-store" => other_store = Some(PathBuf::from(value)),
            "--comparison-namespace" => namespace = Some(value.clone()),
            "--clock-policy" => clock_policy = Some(value.clone()),
            "--clock-basis" => clock_basis = Some(value.clone()),
            "--peer-relationship" => peer_relationship = Some(parse_peer_relationship(value)?),
            "--other-peer-relationship" => {
                other_peer_relationship = Some(parse_peer_relationship(value)?)
            }
            "--max-journal-bytes" => maximum = value.parse().map_err(|_| usage())?,
            "--max-output-bytes" => max_output = value.parse().map_err(|_| usage())?,
            _ => return Err(usage()),
        }
        i += 1;
    }
    let output = output.ok_or_else(usage)?;
    if maximum < 128 || max_output == 0 {
        return Err(usage());
    }
    if matches!(command, "policy" | "associate")
        || command == "query" && (rich_query || session.is_none())
    {
        if command != "policy" && profile.is_some()
            || command != "associate"
                && (other_store.is_some()
                    || namespace.is_some()
                    || clock_policy.is_some()
                    || clock_basis.is_some()
                    || other_peer_relationship.is_some())
            || command == "associate" && (rich_query || session.is_some())
        {
            return Err(usage());
        }
        let (mrt_limits, mut limits) = mrt_profiles(MAX_MRT_SOURCE_BYTES)?;
        let consumer_output_limit = limits
            .output_bytes
            .min(bounded_usize(max_output, "bgp_output")?);
        let options = deep::bgp_mrt_store::MrtReplayOptions { peer_relationship };
        let store = deep::bgp_persisted::VerifiedStore::load(
            &journal,
            maximum,
            mrt_limits.clone(),
            limits.clone(),
            options,
        )?;
        let load_limits = limits.clone();
        limits.output_bytes = consumer_output_limit;
        let encoded = if command == "policy" {
            let profile =
                deep::bgp_persisted::PolicyProfile::read(&profile.ok_or_else(usage)?, &limits)?;
            store.policy(&filters, &profile, &limits)?
        } else if command == "associate" {
            use deep::bgp_association::*;
            let time = match clock_policy.as_deref().ok_or_else(usage)? {
                "same-clock" if clock_basis.is_none() => TimePolicy::Window {
                    max_distance_ns: 0,
                    clocks: ClockRelation::SamePolicyAndId,
                    missing: MissingClockHandling::Unresolved,
                    semantics: WindowSemantics::AllReportedBounds,
                },
                "ignore" => TimePolicy::Ignore {
                    reason: clock_basis
                        .filter(|v| !v.trim().is_empty())
                        .ok_or_else(usage)?,
                },
                _ => return Err(usage()),
            };
            let other = deep::bgp_persisted::VerifiedStore::load(
                &other_store.ok_or_else(usage)?,
                maximum,
                mrt_limits,
                load_limits,
                deep::bgp_mrt_store::MrtReplayOptions {
                    peer_relationship: other_peer_relationship,
                },
            )?;
            let namespace = namespace.ok_or_else(usage)?;
            let policy = Policy {
                policy_id: "persisted-route-evidence-association-v1".into(),
                session: DimensionRule::Ignore,
                generation: DimensionRule::Ignore,
                flow: DimensionRule::Ignore,
                direction: DirectionRule::Ignore,
                spatial: SpatialRule::EqualPrefix,
                time,
            };
            store.associate(&other, &namespace, &policy, &limits)?
        } else {
            store.query(&filters, &limits)?
        };
        let line_bytes = encoded
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::limit("bgp_output"))?;
        if line_bytes as u64 > max_output {
            return Err(Error::limit("bgp_output"));
        }
        return publish(&output, max_output, |writer| {
            writer.write_all(encoded.as_bytes())?;
            writer.write_all(b"\n")?;
            Ok(())
        });
    }
    if rich_query
        || profile.is_some()
        || other_store.is_some()
        || namespace.is_some()
        || clock_policy.is_some()
        || clock_basis.is_some()
        || other_peer_relationship.is_some()
        || (command == "query") != session.is_some()
    {
        return Err(usage());
    }
    match persisted_magic(&journal, maximum)? {
        magic if magic == *deep::bgp_store::MAGIC => {
            if peer_relationship.is_some() {
                return Err(usage());
            }
            let archive = deep::bgp_store::replay(&journal, maximum, Limits::default())?;
            publish(&output, max_output, |writer| {
                if command == "query" {
                    let id = session
                        .expect("validated query session")
                        .parse::<u64>()
                        .map_err(|_| usage())?;
                    let snapshots = archive.session_history(id);
                    if snapshots.is_empty() {
                        return Err(Error::new(
                            ErrorCode::InvalidIndex,
                            0,
                            "bgp_session",
                            "session is not present in the sealed journal",
                        ));
                    }
                    writer.write_all(
                        Json::object([
                            ("schema", "pcap-evidence.bgp.session-query.v1".into()),
                            ("session", id.to_string().into()),
                            (
                                "occurrences",
                                Json::array(snapshots.into_iter().map(|snapshot| snapshot.json())),
                            ),
                            ("endpoint_state_claimed", false.into()),
                        ])
                        .encode_bounded_line(Limits::default().output_bytes)?
                        .as_bytes(),
                    )?;
                } else if command == "export" {
                    writer.write_all(
                        Json::object([
                            ("schema", "pcap-evidence.bgp.export-header.v1".into()),
                            ("source_kind", "captured".into()),
                            ("journal", archive.receipt.json()),
                        ])
                        .encode_bounded_line(Limits::default().output_bytes)?
                        .as_bytes(),
                    )?;
                    for snapshot in &archive.sessions {
                        writer.write_all(
                            snapshot
                                .json()
                                .encode_bounded_line(Limits::default().output_bytes)?
                                .as_bytes(),
                        )?;
                    }
                } else {
                    writer.write_all(
                        archive
                            .json()
                            .encode_bounded_line(Limits::default().output_bytes)?
                            .as_bytes(),
                    )?;
                }
                Ok(())
            })
        }
        magic if magic == *deep::bgp_mrt_store::MAGIC => {
            let (mrt_limits, limits) = mrt_profiles(MAX_MRT_SOURCE_BYTES)?;
            let archive = deep::bgp_mrt_store::replay_with_options(
                &journal,
                maximum,
                mrt_limits,
                limits.clone(),
                deep::bgp_mrt_store::MrtReplayOptions { peer_relationship },
            )?;
            let effective = bounded_usize(max_output, "bgp_output_bytes")?.min(limits.output_bytes);
            publish(&output, max_output, |writer| {
                if command == "query" {
                    let id = session.expect("validated query session");
                    archive.write_session_query_bounded_line(&id, writer, effective)?;
                } else if command == "export" {
                    writer.write_all(
                        Json::object([
                            ("schema", "pcap-evidence.bgp.export-header.v4".into()),
                            ("source_kind", "imported".into()),
                            ("journal", archive.receipt.json()),
                        ])
                        .encode_bounded_line(limits.output_bytes)?
                        .as_bytes(),
                    )?;
                    archive.write_bgp4mp_rib_bounded_line(None, writer, effective)?;
                    for record in archive.record_summaries() {
                        writer.write_all(
                            record.encode_bounded_line(limits.output_bytes)?.as_bytes(),
                        )?;
                    }
                    for event in &archive.bgp4mp_events {
                        writer.write_all(
                            event.encode_bounded_line(limits.output_bytes)?.as_bytes(),
                        )?;
                    }
                    for (observation_index, observation) in
                        archive.state.observations().iter().enumerate()
                    {
                        writer.write_all(
                            Json::object([
                                ("schema", "pcap-evidence.bgp.mrt-observation.v1".into()),
                                ("observation_index", observation_index.to_string().into()),
                                ("normalized_observation", observation.normalized().clone()),
                            ])
                            .encode_bounded_line(limits.output_bytes)?
                            .as_bytes(),
                        )?;
                    }
                    for candidate in &archive.candidates {
                        writer.write_all(
                            candidate
                                .json()
                                .encode_bounded_line(limits.output_bytes)?
                                .as_bytes(),
                        )?;
                    }
                    for candidate in &archive.bgp4mp_candidates {
                        writer.write_all(
                            candidate
                                .json()
                                .encode_bounded_line(limits.output_bytes)?
                                .as_bytes(),
                        )?;
                    }
                } else {
                    archive.write_bounded_line(writer, effective)?;
                }
                Ok(())
            })
        }
        magic if magic == *deep::bgp_bmp_store::MAGIC => {
            let (mrt, limits) = mrt_profiles(MAX_MRT_SOURCE_BYTES)?;
            let archive = deep::bgp_bmp_store::replay_with_options(
                &journal,
                maximum,
                deep::bgp_persisted::bmp_profile(&mrt),
                limits.clone(),
                deep::bgp_bmp_store::BmpReplayOptions { peer_relationship },
            )?;
            let effective = bounded_usize(max_output, "bgp_output_bytes")?.min(limits.output_bytes);
            publish(&output, max_output, |writer| {
                if command == "query" {
                    archive.write_session_query_bounded_line(
                        &session.expect("validated query session"),
                        writer,
                        effective,
                    )?;
                } else if command == "export" {
                    archive.write_export_ndjson(writer, effective)?;
                } else {
                    archive.write_bounded_line(writer, effective)?;
                }
                Ok(())
            })
        }
        _ => Err(Error::new(
            ErrorCode::BadMagic,
            0,
            "bgp_store_magic",
            "not a recognized persisted BGP store",
        )),
    }
}
fn main() {
    let v: Vec<String> = std::env::args().skip(1).collect();
    if v.is_empty() || v == ["--help"] {
        println!("{}", usage().detail);
        return;
    }
    let result = if v[0] == "analyze" {
        analyze(&v)
    } else if v[0] == "bgp" {
        bgp(&v)
    } else {
        run(&v)
    };
    if let Err(e) = result {
        eprintln!(
            "{}",
            Json::object([
                ("error", e.code.as_str().into()),
                ("field", e.field.into()),
                ("detail", e.detail.into())
            ])
            .encode()
        );
        std::process::exit(4);
    }
}
