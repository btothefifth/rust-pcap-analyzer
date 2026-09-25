//! Finalized disk history -> bounded stateful application interpretation.
//! Does not assert complete endpoint execution or repair an ambiguous transport.
#![forbid(unsafe_code)]
use pcap_evidence::{json::Json, sha256, Error, Result};
use pcap_evidence_history::query::History;
use pcap_evidence_product::deep::{continuation::Parser, Context, Limits};
use std::io::Write;
#[derive(Clone, Debug)]
pub struct Request {
    pub generation: [u8; 32],
    pub direction: u8,
    pub start: i64,
    pub end: i64,
    pub page_bytes: usize,
    pub max_output_bytes: u64,
    pub protocol: String,
    pub ua_security_none: bool,
}
pub fn analyze<W: Write>(
    history: &mut History,
    request: &Request,
    l: Limits,
    output: &mut W,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    if request.start >= request.end
        || request.direction > 1
        || request.page_bytes == 0
        || request.page_bytes > history.config.max_query_bytes
    {
        return Err(Error::limit("history_application_request"));
    }
    let mut parser = Parser::new(
        &request.protocol,
        l.clone(),
        Context {
            ua_security_none: request.ua_security_none,
            ..Context::default()
        },
    )?;
    let capture_sha256 = history.identity.sha256;
    let mut seq = 0u64;
    let mut written = 0u64;
    let mut chain = [0u8; 32];
    let mut emit = |kind: &'static str, data: Json| -> Result<()> {
        seq = seq
            .checked_add(1)
            .ok_or_else(|| Error::limit("history_app_sequence"))?;
        let body = Json::object([
            ("schema", "pcap-evidence.history-app.v1".into()),
            ("sequence", seq.to_string().into()),
            ("kind", kind.into()),
            ("capture_sha256", sha256::hex(&capture_sha256).into()),
            ("generation", sha256::hex(&request.generation).into()),
            ("direction", request.direction.into()),
            ("data", data),
        ]);
        let raw = body.encode_bounded(l.output_bytes)?;
        let mut h = sha256::Sha256::new();
        h.update(b"pcap-evidence/history-app/v1\0");
        h.update(&chain);
        h.update(raw.as_bytes());
        let next = h.finalize();
        let line = Json::object([
            ("event", body),
            ("previous_sha256", sha256::hex(&chain).into()),
            ("event_sha256", sha256::hex(&next).into()),
        ])
        .encode_bounded_line(l.output_bytes)?;
        written = written
            .checked_add(line.len() as u64)
            .filter(|n| *n <= request.max_output_bytes)
            .ok_or_else(|| Error::limit("history_app_output"))?;
        output.write_all(line.as_bytes())?;
        chain = next;
        Ok(())
    };
    emit(
        "analysis.start",
        Json::object([
            ("source_range_start", request.start.to_string().into()),
            ("source_range_end", request.end.to_string().into()),
            ("protocol_hypothesis", request.protocol.clone().into()),
            ("input", "sealed_integrity_checked_history".into()),
            ("semantic_replay_verified", false.into()),
            ("page_boundaries_reset_protocol", false.into()),
        ]),
    )?;
    let mut at = request.start;
    let result = (|| -> Result<()> {
        while at < request.end {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Error::limit("history_app_cancelled"));
            }
            let end = at
                .checked_add(request.page_bytes as i64)
                .unwrap_or(i64::MAX)
                .min(request.end);
            let range = history.evidence_range(request.generation, request.direction, at, end)?;
            for p in range.pieces {
                if let Some(bytes) = p.bytes {
                    parser.feed(p.start, &bytes, &mut |record| {
                        emit(
                            "protocol.message",
                            Json::object([
                                (
                                    "available_at_frame",
                                    record.available_at_frame.to_string().into(),
                                ),
                                (
                                    "last_input_stream_start",
                                    record.stream_start.to_string().into(),
                                ),
                                (
                                    "last_input_stream_end",
                                    record.stream_end.to_string().into(),
                                ),
                                ("report", record.report.json()),
                            ]),
                        )
                    })?;
                } else {
                    let report = parser.cut("transport_gap_conflict_or_ambiguous_placement")?;
                    emit(
                        "application.boundary",
                        Json::object([
                            ("start", p.start.to_string().into()),
                            ("end", p.end.to_string().into()),
                            ("transport_status", p.status.into()),
                            ("report", report.json()),
                        ]),
                    )?;
                }
            }
            at = end;
        }
        if let Some(report) = parser.finish()? {
            emit("application.incomplete", report.json())?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => emit(
            "analysis.complete",
            Json::object([
                ("selected_range_consumed", true.into()),
                ("complete_endpoint_history_claimed", false.into()),
            ]),
        )?,
        Err(e) => {
            let _ = emit(
                "analysis.aborted",
                Json::object([
                    ("error", e.code.as_str().into()),
                    ("field", e.field.into()),
                    ("consumed_until", at.to_string().into()),
                ]),
            );
            return Err(e);
        }
    }
    output.flush()?;
    Ok(())
}
