//! Product sink owns only supplementary observations, not core reinterpretation.
use crate::{layer, Error, ErrorCode, Result};
use pcap_evidence::{
    json::Json,
    provenance::{EvidenceBytes, PacketId},
    sha256,
};
use pcap_evidence_stream::{events::Evidence, Event, EventKind, EventSink, EvidenceStatus};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
};
pub struct ByteBudget<W: Write> {
    pub inner: W,
    pub remaining: u64,
}
impl<W: Write> Write for ByteBudget<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() as u64 > self.remaining {
            return Err(std::io::Error::other("output byte budget exceeded"));
        }
        let n = self.inner.write(b)?;
        self.remaining -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
pub struct ProductSink<'a> {
    pub inner: &'a mut dyn EventSink,
    pub source: File,
    pub packets: u64,
    pub maximum: u64,
    pub profile: String,
    pub emitted: u64,
}
fn field<'a>(v: &'a Json, k: &str) -> Option<&'a Json> {
    if let Json::Object(o) = v {
        o.iter().find(|(n, _)| *n == k).map(|(_, v)| v)
    } else {
        None
    }
}
fn integer(v: Option<&Json>) -> Result<u64> {
    match v {
        Some(Json::String(s)) => s.parse().map_err(|_| Error::limit("packet_field")),
        Some(Json::Number(n)) => Ok(*n),
        _ => Err(Error::limit("packet_field")),
    }
}
fn set(v: &mut Json, k: &'static str, value: Json) {
    if let Json::Object(items) = v {
        if let Some((_, x)) = items.iter_mut().find(|(n, _)| *n == k) {
            *x = value
        } else {
            items.push((k, value));
        }
    }
}
impl ProductSink<'_> {
    fn send(&mut self, e: &Event) -> Result<u64> {
        let id = self.inner.emit(e)?;
        self.emitted = self
            .emitted
            .checked_add(1)
            .ok_or_else(|| Error::limit("product_event_count"))?;
        Ok(id)
    }
}
impl EventSink for ProductSink<'_> {
    fn run_id(&self) -> &str {
        self.inner.run_id()
    }
    fn emit(&mut self, e: &Event) -> Result<u64> {
        if e.kind == EventKind::Packet {
            if self.packets >= self.maximum {
                return Err(Error::limit("product_packet_count"));
            }
            self.packets = self
                .packets
                .checked_add(1)
                .ok_or_else(|| Error::limit("product_packet_count"))?;
        }
        let mut own = e.clone();
        if e.kind == EventKind::CaptureStart {
            set(
                &mut own.data,
                "product_profile",
                self.profile.clone().into(),
            );
            set(
                &mut own.data,
                "product_implementation",
                "pcap-evidence-product/0.2.0".into(),
            );
        }
        if e.kind == EventKind::CaptureComplete {
            set(
                &mut own.data,
                "events",
                self.emitted
                    .checked_add(1)
                    .ok_or_else(|| Error::limit("product_event_count"))?
                    .to_string()
                    .into(),
            );
            set(&mut own.data, "product_supplementary_events", true.into());
        }
        let id = self.send(&own)?;
        if e.kind != EventKind::Packet {
            return Ok(id);
        }
        let offset = integer(field(&e.data, "data_offset"))?;
        let cap = usize::try_from(integer(field(&e.data, "captured_length"))?)
            .map_err(|_| Error::limit("packet_length"))?;
        if cap > 1024 * 1024 {
            return Err(Error::limit("supplemental_packet_bytes"));
        }
        let link = integer(field(&e.data, "link_type"))? as u32;
        let mut bytes = vec![0; cap];
        self.source.seek(SeekFrom::Start(offset))?;
        self.source.read_exact(&mut bytes)?;
        let expected = field(&e.data, "packet_sha256");
        if expected != Some(&Json::String(sha256::hex(&sha256::digest(&bytes)))) {
            return Err(Error::new(
                ErrorCode::SourceMismatch,
                offset,
                "source",
                "capture changed during analysis",
            ));
        }
        let packet = PacketId {
            capture: sha256::digest(
                format!("pcap-evidence/unbound-run/v1:{}", self.run_id()).as_bytes(),
            ),
            frame: integer(field(&e.data, "frame"))?,
            record_offset: integer(field(&e.data, "record_offset"))?,
        };
        match layer::decode(link, &bytes) {
            Ok(Some((at, d))) => {
                let raw = EvidenceBytes::from_packet(&bytes[at..at + d.consumed], packet, at);
                let mut ev = Event::new(EventKind::Network, EvidenceStatus::Candidate, d.json());
                ev.protocol = Some(d.protocol.name().into());
                ev.related_events.push(id);
                ev.evidence = Evidence::bytes(&raw);
                self.send(&ev)?;
            }
            Ok(None) => {}
            Err(err) => {
                let mut ev = Event::new(
                    EventKind::Diagnostic,
                    if err.code == ErrorCode::UnsupportedTransport {
                        EvidenceStatus::Unsupported
                    } else {
                        EvidenceStatus::Rejected
                    },
                    Json::object([
                        ("reason", err.to_string().into()),
                        ("layer", "product_link_subset".into()),
                    ]),
                );
                ev.evidence = Evidence::packets(vec![packet]);
                ev.related_events.push(id);
                self.send(&ev)?;
            }
        }
        Ok(id)
    }
}
