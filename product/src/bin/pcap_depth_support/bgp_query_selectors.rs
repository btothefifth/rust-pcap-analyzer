//! Strict parsing for the additive persisted selector interface.
use pcap_evidence::{Error, ErrorCode, Result};
use pcap_evidence_product::deep::{
    bgp_import::ClockPolicy,
    bgp_persisted::{
        AsnRole, AsnSelector, AttributeScope, PrefixRelation, PrefixSelector, Query,
        ReportedTimeWindow,
    },
    bgp_rib::PathId,
};
use std::{net::IpAddr, str::FromStr};
fn malformed() -> Error {
    Error::new(
        ErrorCode::Usage,
        0,
        "bgp_query_selectors",
        "canonical complete selector required",
    )
}
pub fn unsigned<T: FromStr + ToString>(value: &str) -> Result<T> {
    if value.is_empty() || !value.bytes().all(|v| v.is_ascii_digit()) {
        return Err(malformed());
    }
    let parsed: T = value.parse().map_err(|_| malformed())?;
    if parsed.to_string() != value {
        return Err(malformed());
    }
    Ok(parsed)
}
fn signed(value: &str) -> Result<i64> {
    let parsed: i64 = value.parse().map_err(|_| malformed())?;
    if parsed.to_string() != value {
        return Err(malformed());
    }
    Ok(parsed)
}
#[derive(Default)]
pub struct SelectorFlags {
    asn: Option<u32>,
    role: Option<AsnRole>,
    relation: Option<PrefixRelation>,
    clock_policy: Option<ClockPolicy>,
    clock_id: Option<String>,
    clock_source: Option<String>,
    start: Option<i64>,
    end: Option<i64>,
}
impl SelectorFlags {
    /// The outer parser rejects duplicates before calling this function.
    pub fn take(&mut self, query: &mut Query, flag: &str, value: &str) -> Result<bool> {
        match flag {
            "--prefix-mode" => {
                self.relation = Some(match value {
                    "exact" => PrefixRelation::Exact,
                    "contains" => PrefixRelation::Contains,
                    "contained-by" => PrefixRelation::ContainedBy,
                    _ => return Err(malformed()),
                })
            }
            "--asn" => self.asn = Some(unsigned(value)?),
            "--asn-role" => {
                self.role = Some(match value {
                    "origin" => AsnRole::Origin,
                    "path-member" => AsnRole::PathMember,
                    _ => return Err(malformed()),
                })
            }
            "--community" => {
                let (a, b) = value.split_once(':').ok_or_else(malformed)?;
                query.community =
                    Some((u32::from(unsigned::<u16>(a)?) << 16) | u32::from(unsigned::<u16>(b)?));
            }
            "--large-community" => {
                let parts: Vec<_> = value.split(':').collect();
                if parts.len() != 3 {
                    return Err(malformed());
                }
                query.large_community = Some([
                    unsigned(parts[0])?,
                    unsigned(parts[1])?,
                    unsigned(parts[2])?,
                ]);
            }
            "--extended-community" => {
                if value.len() != 16
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(malformed());
                }
                let mut raw = [0u8; 8];
                for (i, v) in raw.iter_mut().enumerate() {
                    *v = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                        .map_err(|_| malformed())?;
                }
                query.extended_community = Some(raw);
            }
            "--next-hop" => {
                let ip: IpAddr = value.parse().map_err(|_| malformed())?;
                if ip.to_string() != value {
                    return Err(malformed());
                }
                query.next_hop = Some(ip);
            }
            "--partition" => query.partition = Some(value.into()),
            "--generation" => query.generation = Some(unsigned(value)?),
            "--direction" => query.direction = Some(unsigned(value)?),
            "--path-id" => {
                query.path_id = Some(match value {
                    "absent" => PathId::Absent,
                    "unknown" => PathId::Unknown,
                    _ => PathId::Present(unsigned(value)?),
                })
            }
            "--lifecycle" => query.lifecycle = Some(unsigned(value)?),
            "--attribute-scope" => {
                query.attribute_scope = Some(match value {
                    "current-effective" => AttributeScope::CurrentEffective,
                    "any-retained-version" => AttributeScope::AnyRetainedVersion,
                    "observation-event" => AttributeScope::ObservationEvent,
                    _ => return Err(malformed()),
                })
            }
            "--version-index" => query.version_index = Some(unsigned(value)?),
            "--occurrence-id" => query.occurrence_id = Some(value.into()),
            "--reported-clock-policy" => {
                self.clock_policy = Some(match value {
                    "source-label" => ClockPolicy::SourceLabel,
                    "ingestion-label" => ClockPolicy::IngestionLabel,
                    _ => return Err(malformed()),
                })
            }
            "--reported-clock-id" => self.clock_id = Some(value.into()),
            "--reported-clock-source" => self.clock_source = Some(value.into()),
            "--reported-start-ns" => self.start = Some(signed(value)?),
            "--reported-end-ns" => self.end = Some(signed(value)?),
            _ => return Ok(false),
        }
        Ok(true)
    }
    pub fn finish(self, query: &mut Query) -> Result<()> {
        match (self.asn, self.role) {
            (None, None) => {}
            (Some(asn), Some(role)) => query.asn = Some(AsnSelector { asn, role }),
            _ => return Err(malformed()),
        }
        if let Some(relation) = self.relation {
            query.prefix_selector = Some(PrefixSelector::parse(
                &query.prefix.take().ok_or_else(malformed)?,
                relation,
            )?);
        }
        match (
            self.clock_policy,
            self.clock_id,
            self.clock_source,
            self.start,
            self.end,
        ) {
            (None, None, None, None, None) => {}
            (Some(clock_policy), Some(clock_id), Some(source), Some(start_ns), Some(end_ns)) => {
                query.time_window = Some(ReportedTimeWindow {
                    source,
                    clock_policy,
                    clock_id,
                    start_ns,
                    end_ns,
                })
            }
            _ => return Err(malformed()),
        }
        query.validate().map_err(|_| malformed())
    }
}
