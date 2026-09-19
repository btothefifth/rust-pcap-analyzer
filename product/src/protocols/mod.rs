//! Bounded independently implemented framing subsets; no endpoint simulation.
//! Per-field offsets describe the current message, never an invented packet.
mod common;
mod industrial;
mod it;
mod semantic_fields;
pub use common::{ber, BerElement};
use pcap_evidence::{json::Json, Error, ErrorCode, Result};

pub const MAX_FRAME: usize = 65536;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Netflow9,
    Bgp,
    Snmp,
    Ftp,
    Tftp,
    Pop3,
    Imap,
    Telnet,
    Sip,
    Rtp,
    Pptp,
    BacnetIp,
    BacnetMstp,
    Enip,
    Goose,
    SampledValues,
    Mms,
    Iec104,
    S7,
    HartIp,
    FinsUdp,
    FinsTcp,
    Ads,
    OpcUa,
    Melsec,
    Synchrophasor,
    Ethercat,
    Profinet,
    Powerlink,
    Stp,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub name: &'static str,
    pub value: Json,
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    pub protocol: Protocol,
    pub consumed: usize,
    pub fields: Vec<Field>,
    pub issues: Vec<&'static str>,
    /// Framing is decoded. Application/device/object semantics are not complete.
    pub support: &'static str,
}
impl Decoded {
    pub(crate) fn new(protocol: Protocol, consumed: usize) -> Self {
        Self {
            protocol,
            consumed,
            fields: Vec::new(),
            issues: Vec::new(),
            support: "metadata-only",
        }
    }
    pub(crate) fn num(
        mut self,
        name: &'static str,
        n: impl Into<u64>,
        start: usize,
        end: usize,
    ) -> Self {
        self.fields.push(Field {
            name,
            value: n.into().to_string().into(),
            start,
            end,
        });
        self
    }
    pub(crate) fn text(
        mut self,
        name: &'static str,
        value: impl Into<String>,
        start: usize,
        end: usize,
    ) -> Self {
        self.fields.push(Field {
            name,
            value: Json::String(value.into()),
            start,
            end,
        });
        self
    }
    pub fn json(&self) -> Json {
        Json::object([
            ("protocol", self.protocol.name().into()),
            ("decoder_version", "product-framing/2".into()),
            ("support", self.support.into()),
            ("consumed", self.consumed.to_string().into()),
            (
                "fields",
                Json::object(self.fields.iter().map(|f| (f.name, f.value.clone()))),
            ),
            (
                "field_ranges",
                Json::array(self.fields.iter().map(|f| {
                    Json::object([
                        ("name", f.name.into()),
                        ("start", f.start.to_string().into()),
                        ("end", f.end.to_string().into()),
                    ])
                })),
            ),
            (
                "issues",
                Json::array(self.issues.iter().copied().map(Json::from)),
            ),
            ("endpoint_behavior_established", false.into()),
            ("payload_semantics_complete", false.into()),
        ])
    }
}
impl Protocol {
    pub const ALL: &'static [Self] = &[
        Self::Netflow9,
        Self::Bgp,
        Self::Snmp,
        Self::Ftp,
        Self::Tftp,
        Self::Pop3,
        Self::Imap,
        Self::Telnet,
        Self::Sip,
        Self::Rtp,
        Self::Pptp,
        Self::BacnetIp,
        Self::BacnetMstp,
        Self::Enip,
        Self::Goose,
        Self::SampledValues,
        Self::Mms,
        Self::Iec104,
        Self::S7,
        Self::HartIp,
        Self::FinsUdp,
        Self::FinsTcp,
        Self::Ads,
        Self::OpcUa,
        Self::Melsec,
        Self::Synchrophasor,
        Self::Ethercat,
        Self::Profinet,
        Self::Powerlink,
        Self::Stp,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Netflow9 => "netflow9",
            Self::Bgp => "bgp",
            Self::Snmp => "snmp",
            Self::Ftp => "ftp",
            Self::Tftp => "tftp",
            Self::Pop3 => "pop3",
            Self::Imap => "imap",
            Self::Telnet => "telnet",
            Self::Sip => "sip",
            Self::Rtp => "rtp",
            Self::Pptp => "pptp",
            Self::BacnetIp => "bacnet_ip",
            Self::BacnetMstp => "bacnet_mstp",
            Self::Enip => "enip_cip",
            Self::Goose => "goose",
            Self::SampledValues => "sampled_values",
            Self::Mms => "mms",
            Self::Iec104 => "iec104",
            Self::S7 => "s7",
            Self::HartIp => "hart_ip",
            Self::FinsUdp => "fins_udp",
            Self::FinsTcp => "fins_tcp",
            Self::Ads => "ads",
            Self::OpcUa => "opcua_tcp",
            Self::Melsec => "melsec_3e",
            Self::Synchrophasor => "c37118",
            Self::Ethercat => "ethercat",
            Self::Profinet => "profinet_rt",
            Self::Powerlink => "powerlink",
            Self::Stp => "stp",
        }
    }
    pub fn feature(self) -> &'static str {
        match self {
            Self::Netflow9 | Self::Stp => "standard",
            Self::Bgp
            | Self::Snmp
            | Self::Ftp
            | Self::Tftp
            | Self::Pop3
            | Self::Imap
            | Self::Telnet
            | Self::Sip
            | Self::Rtp
            | Self::Pptp => "extensions",
            Self::BacnetIp
            | Self::BacnetMstp
            | Self::Enip
            | Self::Goose
            | Self::SampledValues
            | Self::Mms => "industrial",
            _ => "industrial-full",
        }
    }
    pub fn compiled(self) -> bool {
        match self.feature() {
            "standard" => cfg!(feature = "standard"),
            "extensions" => cfg!(feature = "extensions"),
            "industrial" => cfg!(feature = "industrial"),
            _ => cfg!(feature = "industrial-full"),
        }
    }
    pub fn transport(self) -> &'static str {
        match self {
            Self::Netflow9
            | Self::Snmp
            | Self::Tftp
            | Self::Rtp
            | Self::BacnetIp
            | Self::FinsUdp => "udp",
            Self::BacnetMstp
            | Self::Goose
            | Self::SampledValues
            | Self::Ethercat
            | Self::Profinet
            | Self::Powerlink
            | Self::Stp => "link",
            _ => "tcp",
        }
    }
    pub fn decode(self, bytes: &[u8]) -> Result<Decoded> {
        if !self.compiled() {
            return Err(Error::new(
                ErrorCode::UnsupportedTransport,
                0,
                "feature",
                "decoder feature disabled",
            ));
        }
        if bytes.is_empty() {
            return Err(common::short("protocol", 1));
        }
        if bytes.len() > MAX_FRAME {
            return Err(Error::limit("protocol_input"));
        }
        let mut value = match self {
            Self::Netflow9 => it::netflow(bytes),
            Self::Bgp => it::bgp(bytes),
            Self::Snmp => it::snmp(bytes),
            Self::Ftp | Self::Pop3 | Self::Imap => it::text_protocol(self, bytes),
            Self::Tftp => it::tftp(bytes),
            Self::Telnet => it::telnet(bytes),
            Self::Sip => it::sip(bytes),
            Self::Rtp => it::rtp(bytes),
            Self::Pptp => it::pptp(bytes),
            Self::Stp => it::stp(bytes),
            _ => industrial::decode(self, bytes),
        }?;
        semantic_fields::extend(self, bytes, &mut value)?;
        if value.consumed == 0
            || value.consumed > bytes.len()
            || value
                .fields
                .iter()
                .any(|f| f.start > f.end || f.end > value.consumed)
        {
            return Err(Error::new(
                ErrorCode::Invariant,
                0,
                "decoder",
                "invalid decoded extent",
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        if value.fields.iter().any(|f| !names.insert(f.name)) {
            return Err(common::bad(
                "duplicate_field",
                "repeated semantic field requires explicit alternative representation",
            ));
        }
        Ok(value)
    }
}
