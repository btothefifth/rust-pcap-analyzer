//! Content-first selection for the existing snapshot engine. The streaming crate
//! has an open analyzer registry; this compatibility adapter selects its two native
//! industrial analyzers and preserves the legacy port fallback explicitly.
use crate::{
    engine::{Analysis, Config},
    json::Json,
    protocol::{ProbeInput, ProbeRegistry, ProbeResult, ProbeTransport},
    tcp::FlowResult,
    Result,
};
#[derive(Clone, Debug)]
pub struct Selection {
    pub dnp3: bool,
    pub modbus: bool,
    pub basis: &'static str,
    pub matched: Vec<&'static str>,
}
pub fn classify_flow(flow: &FlowResult, config: &Config) -> Result<Selection> {
    let registry = ProbeRegistry::builtins()?;
    let mut content_dnp3 = false;
    let mut content_modbus = false;
    for (direction, stream) in flow.streams.iter().enumerate() {
        let Some(stream) = stream else {
            continue;
        };
        for chunk in &stream.chunks {
            if chunk.bytes.is_empty() {
                continue;
            }
            let (source_port, destination_port) = if direction == 0 {
                (flow.key.a.port, flow.key.b.port)
            } else {
                (flow.key.b.port, flow.key.a.port)
            };
            let prefix = &chunk.bytes.data()[..chunk.bytes.len().min(4096)];
            for observation in registry.inspect(&ProbeInput {
                transport: ProbeTransport::Tcp,
                source_port,
                destination_port,
                prefix,
            })? {
                if let ProbeResult::Match { protocol, .. } = observation.result {
                    match protocol {
                        "dnp3" => content_dnp3 = true,
                        "modbus" => content_modbus = true,
                        _ => {}
                    }
                }
            }
        }
    }
    let hint_dnp3 = config.dnp3_ports.contains(&flow.key.a.port)
        || config.dnp3_ports.contains(&flow.key.b.port);
    let hint_modbus = config.modbus_ports.contains(&flow.key.a.port)
        || config.modbus_ports.contains(&flow.key.b.port);
    // A configured port is a hint, not a forced answer. If it conflicts with a
    // content match, retain both interpretations so the caller can report an
    // explicit ambiguity instead of silently trusting either source.
    let dnp3 = content_dnp3 || hint_dnp3;
    let modbus = content_modbus || hint_modbus;
    let basis = if content_dnp3 || content_modbus {
        let conflicting_hint = (content_dnp3 && hint_modbus) || (content_modbus && hint_dnp3);
        if conflicting_hint {
            "content_and_configured_port_hint"
        } else {
            "content"
        }
    } else if dnp3 || modbus {
        "configured_port_hint_unconfirmed_by_probe"
    } else {
        "none"
    };
    let mut matched = Vec::new();
    if dnp3 {
        matched.push("dnp3");
    }
    if modbus {
        matched.push("modbus");
    }
    Ok(Selection {
        dnp3,
        modbus,
        basis,
        matched,
    })
}
pub fn analysis_json(analysis: &Analysis) -> Result<Json> {
    let mut records = Vec::new();
    for flow in &analysis.flows {
        let s = classify_flow(flow, &analysis.config)?;
        records.push(Json::object([
            ("flow", flow.id.into()),
            ("basis", s.basis.into()),
            (
                "matches",
                Json::array(s.matched.into_iter().map(Json::from)),
            ),
            ("ambiguous", (s.dnp3 && s.modbus).into()),
        ]));
    }
    Ok(Json::Array(records))
}
