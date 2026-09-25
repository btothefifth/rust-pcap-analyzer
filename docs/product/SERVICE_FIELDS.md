# Service-field extension, decoder version product-framing/2

The existing `Protocol::decode` facade invokes `semantic_fields::extend` before
its normal extent and duplicate-field checks. Thus the native plugin, shared event
model, existing JSON/TLV path and GUI receive the same field records. There is no
external parser or consensus path. Existing field meanings are retained; added
fields and more precise issue strings intentionally change these decoders' output.
The decoder version changes to `product-framing/2`; event v1's meaning is unchanged.

## BACnet/IP supported service subset

The existing BVLC/NPDU/APDU framing remains responsible for lower-layer bounds.
Unsegmented Who-Is decodes its optional device-instance interval. I-Am decodes its
device object identifier, maximum APDU size, segmentation declaration and vendor.
ReadProperty request/ack and WriteProperty request decode object type/instance,
property identifier, optional array index and optional write priority. Property
value containers retain an ordered bounded tag trace, source ranges and a value
hash; device effects and complete value-type interpretation are not asserted.

The tag reader bounds extended lengths, tag count and nesting, preserves sequence,
and checks container pairing. Unexpected/duplicate known fields and trailing
service bytes are errors rather than silently overwritten values. Segmented APDUs
remain explicitly unsupported by this service extension until independent segmented
service reconstruction exists. Other service bodies keep their existing opaque state.

## EtherNet/IP / CIP supported path subset

Within framed unconnected CPF data items (0x00B2), the decoder exposes request or
response service, response general/additional status, logical class/instance/member/
connection-point/attribute path segments, and ANSI extended symbols as bytes.
8-, 16-, and 32-bit logical forms have checked extents and padding. Segment ordering
and duplicates remain visible rather than collapsed into a map. Unknown path tails
are hashed and marked unsupported. Service data is represented by extent/hash;
object execution, value semantics and security authentication are not implemented.

Connected 0x00B1 data is not assumed to be a message-router payload without observed
connection semantics. No implicit I/O, secure-authentication or endpoint-state claim
is introduced. All observations retain message-relative offsets used by the existing
provenance mapping. Unknown paths do not become fully supported paths.

## Evidence and tests

`product/tests/service_fields.rs` provides 11 native selectors with independent
byte constructions, positive neighbors, malformed extents, duplicated fields,
invalid priorities/padding, ordered duplicate paths and truncation checks.
These are project regression vectors, not a licensed conformance suite.

Reference targets for additional normative review: ASHRAE 135 BACnet application
services/encoding and ODVA CIP/Encapsulation editions. The public ODVA document
library is https://www.odva.org/technology-standards/document-library/ . A public
BACnet implementation's ReadProperty layout was consulted as a research input, not
copied or treated as the oracle. Exact normative editions and clause-level approval
remain NOT REVIEWED; do not advertise standards certification from these tests.

The existing family catalog is not promoted from registered to qualified by this
extension. DNP3 object/security depth, segmented BACnet services, connected CIP and
complete MMS transport/presentation semantics remain separate open work.
