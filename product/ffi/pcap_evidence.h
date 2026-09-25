#ifndef PCAP_EVIDENCE_H
#define PCAP_EVIDENCE_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
/* ABI v1. Caller owns every input/output buffer. No returned allocation/pointer.
 * All handle operations serialize through a mutex. No reentrant callbacks.
 * Input <= 64 MiB, encoded output <= 64 MiB, at most 8 live handles.
 * Parsing has additional logical budgets; these are not a hard process RSS cap.
 * Feed appends until analyze. Analyze is one-shot. Destroy accepts no reuse.
 * All non-null pointer ranges MUST refer to valid caller-owned allocations.
 */
enum pcap_result { PCAP_OK=0,PCAP_INVALID=1,PCAP_LIMIT=2,PCAP_NO_HANDLE=3,
 PCAP_ANALYSIS_ERROR=4,PCAP_INTERNAL_PANIC=5,PCAP_BUFFER_TOO_SMALL=6 };
uint32_t pcap_abi_version(void);
int32_t pcap_create(size_t max_input,size_t max_output,uint64_t *handle);
int32_t pcap_feed(uint64_t handle,const uint8_t *data,size_t length);
int32_t pcap_analyze(uint64_t handle);
int32_t pcap_output_size(uint64_t handle,size_t *length);
int32_t pcap_copy_output(uint64_t handle,uint8_t *destination,size_t capacity,size_t *written);
int32_t pcap_destroy(uint64_t handle);
#ifdef __cplusplus
}
#endif
#endif
