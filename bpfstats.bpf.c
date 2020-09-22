#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "bpfstats.h"

#define PROCESS_BUFFER_SIZE 200

SEC(".rodata")
const volatile __u32 frac_bits = -1;
const volatile __u32 frac_mask = -1;
const volatile __u32 n_slots = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCESS_BUFFER_SIZE);
	__type(key, u64);
	__type(value, u64);
} process_buffer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, N_SLOTS);
	__type(key, u32);
	__type(value, struct ks_slot);
} kslots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} frac_bits_map SEC(".maps");


/* utility function to Find Last Set bit in 64bit integer */
static inline u32 fls64(u64 val)
{
  u32 res = 0;

  for(res = 0; res < 64; res++){
    if(!val)
      return res;
    val >>= 1;
  }
  return res;

  //return val ? sizeof(val) * 8 - (__builtin_clzll(val)) : 0;
}


SEC("fentry/start")
int START_TIMER(fentry__prog)
{
  u64 pid;
  u64 *value, zero = 0;
  pid = bpf_get_current_pid_tgid();

  bpf_map_update_elem(&process_buffer, &pid, &zero, BPF_ANY);
  value = bpf_map_lookup_elem(&process_buffer, &pid);
  if(value)
    (*value) = bpf_ktime_get_ns();

  /*
  value = bpf_ktime_get_ns();
  bpf_map_update_elem(&process_buffer, &pid, &value, BPF_ANY);
  */

  return 0;
}

SEC("fexit/read")
int READ_TIMER(fexit__prog)
{
  u64 pid;
  u64 *preValue, val, zero = 0;

  /* second timestamp */
  val = bpf_ktime_get_ns();
  pid = bpf_get_current_pid_tgid();

  /* retrieve previous timestamp */
  preValue = bpf_map_lookup_elem(&process_buffer, &pid);
  /* if the target function generate a child process the new process didn't have any previous timestamp*/
  if(!preValue)
    return 0;

  val -= (*preValue);

  /* the .rodata section should be modify by user program before the eBPF attachment */
  if(frac_bits == -1)
    return 0;

  /* calculate the logarithm with some extra cipher */
  u32 bucket = 0, slot = 0;
  bucket = fls64(val >> frac_bits);
  slot = (bucket == 0) ? val : ((bucket << frac_bits) | ((val >> (bucket - 1)) & frac_mask));
  slot = MIN(slot, n_slots - 1);

   /* retrive slot */
   struct ks_slot *slt;
   slt = bpf_map_lookup_elem(&kslots, &slot);

   /* this should never happen but eBPF JIT throws an error if this part is omitted */
   if(!slt)
    return 0;

   /* using atomic operation but not fundamental with per cpu HASH */
   __sync_fetch_and_add(&slt->samples, 1);
   __sync_fetch_and_add(&slt->sum, (bucket < SUM_SCALE) ? val : (val >> (bucket - SUM_SCALE)));

   return 0;
}
