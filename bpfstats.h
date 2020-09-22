#define SUM_SCALE 20
#define BUCKETS 64
#define N_SLOTS (((BUCKETS - 2) << 3) + 1)
#define GET_N_SLOTS(n) (((BUCKETS - (n) + 1) << (n)) + 1)
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct ks_slot {
	uint64_t samples, sum;
};
