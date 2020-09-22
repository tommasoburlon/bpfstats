#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include "bpfstats.skel.h"
#include "bpfstats.h"
#include "bpf_struct.h"

#define MAX_PATH_SIZE 256

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int get_path(char *res_path, char *name_bpf, char *name_obj)
{
  char *base = "/sys/fs/bpf/bpfstats";

  if(name_obj && name_bpf)
    sprintf(res_path, "%s/%s/%s", base, name_bpf, name_obj);
  else if(name_bpf)
    sprintf(res_path, "%s/%s", base, name_bpf);
  else
    sprintf(res_path, "%s", base);
  return 0;
}

struct bpfstats_bpf * create_ebpf(enum bpf_attach_type start_type, char* start_link, enum bpf_attach_type read_type, char* read_link, uint32_t frac_bits)
{
  struct bpfstats_bpf *obj;
  int err;

  /* open bpf skeleton of the program */
  obj = bpfstats_bpf__open();

  /* set the const in the eBPF program */
  obj->rodata->frac_bits = frac_bits;
  obj->rodata->frac_mask = (1 << frac_bits) - 1;
  obj->rodata->n_slots = GET_N_SLOTS(frac_bits);


  /* attach program to another function */
  struct bpf_program *prog;


  prog = bpf_object__find_program_by_name(obj->obj, "START_TIMER");
  bpf_program__set_expected_attach_type(prog, start_type);
  prog->obj->btf_vmlinux = libbpf_find_kernel_btf();
  err = bpf_program__set_attach_target(prog, 0, start_link);


  prog = bpf_object__find_program_by_name(obj->obj, "READ_TIMER");
  bpf_program__set_expected_attach_type(prog, read_type);
  prog->obj->btf_vmlinux = libbpf_find_kernel_btf();
  err = err || bpf_program__set_attach_target(prog,  0, read_link);
  if(err){
    printf("ERROR: failed to find function.\n");
    return NULL;
  }

  /* load bpf program */
  err = bpfstats_bpf__load(obj);
  if(err){
    printf("ERROR: failed to load the skeleton.\n");
    return NULL;
  }

  /* initialize option map and slot map */
  uint32_t i;
  struct ks_slot *slot_iter = malloc(libbpf_num_possible_cpus() * sizeof(struct ks_slot));
  if(!slot_iter){
    printf("ERROR: failed to allocate memory.\n");
    return NULL;
  }

  for(i = 0; i < libbpf_num_possible_cpus(); i++){
    slot_iter[i].sum = 0;
    slot_iter[i].samples = 0;
  }
  for(i = 0; i < N_SLOTS; i++)
    bpf_map_update_elem(bpf_map__fd(obj->maps.kslots), &i, slot_iter, BPF_ANY);

  /* this map should never used by the bpf program is needed only for retrieves frac_bits */
  i = 0;
  bpf_map_update_elem(bpf_map__fd(obj->maps.frac_bits_map), &i, &frac_bits, BPF_ANY);

  free(slot_iter);

  /* attach to its hook */
  err = bpfstats_bpf__attach(obj);
  if(err){
    printf("ERROR: failed to attach the skeleton.\n");
    return NULL;
  }

  return obj;
}

int create_trace(char *S, int B, char *X, char *Y)
{
  /* this function first try to create the skeleton object than pin the program and the maps */
  struct bpfstats_bpf *obj;
  char path[MAX_PATH_SIZE];

  obj = create_ebpf(24, X, 25, Y, B);
  if(obj == NULL){
    printf("ERROR: failed to create, load or attach bpf skeleton.\n");
    return 1;
  }

  struct bpf_map *map;
  struct bpf_link* lnk;

  get_path(path, S, NULL);
  /* S should be unique */
  struct stat buf;
  if (stat(path, &buf) == -1) {
    if(mkdir(path, 0700)){
      printf("ERROR: failed to create directory.\n");
      return 1;
    }
  }else{
    printf("ERROR: trace already exists.\n");
    return 1;
  }

  /* pinning map and programs */
  map = bpf_object__find_map_by_name(obj->obj, "kslots");
  get_path(path, S, "kslots");
  bpf_map__pin(map, path);

  map = bpf_object__find_map_by_name(obj->obj, "frac_bits_map");
  get_path(path, S, "frac_bits_map");
  bpf_map__pin(map, path);

  lnk = obj->links.START_TIMER;
  get_path(path, S, "LINK_START_TIMER");
  bpf_link__pin(lnk, path);

  lnk = obj->links.READ_TIMER;
  get_path(path, S, "LINK_READ_TIMER");
  bpf_link__pin(lnk, path);

  return 0;
}

int remove_trace(char *S)
{
  /* this function simply unlink pinning program and map and remove directory */
  char path[MAX_PATH_SIZE];

  get_path(path, S, "kslots");
  unlink(path);

  get_path(path, S, "frac_bits_map");
  unlink(path);

  get_path(path, S, "LINK_START_TIMER");
  unlink(path);

  get_path(path, S, "LINK_READ_TIMER");
  unlink(path);

  get_path(path, S, NULL);
  if(rmdir(path)){
    printf("ERROR: failed to remove directory. %s\n", path);
    return 1;
  }
  return 0;
}

int read_trace(char *S)
{
  struct ks_slot *slot;
  int ncpus = libbpf_num_possible_cpus();
  int map_fd, frac_bits, zero = 0, n_slots;
  char path[MAX_PATH_SIZE];

  get_path(path, S, "frac_bits_map");
  map_fd = bpf_obj_get(path);

  if(map_fd < 0){
    printf("ERROR: failed to retrive pinned bpf, wrong name: %s\n", S);
    return 1;
  }

  bpf_map_lookup_elem(map_fd, &zero, &frac_bits);
  n_slots = GET_N_SLOTS(frac_bits);
  printf("frac_bits: %d\n", frac_bits);

  get_path(path, S, "kslots");
  map_fd = bpf_obj_get(path);

  slot = malloc(sizeof(struct ks_slot) * ncpus);
  if(!slot){
    printf("ERROR: failed to allocate memory.\n");
    return -ENOMEM;
  }

  for(int i = 0; i < n_slots; i++){
    uint32_t bucket = i >> frac_bits;
		uint32_t sum_shift = bucket < SUM_SCALE ? 0 : bucket - SUM_SCALE;
    uint64_t total_n = 0, total_avg = 0, non_zero = 0;

    bpf_map_lookup_elem(map_fd, &i, slot);
    for(int j = 0; j < ncpus; j++){
      uint64_t avg, n, val;
      n = slot[j].samples;
      val = slot[j].sum;
      avg = (val / n) << sum_shift;

      if(n != 0){
        total_n += n;
        total_avg += (val / n);
        non_zero++;
        printf("CPU %3d slot %3d samples %8ld avg %9ld\n", j, i, n, avg);
      }
    }
    total_avg = (total_avg / non_zero) << sum_shift;

    if(total_n != 0)
      printf("CPUS    slot %3d samples %8ld avg %9ld\n", i, total_n, total_avg);
  }
  free(slot);

  return 0;
}

int list_trace()
{
  char path[MAX_PATH_SIZE];
  get_path(path, NULL, NULL);

  DIR *d;
  struct dirent *dir;
  d = opendir(path);
  if (d) {
    while ((dir = readdir(d)) != NULL) {
      if(strcmp(dir->d_name, ".") && strcmp(dir->d_name, ".."))
        printf("%s\n", dir->d_name);
    }
    closedir(d);
  }
  else
    return 1;
  return 0;
}

int main(int argc, char *argv[])
{
  int err;
  char *S = NULL, *X = NULL, *Y = NULL, path[MAX_PATH_SIZE];  /*tcp_v4_connect*/
  int B = 0;

  /* creation of the master directory in the virtual bpf file system */
  struct stat buf;
  get_path(path, NULL, NULL);
  if (stat(path, &buf) == -1){
    if(mkdir(path, 0700)){
      printf("ERROR: failed to create directory in bpf file system, are you sudoers?\n");
      return 0;
    }
  }

  /* set printf function for libbpf */
  libbpf_set_print(libbpf_print_fn);

  /* expand memory limitt */
	err = bump_memlock_rlimit();
  if(err){
    printf("ERROR: failed to expand memory limit, are you sudoers?\n");
    return 0;
  }

  /*
    command format:
      trace S bits B start X end Y
        S : name of the trace                                    [not optional]
        B : precision, number of bits after fls                  [optional if omitted is equal to 0]
        X : name of the function to start the timer              [optional if omitted is equal to S]
        Y : name of the function or tracepoint  to end the timer [optional if omitted is equal to S]
        Ex:
          "./bpfstats trace sleep bits 3 start msleep"
  */
  if (argc < 2 || argc > 9){
    printf("ERROR: failed to execute command, wrong number of arguments\n");
	} else if (argc > 2 && !strcasecmp(argv[1], "remove")) { // remove pinned ebpf
    S = argv[2];
    err = remove_trace(S);
	} else if (argc > 2 && !strcasecmp(argv[1], "trace")) {  // add new bpf
    S = argv[2];

    /* the commands after trace S could be in a random order */
    for(int i = 3; (i + 1) < argc; i += 2){
      if(!strcasecmp(argv[i], "bits")){
        sscanf(argv[i + 1], "%d", &B);
      }else if(!strcasecmp(argv[i], "start")){
        X = argv[i + 1];
      }else if(!strcasecmp(argv[i], "end")){
        Y = argv[i + 1];
      }
    }
    X = X ? X : S;
    Y = Y ? Y : X;

    if(B < 0 || B > 3){
      printf("ERROR: failed to execute command, number of bits should be between 0 and 3\n");
    }else{
      err = create_trace(S, B, X, Y);
    }

	} else if(argc > 2 && !strcasecmp(argv[1], "read")){
    S = argv[2];
    err = read_trace(S);
  }else if(!strcasecmp(argv[1], "list")){
    err = list_trace();
  }else{
    printf("ERROR: failed to execute command, \"%s\" command not found.\n", argv[1]);
	}

  if(err)
    printf("ERROR: failed to execute command %s\n", argv[1]);

  exit(0);
}
