#include <bpf/btf.h>
#include <gelf.h>
#include <linux/types.h>

struct list_head;

struct list_head{
  struct list_head* next, *prev;
};

struct bpf_program {
	/* Index in elf obj file, for relocation use. */
	int idx;
	char *name;
	int prog_ifindex;
	char *section_name;
	const struct bpf_sec_def *sec_def;
	/* section_name with / replaced by _; makes recursive pinning
	 * in bpf_object__pin_programs easier
	 */
	char *pin_name;
	struct bpf_insn *insns;
	size_t insns_cnt, main_prog_cnt;
	enum bpf_prog_type type;
	bool load;

	struct reloc_desc *reloc_desc;
	int nr_reloc;
	int log_level;

	struct {
		int nr;
		int *fds;
	} instances;
	bpf_program_prep_t preprocessor;

	struct bpf_object *obj;
	void *priv;
	bpf_program_clear_priv_t clear_priv;

	enum bpf_attach_type expected_attach_type;
	__u32 attach_btf_id;
	__u32 attach_prog_fd;
	void *func_info;
	__u32 func_info_rec_size;
	__u32 func_info_cnt;

	void *line_info;
	__u32 line_info_rec_size;
	__u32 line_info_cnt;
	__u32 prog_flags;
};

struct bpf_object {
	char name[BPF_OBJ_NAME_LEN];
	char license[64];
	__u32 kern_version;

	struct bpf_program *programs;
	size_t nr_programs;
	struct bpf_map *maps;
	size_t nr_maps;
	size_t maps_cap;

	char *kconfig;
	struct extern_desc *externs;
	int nr_extern;
	int kconfig_map_idx;

	bool loaded;
	bool has_pseudo_calls;

	/*
	 * Information when doing elf related work. Only valid if fd
	 * is valid.
	 */
	struct {
		int fd;
		const void *obj_buf;
		size_t obj_buf_sz;
		Elf *elf;
		GElf_Ehdr ehdr;
		Elf_Data *symbols;
		Elf_Data *data;
		Elf_Data *rodata;
		Elf_Data *bss;
		Elf_Data *st_ops_data;
		size_t strtabidx;
		struct {
			GElf_Shdr shdr;
			Elf_Data *data;
		} *reloc_sects;
		int nr_reloc_sects;
		int maps_shndx;
		int btf_maps_shndx;
		__u32 btf_maps_sec_btf_id;
		int text_shndx;
		int symbols_shndx;
		int data_shndx;
		int rodata_shndx;
		int bss_shndx;
		int st_ops_shndx;
	} efile;
	/*
	 * All loaded bpf_object is linked in a list, which is
	 * hidden to caller. bpf_objects__<func> handlers deal with
	 * all objects.
	 */
	struct list_head list;

	struct btf *btf;
	/* Parse and load BTF vmlinux if any of the programs in the object need
	 * it at load time.
	 */
	struct btf *btf_vmlinux;
	struct btf_ext *btf_ext;

	void *priv;
	bpf_object_clear_priv_t clear_priv;

	char path[];
};
