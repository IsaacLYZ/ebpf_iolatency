#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_table(__u32 * hist)
{
	const char *stars="****************************************";
	int max=1;
	for(int i=0;i<17;++i)
		if(hist[i]>max)
			max=hist[i];

	printf("%8susces%8s : count     distribution\n","","");
	for(int i=0;i<17;++i){
		__u32 star_index = (1 - (double)hist[i] / max) * 40;
		if(star_index>40)
			star_index=40;
		printf("%9d -> %-9d: %-9d|%-40s|\n",(1<<i)-1,1<<i,hist[i],stars+star_index);
	}
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog[3];
    struct bpf_link *link[3];
	struct bpf_map *hist;
    int prog_fd[3], hist_fd;
	__u32 count[17];
	char *func[]={"handle_block_rq_issue","handle_block_rq_complete"};
	char *tp[]={"block_rq_issue","block_rq_complete"};

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

	for(int i=0;i<2;++i){
		// Attach BPF program
		fprintf(stderr, "Attaching BPF program %d to tracepoint\n", i);
		prog[i] = bpf_object__find_program_by_name(obj, func[i]);
		if (libbpf_get_error(prog)) {
			fprintf(stderr, "ERROR: finding BPF program %d failed\n", i);
			return 1;
		}
		prog_fd[i] = bpf_program__fd(prog[i]);
		if (prog_fd < 0) {
			fprintf(stderr, "ERROR: getting BPF program FD %d failed\n", i);
			return 1;
		}
		link[i] = bpf_program__attach_tracepoint(prog[i], "block", tp[i]);

		if (libbpf_get_error(link[i])) {
			fprintf(stderr, "ERROR: Attaching BPF program %d to tracepoint failed\n", i);
			return 1;
		}
	}

	// Get hist array
	hist = bpf_object__find_map_by_name(obj, "latency_hist");
	if (libbpf_get_error(hist)) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }
	hist_fd = bpf_map__fd(hist);

	// Initialize total counts
    for (int i = 0; i < 17; i++) {
        __u32 value = 0;
		bpf_map_update_elem(hist_fd,&i,&value,BPF_ANY);
    }

	while(1){
		sleep(5);
		// Read and reset counts
		for (int i = 0; i < 17; i++) {
			__u32 value = 0;
			bpf_map_lookup_elem(hist_fd,&i,count+i);
			bpf_map_update_elem(hist_fd,&i,&value,BPF_ANY);
		}

		// Print counts
		system("clear");
		print_table(count);
	}


    printf("BPF tracepoint program attached. Press ENTER to exit...\n");
    getchar();

    // Cleanup
	for(int i=0;i<3;++i)
    	bpf_link__destroy(link[i]);
    bpf_object__close(obj);

    return 0;
}
