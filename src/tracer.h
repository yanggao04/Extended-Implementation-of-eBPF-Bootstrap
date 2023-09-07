#ifndef __TRACER_H
#define __TRACER_H

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
};

struct event_time {
	char filename[MAX_FILENAME_LEN];
	char ts[32]; //time
};

#endif
