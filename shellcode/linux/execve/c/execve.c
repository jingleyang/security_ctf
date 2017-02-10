#include <stdio.h>
#include <unistd.h>

int main(){
	char * target = "//bin/sh";
	char * para_list[2] = { target, NULL};
	int ret = execve(target, para_list, NULL);
	return ret;
}
