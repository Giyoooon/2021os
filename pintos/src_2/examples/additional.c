#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
	int fibo_a;
	int max_of_abcd;
	int a,b,c,d;

	if(argc != 5){
		printf("additional: usage: additional (int)arg1 (int)arg2 (int)arg3 (int)arg4\n");
		return EXIT_FAILURE;
	}
	//fibo_a = fibonacci(a);	
	a = atoi(argv[1]);
	b = atoi(argv[2]);
	c = atoi(argv[3]);
	d = atoi(argv[4]);
	fibo_a = fibonacci(a);
	//printf("\n\n\nadditional\na=%d\nb=%d\nc=%d\nd=%d\n\n",a,b,c,d);
	max_of_abcd = max_of_four_int(a,b,c,d);
	printf("%d %d\n",fibo_a, max_of_abcd);
	return EXIT_SUCCESS;
}
