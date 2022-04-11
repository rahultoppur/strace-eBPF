#include <stdlib.h>
#include <stdio.h>

int main() {
	const int n = snprintf(NULL, 0, "%lu", 94580908290096);
	char buf[n+1];
	sprintf(buf, n+1, "%lu", 94580908290096);

}

