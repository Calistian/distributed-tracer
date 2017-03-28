#include <iostream>
#include <string>
#include <array>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

int main()
{
	cout << "Press enter to start..." << flush;
	getchar();
	int sock, client;
	uint32_t clilen;
	sockaddr_in addr, client_addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(!sock)
	{
		cerr << "Could not create socket" << endl;
		return 1;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(20000);
	addr.sin_addr.s_addr = INADDR_ANY;

	if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		cerr << "Could not bind" << endl;
		return 1;
	}

	listen(sock, 5);
	clilen = sizeof(client_addr);
	client = accept(sock, (struct sockaddr*)&client_addr, &clilen);
	if(client < 0)
	{
		cerr << "Could not accept" << endl;
		return 1;
	}
	array<char, 1024> buf;
	for(;;)
	{
		size_t len = recv(client, buf.data(), buf.size(), 0);
		string s = buf.data();
		cout << "Received " << s << " from " << hex << htonl(client_addr.sin_addr.s_addr) << endl;
		send(client, buf.data(), len, 0);
	}
	return 0;
}