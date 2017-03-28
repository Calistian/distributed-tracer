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
	int sock;
	sockaddr_in server_addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(!sock)
	{
		cerr << "Cant create socket" << endl;
		return 1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(20000);
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if(connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		cerr << "Can't connect" << endl;
		return 1;
	}
	cout << "Here" << endl;

	array<char, 1024> buf;
	string input;
	cout << ">>> ";
	while(getline(cin, input))
	{
		send(sock, input.c_str(), input.size() + 1, 0);
		size_t len = recv(sock, buf.data(), buf.size(), 0);
		input = buf.data();
		cout << "<<< " << input << endl;
		cout << ">>> ";
	}
	return 0;
}