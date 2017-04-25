
import argparse
import socket


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('recv_port', help='Port to listen to', type=int)
    parser.add_argument('srv_addr', help='Server address')
    parser.add_argument('srv_port', help='Server port', type=int)

    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    server.connect((args.srv_addr, args.srv_port))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind(('0.0.0.0', args.recv_port))

    sock.listen(1)

    try:
        while True:
            client, addr = sock.accept()
            print('Client connected : ', addr)
            while True:
                data = client.recv(1024)
                if len(data) == 0:
                    break
                print('<<<', str(data, 'utf-8'))
                server.send(data)
                data = server.recv(1024)
                print('>>>', str(data, 'utf-8'))
                client.send(data)
            print('Client disconnected : ', addr)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
