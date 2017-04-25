
import argparse
import socket


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('server', help='Server to connect to')
    parser.add_argument('port', help='Port to connect to', type=int)

    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.connect((args.server, args.port))

    try:
        while True:
            data = input('>>> ')
            sock.send(bytes(data, 'utf-8'))
            resp = sock.recv(1024)
            print('<<<', str(resp, 'utf-8'))
    except KeyboardInterrupt:
        print('Bye')
        exit()


if __name__ == '__main__':
    main()
