
import argparse
import threading
import socket


def do_client(sock, addr):
    print('Client connected :', addr)
    try:
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            data = str(data, 'utf-8')
            sock.send(bytes(data.upper(), 'utf-8'))
    except socket.error:
        pass
    print('Client disconnected : ', addr)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('port', help='Port to listen to', type=int)

    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind(('0.0.0.0', args.port))

    sock.listen(5)

    try:
        while True:
            client, addr = sock.accept()
            t = threading.Thread(target=do_client, args=(client, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print('Bye')
        exit()


if __name__ == '__main__':
    main()
