#RYAN MACGREGOR
#CSC_4200-001

import socket
import threading
import struct
import sys


ENCODING = 'utf-8'


# creates packets of data to send
def createPacket(format, version, type, message):
    structInfo = struct.Struct(format)
    length = len(message)
    packedInfo = struct.pack(format, version, type, length, message.encode(ENCODING))
    return packedInfo


# Lighton function
def lighton():
    print("Lights are on.")


# Lightoff function
def lightoff():
    print("Lights are off.")


def handle_client(conn, addr):
    print("Handling connection from {}".format(addr))
    while conn:
        message_header = conn.recv(25)  # had (1) originally
        decoded_message = message_header.decode(ENCODING)
        print("Received message length from client: {}".format(decoded_message))
        message_body_length = int(decoded_message)

        message_body = conn.recv(message_body_length)
        decoded_message_body = message_body.decode(ENCODING)
        print("Received message from client: {}".format(decoded_message_body))
        break
        # TODO: handle connection closing from client


if __name__ == '__main__':
    # create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # create a UDP socket
    # server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    IP_ADDR = socket.gethostbyname(socket.gethostname())
    # gethostbyname()

    # Parse command line arguments
    try:
        port = sys.argv[1]
        logFile = sys.argv[2]
        file = open('logFile.log', "w")
    except:
        print("Invalid command line arguments: Server.py <port> <logFile>")
        sys.exit(0)

    # step 2 - specify where the server should listen on, IP and port
    SERVER_ADDR = (IP_ADDR, port)
    print("Received connection from (IP, port): {}".format(SERVER_ADDR))
    server_socket.bind(SERVER_ADDR)

    # step 3 - do the listening
    server_socket.listen()

    # print("Received Data: Version 17 message_type: 1 Length:{}".format(port))

    # while connected to the client
    while True:

        connection, address = server_socket.accept()
        print("")
        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()

        # step 5 - keep listening
        unpacker = struct.Struct('iii8s')
        format = "iii8s"

        with connection as conn:
            try:
                while True:
                    packed_data = conn.recv(unpacker.size)
                    data = unpacker.unpack(packed_data)

                    print("Received Data : Version: {0}, Message_Type: {1}, Length: {2}".format(data[0], data[1], data[2]))
                    message = data[3].decode(ENCODING).strip().strip('\x00')
                    print("Message: ", message)

                    if (message.rstrip() == "Hello" and data[0] == 17):
                        print("Sent: Hello")
                        file.write("Hello sent from client. \n")
                        helloPacket = createPacket(format, 17, 1, "Hello")
                        conn.sendall(helloPacket)
                    if (data[0] == 17):
                        if (data[1] == 1):
                            print("EXECUTING SUPPOERTING COMMAND: LIGHTON")
                            file.write("EXECUTING SUPPOERTING COMMAND: LIGHTON\n")
                            lighton()
                            successPacket = createPacket(format, 17, 1, "SUCCESS")
                        elif (data[1] == 2):
                            print("EXECUTING SUPPOERTING COMMAND: LIGHTOFF")
                            file.write("EXECUTING SUPPOERTING COMMAND: LIGHTOFF")
                            lightoff()
                            successPacket = createPacket(format, 17, 1, "SUCCESS")
                            conn.sendall(successPacket)
                        else:
                            file.write("IGNORING UNKNOWN COMMAND: {0}\n".format(data[1]))
                            print("Error unsupported type ")
                            print("")
            except KeyboardInterrupt:
                server_socket.close()
                file.close()
            finally:
                server_socket.close()
                file.close()


