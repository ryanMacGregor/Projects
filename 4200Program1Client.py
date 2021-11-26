#RYAN MACGREGOR
#CSC_4200-001

import socket
import struct
import sys
import time
DECODING = 'utf-8'

# creates packets of data to send
def createPacket(format, version, type, message):
    structInfo = struct.Struct(format)
    length = len(message)
    packedInfo = struct.pack(format, version, type, length, message.encode(DECODING))
    return packedInfo


# create the socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    ip = sys.argv[1]
    port = int(sys.argv[2])
    logFile = sys.argv[3]
    file = open('logFile.log', "a")
except Exception as ex:
    print("Invalid command line arguments: Client.py <ip> <port> <log file>")
    print(ex)
    sys.exit(0)

#REMOTE_ADDR = socket.gethostbyname(socket.gethostname())

SERVER_ADDR = (ip, port)
# encoded_message  = message.encode(ENCODING)
# length_msg = str(len(encoded_message)).encode(ENCODING)

# CONNECT

print("Connecting to {0}....".format(ip))

client.connect(ip)

print("Connected to: ", ip)

# create struct
format = "iii8s"
packedInfo = createPacket(format, 17, 1, "Hello")

# step 3 - send Binary data
print("Sending: ", packedInfo)
client.sendall(packedInfo)

# recieving hellopacket

unpacker = struct.Struct('iii8s')
packed_data = client.recv(unpacker.size)
data = unpacker.unpack(packed_data)

print("Received Data : Version: {0}, Message_Type: {1}, Length: {2}".format(data[0], data[1], data[2]))
message = data[3].decode(DECODING).strip().strip('\x00')
print("Recieved Message: ", message)

if (data[0] == 17):
    file.write("VERSION ACCEPTED\n")
    packedInfo = createPacket(format, 17, 2, "LIGHTOFF")
    client.sendall(packedInfo)
else:
    file.write("VERISON MISMATCH\n")

packed_data = client.recv(unpacker.size)
data = unpacker.unpack(packed_data)
print("Recieved Data: Version: {0}, Message_Type: {1}, Length: {2}".format(data[0], data[1], data[2]))
message = data[3].decode(DECODING).strip().strip('\x00')
print("Recieved Message: ", message)
file.write("Message Recieved: {0}\n".format(message))

time.sleep(1)
print("Closing Socket")
client.close()
file.close()
