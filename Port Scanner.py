import socket
import sys
import pyfiglet
from datetime import datetime

banner = pyfiglet.figlet_format("Port Scanner")
print(banner)

target = input("Please Enter host to Scan: ")
# target = "localhost"
host = socket.gethostbyname(target)
try:
    file = open("Port-Scanner-2.txt", "w")
except FileExistsError:
    print("File Exists Error")
    sys.exit()

date = datetime.date(datetime.now())
t1 = datetime.now()

print("Start Time:{}".format(t1.strftime("%H:%M:%S")))
file.write("Start Time: {} \n\n".format(t1.strftime("%H:%M:%S")))
try:

    for port in range(1, 1025):
        # AF_INET means IP4 address. AF_INET6 means IP6 address
        # SOCK_STREAM means we are using TCP. SOCK_DGRAM for UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.001)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                print("Port No: {} Open Protocol Service Name: {}".format(port, socket.getservbyport(port, "tcp")))
                file.write("\nPort No : {} Open Protocol Service Name: {}".format(port, socket.getservbyport(port, "tcp")))
            except socket.error:
                print("Port No: {} Open Protocol Service Name".format(port, socket.getservbyport(port, "Unknown")))
                file.write("\nPort No: {} Open Protocol Service Name".format(port, socket.getservbyport(port, "Unknown")))

except socket.gaieerror:
    print("HostName could not resolved. Existing")
    file.write("\n\nHostName could not resolved. Existing")
    sys.exit()
except socket.error:
    print("Couldn't Connect to Server. Existing")
    file.write("\n\nCouldn't Connect to Server. Existing")
    sys.exit()

t2 = datetime.now()
print("End Time: {}".format(t2.strftime("%H:%M:%S")))
file.write("\n\nEnd Time: {}".format(t2.strftime("%H:%M:%S")))


total_time = t2 - t1
print("Total Time: {}".format(total_time))
file.write("\n\nTotal Time: {}".format(total_time))

