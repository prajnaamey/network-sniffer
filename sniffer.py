# Importing the necessary modules
import logging
import subprocess

# This will suppress all messages that have a lower level
# of seriousness than error messages, while running or loading Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


try:
    from scapy.all import *

except ImportError:
    print "Scapy package for Python is not installed on your system."
    print "Get it from https://pypi.python.org/pypi/scapy and try again."
    sys.exit()


print "\n! Make sure to run this program as ROOT !\n"

net_iface = raw_input(
    "* Enter the interface on which to run the sniffer (like 'eth1'): ")

subprocess.call(["ifconfig", net_iface, "promisc"],
                stdout=None, stderr=None, shell=False)

print "\nInterface %s was set to PROMISC mode." % net_iface
print

# Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = raw_input(
    "Enter the number of packets to capture (0 is infinity): ")

# Considering the case when the user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print "\nThe program will capture %d packets." % int(pkt_to_sniff)
    print
elif int(pkt_to_sniff) == 0:
    print "\nThe program will capture packets until the timeout expires."
    print


# Asking the user for the time interval to sniff (the "timeout" parameter)
time_to_sniff = raw_input("* Enter the number of seconds to run the capture: ")

# Handling the value entered by the user
if int(time_to_sniff) != 0:
    print "\nThe program will capture packets for %d seconds." % int(time_to_sniff)
    print


# Asking the user for any protocol filter he might want to apply to the sniffing process
proto_sniff = raw_input(
    "* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")

# Considering the case when the user enters 0 (all)
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print "\nThe program will capture only %s packets." % proto_sniff.upper()
    print
elif int(proto_sniff) == 0:
    print "\nThe program will capture all protocols."
    print


# Creating an external file for packet logging
file_name = raw_input("* Please give a name to the log file: ")
sniffer_log = open(file_name, "w")


# Initializing the packet counter
packet_no = 0


# This is the function that will be applied to each captured packet
# The function will extract some parameters from the packet and then log
# each packet to an external file
def packet_log(pkt):
    # The packet index
    global packet_no

    # Filtering the packets based on the protocol. Using the lower() method to
    # ignore the case when searching for the protocol in the packet.
    if proto_sniff.lower() in pkt[0][1].summary().lower():
        packet_no = packet_no + 1
        # Writing the data for each packet to the external file
        print >>sniffer_log, "Packet " + \
            str(packet_no) + ": " + "SMAC: " + \
            pkt[0].src + " DMAC: " + pkt[0].dst


print "Starting the capture... Waiting for %s seconds..." % time_to_sniff

# Running the sniffing process
pkt = sniff(iface=net_iface, count=int(pkt_to_sniff),
            timeout=int(time_to_sniff), prn=packet_log)

# print pkt.show()

# Printing the closing message
print "The timeout of %s seconds has passed." % time_to_sniff
print "Please check the %s file to see the captured packets." % file_name


# Closing the log file
sniffer_log.close()
