from scapy.all import *
from scapy.arch import get_if_raw_hwaddr
from scapy.utils import mac2str
from mac_vendor_lookup import MacLookup
from ipaddress import ip_address
from dns import resolver
from dns import rdatatype
from dns.resolver import LifetimeTimeout
from dns.nameserver import Do53Nameserver
from argparse import ArgumentParser
from sys import exit, platform
from psutil import net_if_addrs

# Handle cross-platform interface specifics
if sys.platform == 'win32':
    from socket import AF_LINK
elif sys.platform == 'linux':
    from socket import AF_PACKET
else:
    exit(-1)

parser = ArgumentParser(
    prog="query_dhcp", description="Query network for DHCP server(s)"
)


mac_group = parser.add_mutually_exclusive_group(required=True)

mac_group.add_argument(
    "-m",
    "--macs",
    nargs="+",
    type=str,
    required=False,
    help="Provide a space-separated list of MACs in AA:BB:CC:DD:EE:FF A1:B2:C3:D4:E5:F6 format.",
)

mac_group.add_argument(
    "-i",
    "--interfaces",
    nargs="+",
    type=str,
    required=False,
    help="Provide a space-separated list of interface names."
    )

parser.add_argument(
    "-t",
    "--timeout",
    type=int,
    default=1,
    help="Provide an integer number of seconds to wait for DHCP and reverse DNS queries.  Defaults to 1.",
)
parser.add_argument(
    "--output",
    action="store_true",
    help="Provide this argument to print output to stdout.",
)

args = parser.parse_args()

# print(args)

# Compose list of MAC addresses if provided with interface(s)

if args.macs:
    macs = args.macs
else:
    # Make a list to store MACs
    macs = []

    for interface_name in args.interfaces:
        # Each interface can have multiple snicaddr objects, check them
        interface_addresses = net_if_addrs()[interface_name]
        for interface_address in interface_addresses:
            # Check the family attribute type as we want AF_LINK or AF_PACKET (per source code these are aliases on Linux)
            # Handle cross-platform interface specifics
            if sys.platform == 'win32':
                if interface_address.family.name is AF_LINK.name:
                    # This is our MAC address, fix Windows formatting
                    macs.append(interface_address.address.replace('-',':'))
            elif sys.platform == 'linux':
                if interface_address.family.name is AF_PACKET.name:
                    # This is our MAC address
                    macs.append(interface_address.address)
            else:
                exit(-1)

    print("macs are " + str(macs))


# Instantiate DNS resolver for later use
resolver = resolver.Resolver()


# Dynamically cast bytes
def bytes2str(s):
    if type(s) is str:
        # Return back if already  a string
        return s
    elif type(s) is bytes:
        try:
            # Try to decode
            return s.decode("utf-8")
        except (UnicodeDecodeError, AttributeError) as err:
            return str(err)
    else:
        # Do a lazy casting if anything opther than str/bytes
        return str(s)


DHCP_MSG_CODES = {
    1: "DHCPDISCOVER (1)",
    2: "DHCPOFFER (2)",
    3: "DHCPREQUEST (3)",
    4: "DHCPACK (4)",
    5: "DHCPNACK (5)",
    6: "DHCPRELEASE (6)",
    7: "DHCPINFORM (7)",
    8: "DHCPDECLINE (8)",
}

# Do not check IP validity
# Outgoing packet dst is broadcast IP addr
# Returning packet src is DHCP server IP addr
# Since they don't match, scapy will drop response by default
conf.checkIPaddr = False

# Compose DHCP options
dhcp_options = [("message-type", "discover"), ("domain"), ("end")]

# Craft a discovery packet
dhcp_discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff")
    / IP(src="0.0.0.0", dst="255.255.255.255")
    / UDP(dport=67, sport=68)
    / BOOTP(chaddr=get_if_raw_hwaddr(conf.iface)[1])
    / DHCP(
        options=[
            ("message-type", "discover"),
            ("hostname", "hostname"),
            (
                "param_req_list",
                [
                    int(scapy.all.DHCPRevOptions["domain"][0]),
                    int(scapy.all.DHCPRevOptions["name_server"][0]),
                ],
            ),
            ("end"),
        ]
    )
)

# Instantiate an async sniffer
sniffer = AsyncSniffer()
sniffer.start()
# Flood the network with DHCP packets
srpflood(dhcp_discover, verbose=0, timeout=args.timeout)
# Save our results
results = sniffer.stop()

# Create a list to store our offers
offers = {}

for result in results:
    # result.show() # Shows full packet layer cake
    # result is a list of layers
    # We only care if the 'DHCP' class is present in the packet's layers
    if DHCP in result:
        # We only care about DHCPOFFER
        if ("message-type", 2) in result[DHCP].options:
            # Check that our DHCP server's MAC is valid, exit with error if not
            if result.src not in macs:
                print(
                    f"Script returned an unknown DHCP server.\nPermitted MACs: {macs}\nDHCP MAC: {result.src}",
                    file=sys.stderr,
                )
                exit(-1)
            else:
                pass

            # Pack our data in dicts for convenient access
            bootp_payload = {
                "src": result.src,  # src MAC
                "dst": result.dst,  # dst MAC
                "siaddr": result[BOOTP].siaddr,  # IP of server assigning
                "yiaddr": result[BOOTP].yiaddr,  # IP assigned to client
                # MAC reported to server by client
                # Truncate the trailing 10/16 empty bytes, then convert back to encoded string
                "chaddr": str2mac(result[BOOTP].chaddr[0:6]),
            }

            dhcp_payload = {}

            # Iterate through tuple-list to convert to dict
            for option in result[DHCP].options:
                # Abort if 'end' is reached
                if option[0] == "end":
                    break
                if option[0] == "message-type":
                    # Substitute our friendly message type name
                    dhcp_payload[option[0]] = DHCP_MSG_CODES[option[1]]
                else:
                    # First element of tuple becomes dictionary key
                    # Remaining elements become value

                    dhcp_payload_key = option[0]

                    dhcp_payload_data = option[1]

                    dhcp_payload[dhcp_payload_key] = dhcp_payload_data

            # Check to see if our responding server is accounted for, use MAC as identifier
            if str(bootp_payload["src"]) in offers.keys():
                pass
            else:
                # Populate dict using IP and MAC as key
                offers[str(bootp_payload["src"])] = {
                    "bootp_payload": bootp_payload,
                    "dhcp_payload": dhcp_payload,
                }

# If the number of unique offers is less than valid MACs exit with error code
if len(offers.keys()) < len(macs):
    print("Fewer than configured DHCP offers received.", file=sys.stderr)
    exit(-1)

for offer in offers.keys():
    mac_address = offers[offer]["bootp_payload"]["src"]
    ns_addresses = offers[offer]["dhcp_payload"][
        "name_server"
    ]  # Note this returns tuple if multiple, str if singleton

    if type(ns_addresses) is str:
        ns1_address = ns_addresses
    elif type(ns_addresses) is tuple:
        ns1_address = ns_addresses[0]
    else:
        raise Exception("Could not process returned name server(s)!", file=sys.stderr)
        exit(-1)

    # Reverse lookup our first server's name
    # Create nameserver object for lookup

    resolver.nameservers = [Do53Nameserver(address=ns1_address)]

    reversed_dhcp_server_address = str(
        ip_address(offers[offer]["dhcp_payload"]["server_id"]).reverse_pointer
    )

    # Try/catch for resolution failure -- soft fail, as rDNS may not be in place
    try:
        resolved_string = resolver.resolve(
            # Resolve the first response we received
            reversed_dhcp_server_address,
            rdtype=rdatatype.PTR,
        )[
            0
        ]  # Only one address resolved only one resultant output

    except (LifetimeTimeout, Exception) as err:
        # print(str(err))
        resolved_string = "Reverse DNS lookup failed, check DNS zone."

    name_server = offers[offer]["dhcp_payload"]["name_server"]

    if type(name_server) is str:
        name_server_string = name_server
    elif type(name_server) is tuple:
        name_server_string = ", ".join(name_server)

    if args.output:
        print(
            "\nServer Hostname (rDNS): %s\nServer Vendor: %s\nServer IP: %s\nServer MAC: %s\nServer Domain: %s\nDomain Name Servers: %s\nClient Issued IP: %s"
            % (
                resolved_string,
                MacLookup().lookup(mac_address),
                offers[offer]["dhcp_payload"]["server_id"],
                offers[offer]["bootp_payload"]["src"],
                bytes2str(offers[offer]["dhcp_payload"]["domain"]),
                name_server_string,
                offers[offer]["bootp_payload"]["yiaddr"],
            )
        )
