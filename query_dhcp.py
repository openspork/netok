from scapy.all import *
from scapy.arch import get_if_raw_hwaddr
from scapy.utils import mac2str
from mac_vendor_lookup import MacLookup
from ipaddress import ip_address
from dns import resolver
from dns import rdatatype
from dns.resolver import LifetimeTimeout
from dns.nameserver import Do53Nameserver


# Instantiate DNS resolver for later use
resolver = resolver.Resolver()


# Dynamically cast bytes
def bytes2str(s):

    # TODO: Add logic for tuple/list/dict nested bytes

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
srpflood(dhcp_discover, timeout=1)
# srp(dhcp_discover,timeout=1) # Insufficient to fully hit all DHCP servers
# Save our results
results = sniffer.stop()

# Create a list to store our offers
offers = {}

for result in results:
    # result.show() Shows full packet layer cake
    # result is a list of layers
    # We only care if the 'DHCP' class is present in the packet's layers
    if DHCP in result:
        # print(f'Found DHCP traffic: {DHCP_MSG_CODES[result[DHCP].options[0][1]] }')
        # We only care about DHCPOFFER
        if ("message-type", 2) in result[DHCP].options:
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
                    # dhcp_payload[option[0]] = bytes2str(option[1])

                    # First element of tuple becomes dictionary key
                    # Remaining elements become list

                    dhcp_payload_key = option[0]

                    if len(option[1:]) <= 1:
                        # If the length of the tuple is 1 or less, there is a single element or None, save as string
                        #print("lenght of of tuple <= 1")
                        dhcp_payload_data = bytes2str(option[1])
                        #print(dhcp_payload_data)
                    else:
                        #print("lenght of tuple >1")
                        dhcp_payload_data = bytes2str(option[1:])

                        dhcp_payload_data = option[1:]  # Tuple elements 1 thru N

                    dhcp_payload[dhcp_payload_key] = (
                        dhcp_payload_data  # bytes2str(option[1])
                    )

            # Check to see if our responding server is accounted for, use MAC + IP as identifier
            if (
                str(dhcp_payload["server_id"]) + "@" + str(bootp_payload["src"])
                in offers.keys()
            ):
                # print('Already exists: ' + dhcp_payload['server_id'] + '@' + bootp_payload["src"])
                pass
            else:
                print(
                    "Adding: "
                    + str(dhcp_payload["server_id"])
                    + "@"
                    + str(bootp_payload["src"])
                )

                # Populate dict using IP and MAC as key
                offers[
                    str(dhcp_payload["server_id"]) + "@" + str(bootp_payload["src"])
                ] = {
                    "bootp_payload": bootp_payload,
                    "dhcp_payload": dhcp_payload,
                }

print(f"\nDHCP Server Inventory:\n")
for offer in offers.keys():
    mac_address = offers[offer]["bootp_payload"]["src"]
    ns_addresses = offers[offer]["dhcp_payload"]["name_server"]

    # Reverse lookup our first server's name

    # Create nameserver objects for lookup
    nameservers = []
    for ns_address in ns_addresses:
        nameservers.append(Do53Nameserver(address=ns_address))

    # Add the array of nameservers to our resolver
    resolver.nameservers = nameservers

    #print('ns addresses', ns_addresses)
    #print('first ns address', ns_addresses[0])
    #print(type(ns_addresses))

    #print('ns addresses:' , ns_addresses)
    #print('type ns addresses: ', type(ns_addresses))

    # TODO standardize tuples
    if type(ns_addresses) is str:
        formal_ip = ip_address(ns_addresses)
    elif type(ns_addresses) is tuple:
        formal_ip = ip_address(ns_addresses[0])
    else:
        print('WTFFFFFFFFFFFFFFF')
    
    #print('formal ip', formal_ip)

    reversed_ns_address = formal_ip.reverse_pointer

    #print('reversed: ', reversed_ns_address)
    #print(type(reversed_ns_address))

    # Try/catch for resolution failure
    try:
        resolved_string = resolver.resolve(
            # Resolve the first response we received
            reversed_ns_address,
            rdtype=rdatatype.PTR,
        )[0] # Only one address resolved only one resultant output

    except (LifetimeTimeout, Exception) as err:
        # print(str(err))
        resolved_string = "Reverse DNS lookup failed, check DNS zone."

    # TODO FIX TUPLES
    name_server = offers[offer]["dhcp_payload"]["name_server"]

    if type(name_server) is str:
        name_server_string = name_server
    elif type(name_server) is tuple:
        name_server_string = ", ".join(name_server)


    print(offers[offer])


    print(
        "Server Hostname (rDNS): %s\nServer Vendor: %s\nServer IP: %s\nServer MAC: %s\nServer Domain: %s\nDomain Name Servers: %s\nClient Issued IP: %s"
        % (
            resolved_string,
            MacLookup().lookup(mac_address),
            offers[offer]["dhcp_payload"]["server_id"],
            offers[offer]["bootp_payload"]["src"],
            offers[offer]["dhcp_payload"]["domain"],
            name_server_string,
            offers[offer]["bootp_payload"]["yiaddr"],
        )
    )


    print(offers[offer])

    # # print(offers[offer])
