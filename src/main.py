import ipaddress
import subprocess
import sys
import yaml


def check_interface_status(interface):
    this_process = subprocess.Popen(f'ip link show "{interface}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    first_line = (this_process.stdout.readlines()[0]).decode("utf-8")
    returned_status = this_process.wait()
    if returned_status == 0 and 0 < first_line.find(" state UP "):
        return True
    elif returned_status == 0 and 0 < first_line.find(" state DOWN "):
        print(f"INFO: Interface {interface} is down.")
        return False
    elif returned_status == 1 or 0 < first_line.find(" does not exist."):
        print(f"ERROR: Interface {interface} does not exist.")
        return False
    else:
        print(f"ERROR: Cannot get information from interface {interface}.")
        return False


def is_valid_ip_address(address, network = None, silent=False):
    try:
        ip_address = ipaddress.ip_address(address)
        if network:
            try:
                ip_network = ipaddress.ip_network(network, strict=False)
                if ip_address in list(ip_network.hosts()):
                    return True
                else:
                    if not silent:
                        print(f"ERROR: Network {network} does not contains IP address {address} in its range.")
                    return False
            except ValueError:
                if not silent:
                    print(f"ERROR: Invalid network for IP address {address}: {network}")
                return False
        else:
            return True
    except ValueError:
        if not silent:
            print(f"ERROR: Invalid IP address: {address}")
        return False


def is_valid_network(address):
    try:
        ip_network = ipaddress.ip_network(address, strict=False)
        if len(list(ip_network.hosts())) < 4:
            print(f"ERROR: Network {address} does not contains enough hosts.")
            return False
        else:
            return True
    except ValueError:
        print(f"ERROR: Invalid network address: {address}")
        return False


def read_configuration(filename):
    data_from_file = {}
    configuration_data = {}
    try:
        with open(filename) as stream:
            try:
                data_from_file = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(f"ERROR: Failure parsing {filename} file!")
                print(exc)
                sys.exit(1)
    except:
        print("ERROR: Cannot read configuration file!")
        sys.exit(1)

    # Will not validate configuration right now
    return data_from_file


def generate_netplan_file(config):
    ethernets = {}
    for each_network in config.get("general", {}).get("networks", []):
        interface = each_network.get("interface")
        if not isinstance(interface, str) or interface == "":
            print(f"ERROR: Missing or invalid 'interface' property at: {str(each_network)}")
            sys.exit(1)
        if check_interface_status(interface):
            interface_name = each_network.get("name", interface)
            each_ethernet = {
                "optional": True
            }
            dhcp_mode = each_network.get("dhcp", {}).get("mode")
            if dhcp_mode == "client":
                each_ethernet["dhcp4"] = "yes"
            elif dhcp_mode in ["server", "none"]:
                each_ethernet["dhcp4"] = "no"
            else:
                print(f"ERROR: Invalid dhcp option for interface '{interface_name}'")
                sys.exit(1)
            if isinstance(each_network.get("addresses"), list):
                network_addresses = []
                for each_address in each_network.get("addresses"):
                    if is_valid_network(each_address):
                        network_addresses.append(each_address)
                    else:
                        print(f"ERROR: Invalid network address for interface '{interface_name}': {each_address}")
                        sys.exit(1)
                each_ethernet["addresses"] = network_addresses
            domains = []
            if isinstance(each_network.get("domain"), str):
                domains.append(each_network.get("domain"))
            if isinstance(each_network.get("nameservers"), list):
                nameservers = []
                for each_address in each_network.get("nameservers"):
                    if is_valid_ip_address(each_address):
                        nameservers.append(each_address)
                    else:
                        print(f"ERROR: Invalid network address for interface '{interface_name}': {each_address}")
                        sys.exit(1)
                each_ethernet["nameservers"] = {
                    "addresses": nameservers,
                    "search": domains
                }
            gateway = each_network.get("gateway")
            if isinstance(gateway, str):
                valid_gateway = False
                for each_interface_address in each_ethernet.get("addresses"):
                    if is_valid_ip_address(gateway, network=each_interface_address):
                        valid_gateway = True
                if valid_gateway:
                    each_ethernet["routes"] = [{
                        "to": "default",
                        "via": gateway
                    }]
                else:
                    print(f"ERROR: Gateway {gateway} is not a valid IP address from any network related to '{interface_name}' interface")
                    sys.exit(1)
            ethernets[interface] = each_ethernet
        else:
            print(f"INFO: Skipping interface {interface}")
    netplan_data = {
        "network": {
          "version": 2,
          "ethernets": ethernets
        }
    }
    with open('netplan.yaml', 'w', encoding='utf8') as outfile:
        yaml.dump(netplan_data, outfile, default_flow_style=False, allow_unicode=True)
        outfile.close()


def generate_dhcpd_file(config):
    dhcp_ipv4_hosts = []
    dhcp_ipv4_subnets = []
    dhcp_ipv6_hosts = []
    dhcp_ipv6_subnets = []
    for each_network in config.get("general", {}).get("networks", []):
        interface = each_network.get("interface")
        if not isinstance(interface, str) or interface == "":
            print(f"ERROR: Missing or invalid 'interface' property at: {str(each_network)}")
            sys.exit(1)
        if check_interface_status(interface):
            interface_name = each_network.get("name", interface)
            dhcp_mode = each_network.get("dhcp", {}).get("mode")
            if dhcp_mode == "server":
                domain = None
                if isinstance(each_network.get("domain"), str):
                    domain = each_network.get("domain")
                nameservers = []
                if isinstance(each_network.get("nameservers"), list):
                    for each_address in each_network.get("nameservers"):
                        if is_valid_ip_address(each_address):
                            nameservers.append(each_address)
                        else:
                            print(f"ERROR: Invalid network address for interface '{interface_name}': {each_address}")
                            sys.exit(1)
                networks_map = {}
                if isinstance(each_network.get("addresses"), list):
                    for each_address in each_network.get("addresses"):
                        if is_valid_network(each_address):
                            network = ipaddress.ip_network(each_address, strict=False)
                            gateway = ipaddress.ip_address(each_address.split("/")[0])
                            networks_map[each_address] = {
                                "version": network.version,
                                "network_address": str(network.network_address),
                                "broadcast_address": str(network.broadcast_address),
                                "netmask": str(network.netmask),
                                "gateway": str(gateway),
                                "domain": domain,
                                "nameservers": nameservers,
                                "ranges": [],
                                "allowed_hosts": list(network.hosts())
                            }
                        else:
                            print(f"ERROR: Invalid network address for interface '{interface_name}': {each_address}")
                            sys.exit(1)

                nameservers = []
                if isinstance(each_network.get("dhcp", {}).get("nameservers"), list):
                    for each_address in each_network.get("dhcp", {}).get("nameservers"):
                        if is_valid_ip_address(each_address):
                            nameservers.append(each_address)
                        else:
                            print(f"ERROR: Invalid network address for interface '{interface_name}': {each_address}")
                            sys.exit(1)

                if isinstance(each_network.get("dhcp", {}).get("ranges"), list):
                    for each_range in each_network.get("dhcp", {}).get("ranges"):
                        begin = each_range.get("begin")
                        end = each_range.get("end")
                        selected_network = None
                        for each_network in networks_map.keys():
                            if is_valid_ip_address(begin, each_network, silent=True) and is_valid_ip_address(end, each_network, silent=True):
                                selected_network = each_network
                                break
                        if selected_network:
                            begin_ip = ipaddress.ip_address(begin)
                            end_ip = ipaddress.ip_address(end)
                            if begin_ip > end_ip:
                                print(f"ERROR: Invalid DHCP range for interface '{interface_name}': {begin}-{end} (wrong order)")
                                sys.exit(1)

                            if begin_ip < ipaddress.ip_address(networks_map.get(selected_network).get("gateway")) < end_ip:
                                print(f"ERROR: Invalid DHCP range for interface '{interface_name}': {begin}-{end} (interface address is inside range)")
                                sys.exit(1)
                            networks_map.get(selected_network).get("ranges").append({
                                "begin": begin,
                                "end": end
                            })
                        else:
                            print(f"ERROR: Cannot find a valid network for range {begin}-{end} for DHCP server on '{interface_name}'.")
                            sys.exit(1)

                for each_dhcp_range in networks_map.values():
                    ranges = each_dhcp_range.get("ranges")
                    if 0 < len(ranges):
                        conflict = None
                        for first_index in range(0, len(ranges)):
                            for second_index in range(first_index + 1, len(ranges)):
                                first_begin = ipaddress.ip_address(ranges[first_index].get("begin"))
                                first_end = ipaddress.ip_address(ranges[first_index].get("end"))
                                second_begin = ipaddress.ip_address(ranges[second_index].get("begin"))
                                second_end = ipaddress.ip_address(ranges[second_index].get("end"))
                                if first_begin <= second_begin <= first_end or first_begin <= second_end <= first_end:
                                    conflict = f"{first_begin}-{first_end} and {second_begin}-{second_end}"
                        if conflict:
                            print(f"ERROR: DHCP range conflict between {conflict} for interface '{interface_name}'.")
                            sys.exit(1)
                        if each_dhcp_range.get("version") == 4:
                            dhcp_ipv4_subnets.append(each_dhcp_range)
                        elif each_dhcp_range.get("version") == 6:
                            dhcp_ipv6_subnets.append(each_dhcp_range)
                        else:
                            print(f"ERROR: Unexpected IP version found for interface '{interface_name}'.")
                            sys.exit(1)
        else:
            print(f"INFO: Skipping interface {interface}")

    dns_ips = {}
    for each_dns in config.get("general", {}).get("dns", []):
        name = each_dns.get("name")
        type = each_dns.get("type")
        if type == "external":
            dns_list = []
            for each_dns_server in each_dns.get("addresses"):
                if is_valid_ip_address(each_dns_server):
                    dns_list.append(each_dns_server)
            dns_ips[name] = dns_list
        else:
            print(f"ERROR: NOT IMPLEMENTED YET.")
            sys.exit(1)

    for each_client in config.get("general", {}).get("clients", []):
        name = each_client.get("name")
        mac = each_client.get("mac-address")
        ip = each_client.get("ip-address")
        if not is_valid_ip_address(ip):
            print(f"ERROR: Invalid IP address '{ip}' for client '{name}'.")
            sys.exit(1)
        ip_version = ipaddress.ip_address(ip).version
        subnets = []
        if ip_version == 4:
            subnets = dhcp_ipv4_subnets
        elif ip_version == 6:
            subnets = dhcp_ipv6_subnets
        else:
            print(f"ERROR: Unexpected IP version found for client '{name}'.")
            sys.exit(1)
        has_valid_network = False
        domain = None
        for each_network in subnets:
            if ipaddress.ip_address(ip) in each_network.get("allowed_hosts"):
                has_valid_network = True
                domain = each_network.get("domain")
        if not has_valid_network:
            print(f"INFO: Skipping client '{name}' because it does not belong to any valid IPv4 network.")
        else:
            dns = []
            for each_dns_server in dns_ips.get(each_client.get("dns")):
                if ipaddress.ip_address(each_dns_server).version == ip_version:
                    dns.append(each_dns_server)
            client_info = {
                "name": name,
                "mac": mac,
                "ip": ip,
                "dns": dns,
                "domain": domain
            }
            if ip_version == 4:
                dhcp_ipv4_hosts.append(client_info)
            elif ip_version == 6:
                dhcp_ipv6_hosts.append(client_info)
            else:
                print(f"ERROR: Unexpected IP version found for client '{name}'.")
                sys.exit(1)

    try:
        file_handler = open("dhcpd.conf", "w")
        file_handler.write("#\n# dhcpd.conf\n#\n# This file was generated automatically. Do not edit!\n#\n")
        file_handler.write("default-lease-time 600;\nmax-lease-time 7200;\n")
        file_handler.write("ddns-update-style none;\nauthoritative;\n\n")
        for each_subnet in dhcp_ipv4_subnets:
            file_handler.write(f"subnet {each_subnet.get("network_address")} netmask {each_subnet.get("netmask")} {{\n")
            for each_subnet_range in each_subnet.get("ranges"):
                file_handler.write(f"    range {each_subnet_range.get("begin")} {each_subnet_range.get("end")};\n")
            file_handler.write(f"    option routers {each_subnet.get("gateway")};\n")
            file_handler.write(f"    option broadcast-address {each_subnet.get("broadcast_address")};\n")
            file_handler.write(f"    option subnet-mask {each_subnet.get("netmask")};\n")
            if each_subnet.get("domain"):
                file_handler.write(f"    option domain-name \"{each_subnet.get("domain")}\";\n")
            if 0 < len(each_subnet.get("nameservers")):
                file_handler.write(f"    option domain-name-servers {", ".join(each_subnet.get("nameservers"))};\n")
            file_handler.write("}\n")
        file_handler.write("\n")
        unknown_index = 0
        for each_host in dhcp_ipv4_hosts:
            name = each_host.get("name")
            if not name:
                name = f"unknown-{unknown_index}"
                unknown_index = unknown_index + 1
            file_handler.write(f"host {name} {{\n")
            file_handler.write(f"    hardware ethernet {each_host.get("mac")};\n")
            file_handler.write(f"    fixed-address {each_host.get("ip")};\n")
            if each_host.get("domain"):
                file_handler.write(f"    option domain-name \"{each_host.get("domain")}\";\n")
            if 0 < len(each_host.get("dns")):
                file_handler.write(f"    option domain-name-servers {", ".join(each_host.get("dns"))};\n")
            file_handler.write("}\n")
        file_handler.close()
    except:
        print(f"ERROR: Could not write to dhcpd.conf file.")
        sys.exit(1)

    try:
        file_handler = open("dhcpd6.conf", "w")
        file_handler.write("#\n# dhcpd.conf\n#\n# This file was generated automatically. Do not edit!\n#\n")
        file_handler.write("default-lease-time 600;\nmax-lease-time 7200;\n")
        file_handler.write("ddns-update-style none;\nauthoritative;\n\n")
        for each_subnet in dhcp_ipv6_subnets:
            file_handler.write(f"subnet {each_subnet.get("network_address")} netmask {each_subnet.get("netmask")} {{\n")
            for each_subnet_range in each_subnet.get("ranges"):
                file_handler.write(f"    range {each_subnet_range.get("begin")} {each_subnet_range.get("end")};\n")
            file_handler.write(f"    option routers {each_subnet.get("gateway")};\n")
            file_handler.write(f"    option broadcast-address {each_subnet.get("broadcast_address")};\n")
            file_handler.write(f"    option subnet-mask {each_subnet.get("netmask")};\n")
            if each_subnet.get("domain"):
                file_handler.write(f"    option domain-name \"{each_subnet.get("domain")}\";\n")
            if 0 < len(each_subnet.get("nameservers")):
                file_handler.write(f"    option domain-name-servers {", ".join(each_subnet.get("nameservers"))};\n")
            file_handler.write("}\n")
        file_handler.write("\n")
        unknown_index = 0
        for each_host in dhcp_ipv6_hosts:
            name = each_host.get("name")
            if not name:
                name = f"unknown-{unknown_index}"
                unknown_index = unknown_index + 1
            file_handler.write(f"host {name} {{\n")
            file_handler.write(f"    hardware ethernet {each_host.get("mac")};\n")
            file_handler.write(f"    fixed-address {each_host.get("ip")};\n")
            if each_host.get("domain"):
                file_handler.write(f"    option domain-name \"{each_host.get("domain")}\";\n")
            if 0 < len(each_host.get("dns")):
                file_handler.write(f"    option domain-name-servers {", ".join(each_host.get("dns"))};\n")
            file_handler.write("}\n")
        file_handler.close()
    except:
        print(f"ERROR: Could not write to dhcpd.conf file.")
        sys.exit(1)

configuration = read_configuration("config.yaml")
generate_netplan_file(configuration)
generate_dhcpd_file(configuration)
print("Done.")
