#https://wiki.wireshark.org/X11
#https://www.cbtnuggets.com/common-ports/what-are-ports-6665-6669
#https://www.speedguide.net/port.php?port=210

# IRC, X11, Z39_50, aol, auth, bgp, courier,
# csnet_ns, ctf, daytime, discard, domain, domain_u, echo,
# eco_i, ecr_i, efs, exec, finger, ftp, ftp_data, gopher,
# harvest, hostnames, http, http_2784, http_443, http_8001,
# imap4, iso_tsap, klogin, kshell, ldap, link, login, mtp,
# name, netbios_dgm, netbios_ns, netbios_ssn, netstat, nnsp,
# nntp, ntp_u, other, pm_dump, pop_2, pop_3, printer, private,
# red_i, remote_job, rje, shell, smtp, sql_net, ssh, sunrpc,
# supdup, systat, telnet, tftp_u, tim_i, time, urh_i, urp_i,
# uucp, uucp_patanlh, vmnet, whois

def get_service_name(port):
    if 6000 <= port <= 6063:
        return "X11"
    elif 6665 <= port <= 6669:
        return "IRC"
    
    # Source: https://www.speedguide.net/port.php?port=0
    service_map = {
        210: "Z39_50",
        5190: "aol",
        113: "auth",
        179: "bgp",
        530: "courier",
        105: "csnet_ns",
        84: "ctf",
        13: "daytime",
        9: "discard",
        53: "domain",
        7: "echo",
        20: "ftp_data",
        21: "ftp",
        70: "gopher",
        2784: "http_2784",
        443: "http_443",
        8001: "http_8001",
        80: "http",
        143: "imap4",
        102: "iso_tsap",
        543: "klogin",
        544: "kshell",
        389: "ldap",
        87: "link",
        513: "login",
        57: "mtp",
        42: "name",
        138: "netbios_dgm",
        137: "netbios_ns",
        139: "netbios_ssn",
        15: "netstat",
        119: "nntp",
        123: "ntp_u",
        109: "pop_2",
        110: "pop_3",
        515: "printer",
        23: "telnet",
        69: "tftp_u",
        89: "su3",
        512: "exec",
        79: "finger",
        111: "sunrpc",
        514: "shell",
        25: "smtp",
        1521: "sql_net",
        22: "ssh",
        95: "supdup",
        11: "systat",
        37: "time",
        191: "urh_i",
        540: "uucp",
        117: "uucp_path",
        175: "vmnet",
        43: "whois",
    }
    if port in service_map:
        return service_map[port]
    return "other"

# Below services are eliminated because of there are not enough information about these services.
# "eco_i" 
# "red_i"
# "urp_i" 
if __name__ == "__main__":
    print(get_service_name(6666))
    print(get_service_name(43))
    print(get_service_name(111))
    print(get_service_name(121))
    print(get_service_name(12))

# Services must match together with NSL-KDD's numerical equivalents of services.
