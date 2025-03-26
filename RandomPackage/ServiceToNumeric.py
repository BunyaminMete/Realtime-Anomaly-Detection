from PortToService import get_service_name

SERVICE_LIST = [
    "IRC", "X11", "Z39_50", "aol", "auth", "bgp", "courier", "csnet_ns", "ctf", "daytime",
    "discard", "domain", "domain_u", "echo", "eco_i", "ecr_i", "efs", "exec", "finger",
    "ftp", "ftp_data", "gopher", "harvest", "hostnames", "http", "http_2784", "http_443",
    "http_8001", "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login", "mtp",
    "name", "netbios_dgm", "netbios_ns", "netbios_ssn", "netstat", "nnsp", "nntp", "ntp_u",
    "other", "pm_dump", "pop_2", "pop_3", "printer", "private", "red_i", "remote_job", "rje",
    "shell", "smtp", "sql_net", "ssh", "sunrpc", "supdup", "systat", "telnet", "tftp_u",
    "tim_i", "time", "urh_i", "urp_i", "uucp", "uucp_path", "vmnet", "whois"
]

def get_service_numeric_index(service_name):
    try:
        return SERVICE_LIST.index(service_name)
    except ValueError:
        print(f"Service '{service_name}' not found!")
        return -1  # veya None
    
staticNum = 111 # 43, whois, 69
                # 111, sunrpc, 57

serviceName =  get_service_name(staticNum)
serviceNumber = get_service_numeric_index(serviceName)

if serviceName and serviceNumber:
    print("Port:",staticNum ,"\nService:",serviceName,"\nPort:", serviceNumber)