import socket

def raw_whois_query(domain, server="whois.verisign-grs.com"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server, 43))
        s.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
            print(response)
        return response.decode(errors='ignore')

def get_whois_server_for_tld(tld):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("whois.iana.org", 43))
    s.sendall((tld + "\r\n").encode())
    response = b""
    while True:
        data = s.recv(4096)
        if not data:
            break
        response += data
    s.close()
    response = response.decode(errors="ignore")
    for line in response.splitlines():
        if line.lower().startswith("whois:"):
            return line.split(":")[1].strip()
    return None


domain_test = 'matrixcalc.org'
domain_test2 = 'landrop.app'
tld = domain_test2.split(".")[-1]
raw_whois_query(domain=domain_test2, server=get_whois_server_for_tld(tld))