import dns.query
import dns.message
import dns.dnssec
import dns.tokenizer

import sys
import time

L = {"a.root-servers.net":'198.41.0.4', "b.root-servers.net":'199.9.14.201', "c.root-servers.net":'192.33.4.12', "d.root-servers.net":'199.7.91.13', "e.root-servers.net":'192.203.230.10',"f.root-servers.net":'192.5.5.241',"g.root-servers.net":'192.112.36.4', "h.root-servers.net":'198.97.190.53',"i.root-servers.net":'192.36.148.17',"j.root-servers.net":'192.58.128.30', "k.root-servers.net":'193.0.14.129',
"l.root-servers.net":'199.7.83.42', "m.root-servers.net":'202.12.27.33'}

def validate(data, rrsig, dnskeys, dnskeys_rrsig):
    keys = {}               #is for the actual answer to the query, not some DS (it doesn't exist at the authoritative DNS server's level).
    keys[rrsig[0].signer] = dnskeys
    dns.dnssec._validate(data, rrsig, keys)  #Check for this in above loop.
    keys = {}               #Empty the keys dictionary for the next validation we perform, involving the DNSKEY RRSET
    keys[dnskeys_rrsig[0].signer] = dnskeys
    dns.dnssec._validate(dnskeys, dnskeys_rrsig, keys)

def find_answer_iter(m, typ_num):
    fr = open("root.keys", "r")
    fields = fr.read().split()
    dnskeys = None
    tokenizer = dns.tokenizer.Tokenizer(f= "root.keys")
    dnskeys = dns.rrset.from_text(dns.name.from_text(fields[0]),int(fields[1]), dns.rdataclass.from_text(fields[2]), dns.rdatatype.from_text(fields[3]), tokenizer)
    fr.close()
    enabled = True
    global L
    keys = L.keys()
    right_key = None
    r = None
    km = None
    for key in keys:
        r = dns.query.udp(m, L[key])
        if r != None:
            right_key = key
            break
    t = time.time()
    curr_t = t
    don = False
    query = None
    rk = None
    mk = None
    where = None
    rrsig = None
    prev_ds = None
    curr_ds = None
    dnskeys = None
    while len(r.answer) == 0 and (curr_t - t) < 5:
        query = r.question[0].to_text().split()[0]
        auth_info = r.authority[0].to_text().split('\n')[0].split()
        corr_ip = None
        for auth in r.authority:
            if auth.to_text().split()[3] == "DS":
                curr_ds = auth
            elif auth.to_text().split()[3] == "RRSIG":
                rrsig = auth
        if curr_ds == None or dnskeys == None or rrsig == None or dnskeys_rrsig == None:
            enabled = False
        else:
            validate(curr_ds, rrsig, dnskeys, dnskeys_rrsig)
            if prev_ds != None:
                ksk = None
                splitkeys = dnskeys.to_text().split('\n')
                for key in splitkeys:
                    if key.split()[4] == '257':
                        ksk = key
                split_ksk = ksk.split()
                print(prev_ds.to_text())
                print(dnskeys.to_text())
                full_ksk = dns.rdtypes.dnskeybase.DNSKEYBase(dns.rdataclass.from_text(split_ksk[2]), dns.rdatatype.from_text(split_ksk[3]), int(split_ksk[4]), int(split_ksk[5]), int(split_ksk[6]), split_ksk[7])
                ds_replica = dns.dnssec.make_ds(split_ksk[0], full_ksk.key, dns.dnssec.algorithm_to_text(full_ksk.algorithm))
                if prev_ds.digest != ds_replica.digest:
                    print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAHHHHHHHH!!!! Unequal hashes! Run for your lives!")
                    sys.exit(1)
        #if auth_info[4] == query:
        #    return None
        if len(r.additional) == 0:      #Need to instead perform full resolution on an upper-level server, auth_info, and get its A-record
            mm = dns.message.make_query(auth_info[4], 1, want_dnssec = True)
            rs = find_answer_recur(mm, 1)
            if rs == None:      #The base case that actually times out will return below, returning None;
                return rs       #this conditional stmt is for the higher layers in the recursion stack.
            rr = rs[len(rs) - 1]
            where = rr.answer[0].to_text().split()[4]
        else:
            for el in r.additional:
                curr = el.to_text().split()
                if curr[0] == auth_info[4] and curr[3] == 'A':
                    where = curr[4]
                    break
        mk = dns.message.make_query(auth_info[0], 48, want_dnssec= True)
        rk = dns.query.udp(mk, where)
        dnskeys = None
        for answer in rk.answer:
            if answer.to_text().split()[4] == "256" or answer.to_text().split()[4] == "257":
                dnskeys = answer
            elif answer.to_text().split()[3] == "RRSIG":
                dnskeys_rrsig = answer
        r = dns.query.udp(m, where, timeout=5)
        prev_ds = curr_ds
        curr_t = time.time()

    if (curr_t - t) >= 5:
        return None
    if (len(r.answer)) > 1:     #Now, the RRSIG we are validating (besides for the DNSKEY set)
        validate(r.answer[0], r.answer[1], dnskeys, dnskeys_rrsig)
    return (r, enabled)

def find_answer_recur(m, typ_num):
    rs = []
    (r, enabled) = find_answer_iter(m, typ_num)
    if r == None:
        return None
    rs.append(r)
    cname = None
    while r.answer[0].to_text().split()[3] == 'CNAME':
        cname = r.answer[0].to_text().split()[4]
        m = dns.message.make_query(cname, typ_num, want_dnssec = True)
        (r, enabled) = find_answer_iter(m, typ_num)
        if r == None:
            return None
        else:
            rs.append(r)
    #if not enabled:
    #    print("DNSSEC not supported")
    #    sys.exit(1)

    return rs

def main():
    d = {'A':1, 'NS':2, 'MX':15, 'RRSIG':46, 'DNSKEY':48}
    if len(sys.argv) != 3:
        print("Usage: ./mydig <query hostname> <query type>")
        sys.exit(1)
    query = sys.argv[1]
    typ = sys.argv[2]
    if typ != 'A' and typ != 'NS' and typ != 'MX':
        print("Usage: second argument must be one of 'A', 'NS', 'MX'")
        sys.exit(1)
    typ_num = d[typ]
    m = dns.message.make_query(query, typ_num, want_dnssec = True)
    rs = find_answer_recur(m, typ_num)

    time = 0
    size = 0
    if rs != None:
        print("QUESTION SECTION:")
        print(rs[0].question[0].to_text())
        print('\n')

        print("ANSWER Section")
        for r in rs:
            time += r.time
            size += r.request_payload
            for answer in r.answer:
                print(answer.to_text())

        print('\n')
        print("Query time: " + str(time * 1000) + "ms")
        print("Msg size rcvd: " + str(size))
    else:
        print("Timeout: there may not be an existing record of type " + typ + " for query " + query)

if __name__ == "__main__":
    main()
