import dns.query
import dns.message

import sys
import time

L = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10','192.5.5.241','192.112.36.4', '198.97.190.53','192.36.148.17','192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

def find_answer_iter(m, typ_num):
    global L
    r = None
    for i in range(len(L)):
        r = dns.query.udp(m, L[i])
        if r != None:
            break
    t = time.time()
    curr_t = t
    don = False
    query = None
    while len(r.answer) == 0 and (curr_t - t) < 5:
        query = r.question[0].to_text().split()[0]
        auth_info = r.authority[0].to_text().split('\n')[0].split()
        corr_ip = None
        where = None
        #if auth_info[4] == query:
        #    return None
        if len(r.additional) == 0:      #Need to instead perform full resolution on an upper-level server, auth_info, and get its A-record
            mm = dns.message.make_query(auth_info[4], 1)
            rs = find_answer_recur(mm, 1)
            #print(rs[len(rs) - 1].answer[0].to_text())
            #print("QUESTION: " + query)
            #print("AUTHORITY: " + auth_info[4])
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

        r = dns.query.udp(m, where, timeout=5)
        curr_t = time.time()

    if (curr_t - t) >= 5:
        return None

    return r

def find_answer_recur(m, typ_num):
    rs = []
    r = find_answer_iter(m, typ_num)
    if r == None:
        return None
    rs.append(r)
    cname = None
    while r.answer[0].to_text().split()[3] == 'CNAME':
        cname = r.answer[0].to_text().split()[4]
        m = dns.message.make_query(cname, typ_num)
        r = find_answer_iter(m, typ_num)
        if r == None:
            return None
        else:
            rs.append(r)

    return rs

def main():
    d = {'A':1, 'NS':2, 'MX':15}
    if len(sys.argv) != 3:
        print("Usage: ./mydig <query hostname> <query type>")
        sys.exit(1)
    query = sys.argv[1]
    typ = sys.argv[2]
    if typ != 'A' and typ != 'NS' and typ != 'MX':
        print("Usage: second argument must be one of 'A', 'NS', 'MX'")
        sys.exit(1)
    typ_num = d[typ]
    m = dns.message.make_query(query, typ_num)
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
