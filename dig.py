import dns.query
import sys
import time
import datetime as currdate
def main():
    Rootservers = [
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33"
    ]
    answer = []
    domainname = sys.argv[1]
    input = sys.argv[2]
    origdomainname = domainname
    if (input == "A" or input == "a"):
        datatype = dns.rdatatype.A
    elif input == "MX" or input == "mx":
        datatype = dns.rdatatype.MX
    elif input == "NS" or input == "ns":
        datatype = dns.rdatatype.NS
    mainflag = 0
    for rootserver in Rootservers:
        if (mainflag == 1):  # Second Server
            break
        cur = rootserver
        q = dns.message.make_query(domainname, datatype)  # Local to Root Server
        x = dns.query.udp(q, cur, 15)
        if (x):  # Rootserver true
            mainflag = 1
            start = time.time()
            print(";; QUESTION SECTION:")
            for quest in x.question:
                print(quest)
        else:
            continue
        copy_cur = cur
        count = 0
        answerflag = 0
        while (answer == []):
            q = dns.message.make_query(domainname, datatype)
            x = dns.query.udp(q, cur, 30)
            # print(x)
            if (x.answer == []):
                if (x.additional != []):  # Additional Not empty
                    flag = 0
                    for gg in x.additional:
                        if ("AAAA" not in str(gg)):  # Only allows ipv4 to execute
                            flag = 1
                        if flag == 1:
                            break
                    cur = str(gg[0])
                else:  # Additional Empty
                    flag = 0
                    if "NS" in str(x.authority) and input == "NS":  # If our input asks for NS
                        answer = x.authority
                    for wp in x.authority:
                        if (wp[0]):
                            domainname = str(wp[0])
                            cur = copy_cur
                            datatype = dns.rdatatype.A  # Recurse using A
                            flag = 1
                        if flag == 1:
                            break
            elif ("CNAME" in str(x.answer)):
                if input == 'A':
                    answerflag = 1
                    answer = []
                    domainname = str(x.answer[0][0])
                    cur = copy_cur
                else:
                    answer = x.answer
            else:
                answer = x.answer

        if origdomainname != domainname:
            if input == "MX" or input == "mx":
                q = dns.message.make_query(origdomainname, dns.rdatatype.MX)
                x = dns.query.udp(q, str(x.answer[0][0]), 15)
                answer = x.answer
            elif (input == "A" or input == "a") and answerflag == 0:
                q = dns.message.make_query(origdomainname, dns.rdatatype.A)
                x = dns.query.udp(q, str(x.answer[0][0]), 15)
                answer = x.answer
        end = time.time()
        for ans in answer:
            print(";; ANSWER SECTION")
            print(ans)
        print(";; WHEN:", currdate.datetime.strftime(currdate.datetime.now(), "%a %B %d %H:%M:%S %Y"))
        print(";; Query time: % .2f"%((end-start)*1000)+"msec")
        print(";; MSG SIZE  rcvd:", sys.getsizeof(answer))
main()
