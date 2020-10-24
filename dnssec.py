import dns.query
import sys
import time
import datetime as currdate

#Each Time two request is made from the local server to Root/Authoritative Server
#First Request is using DNSKEY and it fetches with the
#Each Record is Validated based on the server response

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
def recursforAuthority(x,copy_cur):
    gg = str(x.authority[0][0])
    copy_copy_cur = copy_cur
    ans=[]
    while(ans==[]):
        req = dns.message.make_query(gg,dns.rdatatype.A)
        res = dns.query.udp(req, copy_cur, 15)
        #print(res)
        if (res.answer == []):
            if (res.additional != []):  # Additional Not empty
                for zzz in res.additional:
                    if (" A " in str(zzz)):  # Only allows ipv4 to execute
                        #print(zzz)
                        break
                copy_cur = str(zzz[0])
        else:
            if("CNAME" in str(x.answer)):
                ans = []
                gg = str(x.answer[0][0])
                copy_cur = copy_copy_cur
                break
            else:
                ans = res.answer[0][0]
    return str(ans)

domainname = sys.argv[1]
input = sys.argv[2]
origdomainname=domainname
curdomain = "." # Step 1 is to hit the "."
answer=[]
if (input == "A" or input == "a"):
    datatype = dns.rdatatype.A
elif input == "MX" or input == "mx":
    datatype = dns.rdatatype.MX
elif input == "NS" or input == "ns":
    datatype = dns.rdatatype.NS
mainflag=0 #See request is accepted or not
mainflag2=0
#Flag
Dnsnotsupported=0
Dnsverificationfailed=0
for rootserver in Rootservers:
    if(mainflag==1 and mainflag2==1):
        break
    cur = rootserver
    copy_cur=cur
    answerflag= 0

    while(answer==[]):
        dnsr= dns.message.make_query(curdomain,dns.rdatatype.DNSKEY,want_dnssec=True)  #Hitting the domain
        dnsres = dns.query.udp(dnsr, cur,30) # Return DNSKEY
        if(dnsres):
           mainflag=1
        request = dns.message.make_query(domainname,datatype,want_dnssec=True)
        x = dns.query.udp(request,cur,30)
        if (x):
            mainflag2 = 1


        if (dnsres.answer == []):
            Dnsnotsupported=1
            #print("DNSSEC not supported")  # Not enabled
            break
        #TODO: Validate the response for each request
        recordset=-1 #Needs to be reassigned
        recordsignature=-1
        if(x.answer==[]):
            if(x.authority):
                recordset = x.authority[1]            #DS
                recordsignature = x.authority[2]      #RSIG
        else:
            if(len(x.answer)>1):                             #DS AND RSIG BOTH SHOULD BE PRESENT
                recordset = x.answer[0]                #DS
                recordsignature = x.answer[1]          #RSIG

        Key = {
            dns.name.from_text(curdomain): dnsres.answer[0]
        }
        try:
            dns.dnssec.validate(recordset, recordsignature,Key)
        except:
            Dnsverificationfailed=1
            #print("DNSSec verification failed")
            break
        #Validate the key used
        keysigningkey = []
        for kez in dnsres.answer[0]:
            if ("257" in str(kez)):  # 257 - KeySigningKey
                keysigningkey = kez
        # print(keysigningkey)
        # Validate the key used
        if (curdomain != "."):  # Skip for root server
            # print(curdomain)
            # print(childserver)
            for child in childserver:
                algo = int(str(child).split()[1])  # Get the algorithm from the Childserver
            Map = {7: "SHA1", 8: "SHA256", 14: "SHA384", 5: "SHA1"}

            encryped = dns.dnssec.make_ds(curdomain, keysigningkey, Map[algo])
            if ((str(encryped).split()[3]) != (str(childserver).split()[7])):
                Dnsverificationfailed=1
                break
            #print(Map[algo])

        #DNSRESOLVER
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
                cur = recursforAuthority(x, copy_cur)
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
        if(x.authority):
            for val in x.authority:
                val2 = str(val)
                curdomain=val2.split()[0] #Gets updated every turn
                break
        #print(x.authority)
            childserver = x.authority[1]  #ChildServer

if Dnsnotsupported==1:
    print("DNSSEC not supported")
elif Dnsverificationfailed==1:
    print("DNSSec verification failed")
else:
    if origdomainname != domainname:
        if input == "MX":
            q = dns.message.make_query(origdomainname, dns.rdatatype.MX)
            x = dns.query.udp(q, str(x.answer[0][0]), 15)
            answer = x.answer
        elif input == "A" and answerflag == 0:
            q = dns.message.make_query(origdomainname, dns.rdatatype.A)
            x = dns.query.udp(q, str(x.answer[0][0]), 15)
            answer = x.answer
    for ans in answer:
        print(ans)


