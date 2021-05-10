from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR


def load():
    result = dict()

    with open('data_base.txt') as f:
        for line in f.readlines():
            line.split(' ')
            if line[0] not in result:
                result[line[0]] = dict()
            result[line[0]][int(line[1])] = line[2:]

    return result


def save(data_base):
    with open('data_base.txt', 'w') as f:
        for k, v in data_base.items():
            for kk, vv in v.items():
                if float(vv[2]) > time.time():
                    f.write(f'{k} {kk}' + ' '.join(map(str, vv)) + '\n')


def main():
    def on_get_pkt(pkt):
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and \
                pkt[IP].dst == '192.168.1.2':
            qname = pkt[DNSQR].qname.decode()
            if str(qname).endswith('Home.'):
                qname = qname[:-5]
            if qname not in data_base.keys() or \
                    pkt[DNSQR].qtype not in data_base[qname] or \
                    data_base[qname][pkt[DNSQR].qtype][2] < time.time():
                send_request(pkt)
            send_response(pkt)

    def send_response(pkt_original):
        qname = pkt_original[DNSQR].qname.decode()
        if str(qname).endswith('Home.'):
            qname = qname[:-5]
        data = data_base[qname][pkt_original[DNSQR].qtype]

        send(IP(dst=pkt_original[IP].src) / UDP(dport=53) /
             DNS(id=pkt_original[DNS].id, qr=1, rd=1, ra=1,
                 qd=pkt_original[DNS].qd,
                 an=DNSRR(rrname=qname,
                          type=pkt_original[DNSQR].qtype,
                          rdata=data[0],
                          ttl=int(data[1]))),
             verbose=False)

    def send_request(pkt_original):
        qname = pkt_original[DNSQR].qname.decode()
        if str(qname).endswith('Home.'):
            qname = qname[:-5]

        response = sr1(IP(dst='8.8.8.8') / UDP(dport=53) /
                       DNS(rd=1,
                           qd=DNSQR(
                               qname=qname,
                               qtype=pkt_original[DNSQR].qtype)))

        for i in range(response[DNS].ancount):
            rname = response[DNSRR][i].rrname.decode()
            rtype = response[DNSRR][i].type

            if rtype in [1, 2, 12, 28]:
                rdata = response[DNSRR][i].rdata.decode() \
                    if type(response[DNSRR][i].rdata) == bytes \
                    else response[DNSRR][i].rdata
                ttl = int(response[DNSRR][i].ttl)

                if rname not in data_base.keys():
                    data_base[rname] = dict()
                data_base[rname][rtype] = [rdata, ttl, time.time() + ttl]

        save(data_base)

    data_base = load()
    sniff(filter='udp port 53', store=0, prn=on_get_pkt)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
