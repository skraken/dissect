import unittest
import dissect.formats.pcap as pcap


class Test_PCAPmethods(unittest.TestCase):

    def test_pcap(self):

        p = list(pcap.iterPcapFileName('test_packets/smallerFlows.pcap'))


        self.assertEqual(p[0][0]['caplen']._vs_size, 4)

        self.assertEqual(repr(p[0][1]['srcaddr']), '192.168.3.131')
        self.assertEqual(p[0][1].srcaddr, 3232236419)

        self.assertEqual(repr(p[0][1]['dstaddr']), '72.14.213.138')
        self.assertEqual(p[0][1].dstaddr, 1208931722)

        self.assertEqual(p[2][0]['tvsec']._vs_size, 4)

        self.assertEqual(p[2][2].checksum, 30424)

        self.assertEqual(p[6][3],
                         b'GET /complete/search?client=chrome&hl=en-US&q=msn HTTP/1.1\r\nHost: clients1.google.ca\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10\r\nAccept-Encoding: gzip,deflate,sdch\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\nCookie: PREF=ID=c2e350012258df1c:U=386a6ebef0db287c:FF=0:TM=1294164294:LM=1294164294:S=bcuwM6Vh5ecKxqmk; SID=DQAAAN4AAAB3Mw7hSAXm29svfZQxRhaEVL5x_7JEyWEywPtfIKmV2QMCZ61VfSvGxg-WCwS7OYnEonavdReiTgZ_3JalcPyInxYbHG668hbhfVRxCHWraC8lNhhhZvC45L32WDjkPRRy0qmoz_3SGzDDgumB2mgyjTHiqRdgEmopsEvouobSZDRxixXdANvTHyq85PmVnzKHK_-x7hVdYhu44J6P_oI4bZWnHA966Qna73q5YOPPevvZQVX8F71nVjDk4aJM5KhlAQwBDx5fzrV9Wk_R_Y-egz0sDL9oC3fBURGVwp4ywQ; HSID=AqgM3JlzrVA3Qkiyz; NID=43=nEX-4HaaPZYe0kzvBiG2-vthPaK9dm8ewcl685Rdz57zib8A5PoX3puBlNIByvre-pcW3q2LZLN4ZgDZOhV2QPOvlsNNZPtSKlQmIyp-fu9x8w7RVY7XW-4TZbgoxXY8\r\n\r\n')

        self.assertEqual(repr(p[7][1]['srcaddr']), '192.168.3.131')
        self.assertEqual(p[7][1].srcaddr, 3232236419)

        self.assertEqual(repr(p[7][1]['dstaddr']), '72.14.213.102')
        self.assertEqual(p[7][1].dstaddr, 1208931686)

    def test_pcapng(self):

        p = list(pcap.iterPcapFileName('test_packets/rtps_cooked.pcapng'))

        self.assertEqual(repr(p[0][1]['dstaddr']), '192.168.0.6')
        self.assertEqual(repr(p[0][1]['srcaddr']), '192.168.0.5')

        self.assertEqual(p[0][1]['veriphl']._vs_size, 1)

        self.assertEqual(repr(p[3][1]['dstaddr']), '192.168.0.6')
        self.assertEqual(repr(p[3][1]['srcaddr']), '192.168.0.5')

        self.assertEqual(p[3][2]['udplen']._vs_size, 2)

