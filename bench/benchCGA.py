#!/usr/bin/python 
"""this little program only serves one purpose: benchmarking the speed of:
    - CGA generation
    - CGA verification
    - Signature generation
    - Signature verification"""

# import cProfile, sys, pstats
import sys, time

sys.path.append("..")


from scapy6send.ecc import *
from scapy6send.cert import *
from scapy6send.scapy6 import *
from NDprotector.Tool import PubKeyListtoCGAPKExtList
from math import * # cynthiao

sigtypeID = 9
extrakeynum =3

key_gen_time = []
cga_gen_time = []
cga_verif_time = []
sign_gen_time = []
sign_verif_time = []

def construct_message(address):
    p = str( IPv6(src = address,dst = inet_ntop(socket.AF_INET6, # dst is the solicited node multicast address
             in6_getnsma(inet_pton(socket.AF_INET6, address))))/
             ICMPv6ND_NS(tgt = address) /
             ICMPv6NDOptSrcLLAddr(lladdr = "00:11:22:33:44:55"))
    return p

def sign(data, pds, key):
    msg = IPv6(data)
    msg /= ICMPv6NDOptCGA(cgaparams = pds) / \
               ICMPv6NDOptTimestamp() / \
               ICMPv6NDOptNonce() 

    extra_payload_len = len(str(msg.getlayer(ICMPv6NDOptCGA)))
    msg[IPv6].plen += extra_payload_len

    # dirty hack: force to recompute the (ICMP) checksum
    del(msg[IPv6].payload.cksum)

    # freezing data inside the new option fields
    msg = IPv6(str(msg))


    keyh = get_public_key_hash(key, sigtypeID=sigtypeID)

    # adding the signature
    msg /= ICMPv6NDOptUSSig(key=key, pos = 0,
            keyh = keyh, sigtypeID=sigtypeID)
    


    # dirty hack: force the update of the payload length
    extra_payload_len = len(str(msg.getlayer(ICMPv6NDOptUSSig)))
    msg[IPv6].plen += extra_payload_len


    # dirty hack: force to recompute the (ICMP) checksum (once again)
    del(msg[IPv6].payload.cksum)


    return str(msg)

def cga_verify(address, data):
    return CGAverify(address, IPv6(data).getlayer(CGAParams))

def signature_verify(data,k):
    return IPv6(data)[ICMPv6NDOptUSSig].verify_sig(k)

def compute_key():
    return ECCkey(NID_secp256k1) # jochoi: (observation) key is being generated with 256 bits?

def gen_cga(key):
    return CGAgen("fe80::", key, 1,
            ext = PubKeyListtoCGAPKExtList([ key for i in range(extrakeynum)]) )

def bench_single_ecc():
    for i in range(100):
	before = time.time()
        k = compute_key()
	# print "key computed, %s" % k # jochoi: debug / should time tthe key generation
	after = time.time()
	# print "key generation took: %s" % str(after - before)
	key_gen_time.append(after - before)

        # computes a CGA address
        before = time.time()
        (address, params) = gen_cga(k)
        after = time.time()

        cga_gen_time.append(after - before)

        m = construct_message(address)
        before = time.time()
        m = sign(m, params, k)
        after = time.time()
        sign_gen_time.append(after - before)
        

        before = time.time()
        cga_verify(address, m)
        after = time.time()
        cga_verif_time.append(after - before)

        before = time.time()
        signature_verify(m, k)
        after = time.time()
        sign_verif_time.append(after - before)


        print "loop #%d computed, message size: %d" % (i, len(m))

def computeMdev(data, avg):
	'''
	Compute the mean deviation given the list and the average value
	'''
	num = len(data)
	sum = 0.0
	for d in data:
		sum += abs(d - avg)

	return(sum/num)

if __name__ == "__main__":

    try:
        extrakeynum = int(sys.argv[1])
    except (IndexError, ValueError):
        print "first argument should be the number of Public Key stored in the Public Key Extensions"
        sys.exit(-1)
    bench_single_ecc()

    f = open("%d-key-ecc-duration" % extrakeynum, "w")

    f.write("key_gen_time = " + repr(key_gen_time) + "\n")
    f.write("cga_gen_time = " + repr(cga_gen_time) + "\n")
    f.write("cga_verif_time = " + repr(cga_verif_time) + "\n")
    f.write("sign_gen_time = " + repr(sign_gen_time) + "\n")
    f.write("sign_verif_time = " + repr(sign_verif_time) + "\n")

    f.close()
    # cynthiao additions :: added min, max, standard deviation
   
    print "==KEY GENERATION TIMES=="
    print "min KEY Generation time: " + str(min(key_gen_time))
    print "max KEY generation time: " + str(max(key_gen_time))
    print "mean KEY generation time: " + str(sum(key_gen_time) / len(key_gen_time))
    
    def average(key_gen_time): return sum(key_gen_time) * 1.0 / len(key_gen_time)
    avg = average(key_gen_time)
    variance = map(lambda x: (x - avg)**2, key_gen_time)
    average(variance)
    stdGenDev = math.sqrt(average(variance))
    print "deviation of KEY generation time: " + str(stdGenDev)
    mdev = computeMdev(key_gen_time, avg)
    print "mean deviation of KEY generation time: " + str(mdev)
 
    print "==CGA GENERATION TIMES=="
    print "min CGA generation time: " + str(min(cga_gen_time))
    print "max CGA generation time: " + str(max(cga_gen_time))
    print "mean CGA generation time: " + str(sum(cga_gen_time) / len(cga_gen_time))
    
    def average(cga_gen_time): return sum(cga_gen_time) * 1.0 / len(cga_gen_time)
    avg = average(cga_gen_time)
    variance = map(lambda x: (x - avg)**2, cga_gen_time)
    average(variance)
    stdGenDev = math.sqrt(average(variance))
    print "deviation of CGA generation time: " + str(stdGenDev)
    mdev = computeMdev(cga_gen_time, avg)
    print "mean deviation of KEY generation time: " + str(mdev)

    print "==CGA VERIFICATION TIMES=="
    print "min CGA verification time: " + str(min(cga_verif_time))
    print "max CGA verification time: " + str(max(cga_verif_time))
    print "mean CGA verification time: " + str(sum(cga_verif_time) / len(cga_verif_time))

    def average(cga_verif_time): return sum(cga_verif_time) * 1.0 / len(cga_verif_time)
    avg = average(cga_verif_time)
    variance = map(lambda x: (x - avg)**2, cga_verif_time)
    average(variance)
    stdVerDev = math.sqrt(average(variance))
    print "deviation of CGA verification time: " + str(stdVerDev)
    mdev = computeMdev(cga_verif_time, avg)
    print "mean deviation of KEY generation time: " + str(mdev)

    print "==SIGNATURE GENERATION TIMES=="
    print "min Signature generation time: " + str(min(sign_gen_time))
    print "max Signature generation time: " + str(max(sign_gen_time))
    print "mean Signature generation time: " + str(sum(sign_gen_time) / len(sign_gen_time))

    def average(sign_gen_time): return sum(sign_gen_time) * 1.0 / len(sign_gen_time)
    avg = average(sign_gen_time)
    variance = map(lambda x: (x - avg)**2, sign_gen_time)
    average(variance)
    stdSigDev = math.sqrt(average(variance))
    print "deviation of Signature generation time: " + str(stdSigDev)
    mdev = computeMdev(sign_gen_time, avg)
    print "mean deviation of KEY generation time: " + str(mdev)
    
    print "==SIGNATURE VERIFICATION TIMES=="
    print "min Signature verification time: " + str(min(sign_verif_time))
    print "max Signature verification time: " + str(max(sign_verif_time))
    print "mean Signature verification time: " + str(sum(sign_verif_time) / len(sign_verif_time))

    def average(sign_verif_time): return sum(sign_verif_time) * 1.0 / len(sign_verif_time)
    avg = average(sign_verif_time)
    variance = map(lambda x: (x - avg)**2, sign_verif_time)
    average(variance)
    stdSigVerDev = math.sqrt(average(variance))
    print "deviation of Signature verification time: " + str(stdSigVerDev)
    mdev = computeMdev(sign_verif_time, avg)
    print "mean deviation of KEY generation time: " + str(mdev)

    # prof = cProfile.run("bench_single_ecc()","%d-key-ecc.prof" % extrakeynum)


    # print """############## Single ECC Public Key ###############"""
    # stats = pstats.Stats("%d-key-ecc.prof" % extrakeynum)
    # stats.strip_dirs()
    # stats.sort_stats('name')
    # stats.print_stats('benchCGA.py:')


