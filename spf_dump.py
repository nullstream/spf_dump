#!/usr/local/bin/python

# Parser written relative to: http://www.openspf.org/SPF_Record_Syntax
import os,sys,re

def handle_a(domain,debug=False):
    result = []
    for a in (dig(domain,"A",debug)).split("\n"):
        if debug: print "Resolved A [%s] as [%s]"%(domain,a)
        result.extend([a]);
    return result

def handle_mx(domain,debug=False):
    result = []
    mx_list = dig(domain,"MX",debug)
    if '' != mx_list:
        for mx in mx_list.split('\n'): 
            record = mx.split()
            if debug: print "Resolving MX [%s] with [%s]"%(record[0],record[1])
            result.extend(handle_a(record[1].rstrip("."),debug))
    else:
            result.extend(handle_a(domain,debug))
    return result

def dig(domain,type,debug=False):
    process = os.popen('dig %s %s +short'%(domain,type))
    record = process.read()
    record = re.sub(r'^"|"$','',record)
    process.close() 
    if debug: print "dig [%s]"%record[:-1]
    return record[:-1]

def parse(domain,debug=False):
    ranges = []
    record = dig(domain,"TXT",debug)
    for token in record.split():
        token = token.split(':')
        if len(token) == 2:
            key = token[0].lower()
            value = token[1].rstrip('\"')
            if debug: print "Parsed [%s][%s]"%(key,value)
            if "ip4" == key:
                ranges.append(value)
                if debug: print "Found ip4 [%s]"%value
            elif "include" == key or "redirect" == key:
                ranges.extend(parse(value,debug))
                if debug: print "Recursed on [%s]"%value
	    elif "a" == key or "+a" == key:
                if debug: print "Found Dyad A [%s]"%value
                ranges.extend(handle_a(value,debug))
	    elif "mx" == key or "+mx" == key:
                if debug: print "Found Dyad MX [%s]"%value
                ranges.extend(handle_mx(value,debug))
            else:
                if debug: print "Dyad Unknown [%s][%s]"%(key,value)
	elif [] != token:
		if "a" == token[0] or "+a" == token[0] or "ptr" == token[0]:
                	if debug: print "Found A [%s]"%token[0]
                        ranges.extend(handle_a(domain,debug))
		elif "mx" == token[0] or "+mx" == token[0]:
                	if debug: print "Found Monad MX [%s]"%token[0]
                        ranges.extend(handle_mx(domain,debug))
		else:
                	if debug: print "Monad Unknown [%s]"%token

    return ranges

for i in parse(sys.argv[1]):
    print i
