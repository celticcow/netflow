#!/usr/bin/python3 -W ignore::DeprecationWarning

import requests
import json
import sys
import time
import apifunctions
import base64

#remove the InsecureRequestWarning messages
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


"""
get netflow data
"""

"""
go through a cma and find gateways
"""
def get_gateways_per_cma(ip_addr, sid):
    print("in get_gateays_per_cma")

    debug = 0

    gateways = {}

    gateways_result = apifunctions.api_call(ip_addr, "show-gateways-and-servers", {"details-level" : "full"}, sid)

    #print(json.dumps(gateways_result))

    for x in range(gateways_result['total']):

        gw = gateways_result['objects'][x]['name']

        if(debug == 1):
            print(gw)
            print(gateways_result['objects'][x]['type'])

        if(gateways_result['objects'][x]['type'] == "CpmiClusterMember"):

            #print(gateways_result['objects'][x]['ipv4-address'])

            ifaces = len(gateways_result['objects'][x]['interfaces'])

            #print(gateways_result['objects'][x]['interfaces'])
            for i in range(ifaces):
                #print(gateways_result['objects'][x]['interfaces'][i]['interface-name'])

                if(gateways_result['objects'][x]['interfaces'][i]['interface-name'] == "Mgmt"):
                    ip_info = gateways_result['objects'][x]['interfaces'][i]['ipv4-address']
                    #print(ip_info)
                    gateways[gw] = ip_info
        if(debug == 1):
            print("---------------------------------------------------------------------")
    return(gateways)
#end_of for  x in range   ipv4-address

def script_to_run(fwname, ip_addr, sid):
    ###
    ###  show config netflow
    
    debug = 0

    get_log_status = {
        "script-name" : "log status",
        "script" : "clish -c 'show configuration netflow'",
        "targets" : [fwname]
    }

    log_result = apifunctions.api_call(ip_addr, "run-script", get_log_status, sid)

    if(debug == 1):
        print(json.dumps(log_result))
    
    #get task_ID
    task_id = log_result['tasks'][0]['task-id']

    #get task info ... lots of stuff in here
    task_info = apifunctions.api_call(ip_addr, "show-task", {"task-id" : task_id, "details-level" : "full"}, sid)

    percent = task_info['tasks'][0]['progress-percentage']

    while(percent != 100):
        if(debug == 1):
            print("In progress")
        
        time.sleep(1)

        task_info = apifunctions.api_call(ip_addr, "show-task", {"task-id" : task_id, "details-level" : "full"}, sid)  #, "details-level" : "full"
        status = task_info['tasks'][0]['status']
        percent = task_info['tasks'][0]['progress-percentage']

        if(debug == 1):
            print(json.dumps(task_info))
            print(percent)
            print("/////////////////////////////////////")
    #end of while loop

    if(debug == 1):
        print(json.dumps(task_info))
    
    if(debug == 1):
        print("------------------------------------------------------\n\n")
        print(task_info['tasks'][0]['task-details'][0]['responseMessage'])
        print("\n\n\n")

    return(task_info['tasks'][0]['task-details'][0]['responseMessage'])
#end of script_to_run()

"""
take base 64 result and convert
"""
def get_results(b64):
    debug = 0

    print("in function get_results")

    a_base64_bytes = b64.encode('ascii')
    a_message_bytes = base64.b64decode(a_base64_bytes)
    a_message = a_message_bytes.decode('ascii')

    print(a_message)

#end of get_results()

def main():
    print("in main")

    debug = 1

    ip_addr = "146.18.96.16"
    ip_cma  = "146.18.96.25"
    user    = "gdunlap"
    passwd  = "1qazxsw2"

    sid = apifunctions.login(user, passwd, ip_addr, ip_cma)

    if(debug == 1):
        print("session id : " + sid)

    gateway_info = {}

    gateway_info = get_gateways_per_cma(ip_addr, sid)
    """
    for gw in gateway_info:
        print(gw)
        try:
            base64_result = script_to_run(gw, ip_addr, sid)
            if(debug == 1):
                print("++++++++++++++++++++++++++++++++++++")
                print(base64_result)
            
            print("^^^^^^^^^^^^^^^^^^^^^^^^^^")
            print(get_results(base64_result))
        except:
            print("error running script")
    """

    base64_result = script_to_run("bd70-100g", ip_addr, sid)
    print("++++++++++++++++++++++++++++++++++++")
    #print(base64_result)
    print(get_results(base64_result))



    #### Don't Need to publish 
    print("Starting Logout ZZZZZZZZ")
    time.sleep(20)

    ### logout
    logout_result = apifunctions.api_call(ip_addr, "logout", {}, sid)
    if(debug == 1):
        print(logout_result)
#end of main

if __name__ == "__main__":
    main()

#end of program