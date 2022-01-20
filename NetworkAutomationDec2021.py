import requests
from flask import Flask, render_template, request,Response, redirect, url_for, flash
from nornir import InitNornir
import csv
import sys
import ipapi
from nornir.core.exceptions import NornirExecutionError
import pyshark
from tabulate import tabulate
from nornir.plugins.functions.text import print_result, print_title
from nornir.plugins.tasks.networking import netmiko_send_config, netmiko_send_command,napalm_get
import pandas as pd
from nornir.plugins.tasks.files import write_file
from nornir.core.filter import F
from datetime import datetime
import pathlib
from scapy.all import *
import base64
from scapy.layers.inet import traceroute
import graphviz
import ipaddress

import os
import yaml
from datetime import date
from nornir.plugins.tasks import networking
from flask_apscheduler import APScheduler
from flask_sqlalchemy import SQLAlchemy
import scapy.all as scapy
from scapy.utils import PcapWriter
import time
import datetime




exiting = False

app = Flask(__name__)
scheduler = APScheduler()
#app.secret_key = "Secret Key"
app.config['SECRET_KEY']='imranawan'
# SqlAlchemy Database Configuration With Sqllite

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///NMSdata'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

    

# Creating model table for our CRUD database
class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    hostname = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    port = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    secret = db.Column(db.String(100))
    groups = db.Column(db.String(100))
    pas = db.Column(db.String(100))

    def __init__(self, name, hostname, platform,port,username,password,secret,groups,pas):

        self.name = name
        self.hostname = hostname
        self.platform = platform
        self.port = port
        self.username = username
        self.password = password
        self.secret = secret
        self.groups = groups
        self.pas = pas
db.create_all()
# query on all our employee data
@app.route('/index22')
def Index22():
    all_data = Data.query.all()

    f = open('inventory.csv', 'w',newline='')
    out = csv.writer(f)
    out.writerow(['name', 'hostname', 'platform','port','username','password','secret','groups','secret'])
    for item in Data.query.all():
        out.writerow([item.name,item.hostname,item.platform, item.port, item.username, item.password,item.secret,item.groups,item.pas])
        #print("Printing CSV Data..")
    f.close()

    return render_template("index22.html", employees=all_data)


# this route is for inserting data to mysql database via html forms
@app.route('/insert', methods=['POST'])
def insert():
    if request.method == 'POST':
        name = request.form['name']
        hostname = request.form['hostname']
        platform = request.form['platform']
        port = request.form['port']
        username = request.form['username']
        password = request.form['password']
        secret = request.form['secret']
        groups = request.form['groups']
        pas = request.form['pas']

        my_data = Data(name, hostname, platform,port,username,password,secret,groups,pas)
        db.session.add(my_data)
        db.session.commit()

        flash("Device Inserted Successfully")

        return redirect(url_for('Index22'))


# this is our update route where we are going to update our Device
@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        my_data = Data.query.get(request.form.get('id'))

        my_data.name = request.form['name']
        my_data.hostname = request.form['hostname']
        my_data.platform = request.form['platform']
        my_data.port = request.form['port']
        my_data.username = request.form['username']
        my_data.password = request.form['password']
        my_data.secret = request.form['secret']
        my_data.groups = request.form['groups']
        my_data.pas = request.form['pas']

        db.session.commit()
        flash("Device Updated Successfully")

        return redirect(url_for('Index22'))


# This route is for deleting our Record
@app.route('/delete/<id>/', methods=['GET', 'POST'])
def delete(id):
    my_data = Data.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Device Deleted Successfully")

    return redirect(url_for('Index22'))
#//////////////////////////////////////////////////////

#Class for CSV TO YAML////////////////////////
class Csv2NornirSimple:

    def __init__(self, filename):
        self.filename = filename
        self.inventory_data = []

    def inventory_converter(self):
        inventory_list = []
        # Currently not in use

        try:
            with open(self.filename) as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    inventory_list.append([
                        row["name"],
                        row["hostname"],
                        row["platform"],
                        row["port"],
                        row["username"],
                        row["password"],
                        row["secret"],
                        row["groups"],
                        row["secret"],



                    ])
                self.inventory_data = inventory_list
        except FileNotFoundError:
            print(f"Please make sure that filename is correct and exists...")
            sys.exit(1)


    # Iterates over the list and creates the csv_inventory.yaml based on the Nornir model

    def make_nornir_inventory(self):
        if len(self.inventory_data) < 1:
            print("The list argument doesn't have any records! Cannot create an inventory file out of an empty list!")
            return ValueError
        try:

            with open("csv_inventory.yaml", "w") as out_file:
                out_file.write("---\n")
                for host in self.inventory_data:
                    out_file.write(f"{host[0]}:\n")
                    out_file.write(f"  hostname: {host[1]}\n")
                    out_file.write(f"  platform: {host[2]}\n")
                    out_file.write(f"  port: {host[3]}\n")
                    out_file.write(f"  username: {host[4]}\n")
                    out_file.write(f"  password: {host[5]}\n")
                    out_file.write(f"  secret: {host[6]}\n")

                    if len(host[7].split("_")) > 0:
                        out_file.write(f"  groups:\n")
                        for group in host[7].split("__"):
                            out_file.write(f"    - {group}\n")

                    else:
                        out_file.write("\n")
                    out_file.write(f"  connection_options:\n")
                    out_file.write(f"    napalm:\n")
                    out_file.write(f"      extras:\n")
                    out_file.write(f"        optional_args:\n")
                    out_file.write(f"          secret: {host[8]}\n")




                print("Inventory file created...")
        except PermissionError:
            print("An error occurred whilst trying to write into the file... Please make sure that there are enough permission assigned to the user executing the script...")
            sys.exit(1)


csv2n = Csv2NornirSimple("inventory.csv")
inventory_list = csv2n.inventory_converter()
csv2n.make_nornir_inventory()

# Verify that the inventory file is readable

nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
#//////////////////////////////////////////////

#Home Page////////////////////////////////////
@app.route('/')
def home():
    

    return render_template("home.html")


#/////////////////////////////////////////////

#///////////////////////////////////BackupConfig///////////////////
@app.route('/backup', methods = ['GET', 'POST'])
def backup():
    nr.data.reset_failed_hosts()
    #command = request.form.get('command')
    groupname = request.form.get('backup')


    try:

        def backup_configurations(task):
            config_dir = "config-archive"
            device_dir = config_dir + "/" + task.host.name
            pathlib.Path(config_dir).mkdir(exist_ok=True)
            pathlib.Path(device_dir).mkdir(exist_ok=True)
            r = task.run(task=networking.napalm_get, getters=["config"])
            task.run(task=write_file,content=r.result["config"]["running"],
             filename=f"" + str(device_dir) + "/" + str(date.today()) + ".txt",)
        hosts=nr.filter(F(groups__contains=groupname))
        record=hosts.run(name="Creating Backup Archive", task=backup_configurations)
        results=nr.data.failed_hosts
        l=len(nr.data.failed_hosts)



    except:
            print(' Make sure GroupName is OK.')


    return render_template('backup.html',  results=results,l=l)
#///////////////////////////////////////////////////////////////////
#///////////////////////////////////BackupConfigbyCommands///////////////////
@app.route('/backup1', methods = ['GET', 'POST'])
def backup1():
    nr.data.reset_failed_hosts()
    results=''
    l=''
    command1 = request.form.get('command1')
    groupname1 = request.form.get('backup1')


    try:

        def backup_configurations(task):
            config_dir = "config-archive"
            device_dir = config_dir + "/" + task.host.name
            pathlib.Path(config_dir).mkdir(exist_ok=True)
            pathlib.Path(device_dir).mkdir(exist_ok=True)
            r = task.run(task=netmiko_send_command, command_string = command1)
            task.run(task=write_file,content=r.result,
                     filename=f"" + str(device_dir) + "/" + str(date.today()) + ".txt",)
        hosts=nr.filter(F(groups__contains=groupname1))
        record=hosts.run(name="Creating Backup Archive", task=backup_configurations)



    except:
        print(' Make sure GroupName is OK.')


    return render_template('backup.html',  results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))


#///////////////////////////////////////////////////////////////////

#/INDEXhtml/////////////////////////////////////////////////////////////////
def load_hosts_inventory(filename):
    return yaml.load(open(filename, "r"), Loader=yaml.SafeLoader)
hosts = load_hosts_inventory("csv_inventory.yaml")
# print(hosts)
inventory = []
for host in hosts:
    inventory.append({"name": host, "mgmt_ip": hosts[host]["hostname"],"group": hosts[host]["groups"], "platform": hosts[host]["platform"]})
#//////////////////////////////////////////////////////////////////////////
#///////////Factshtml/////////////////////////////////////////////////////
def get_facts(device):
    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    nrfil = nr.filter(name=device)
    results = nrfil.run(
        task=networking.napalm_get,
        getters=["facts", "interfaces","arp_table","interfaces_counters"]
    )
    return results[device][0].result
@app.route('/facts/<string:device_name>' , methods = ['GET', 'POST'])
def display_facts(device_name):
    nr.data.reset_failed_hosts()
    facts = get_facts(device_name)

    arp_list= []
    for arp in facts["arp_table"]:
        arp_list.append(arp)
    ios_output2=facts["interfaces_counters"]



    device_interface_list = []
    for interface in facts["facts"]["interface_list"]:
        device_interface_list.append({"name": interface,
                                      "enabled":  facts["interfaces"][interface]["is_enabled"],
                                      "up": facts["interfaces"][interface]["is_up"],
                                      "description": facts["interfaces"][interface]["description"],
                                      "mac": facts["interfaces"][interface]["mac_address"],
                                      "mtu": facts["interfaces"][interface]["mtu"],
                                      "speed": facts["interfaces"][interface]["speed"],
                                      "last_flapped": facts["interfaces"][interface]["last_flapped"]
                                      })

    return render_template("facts.html", device_name=device_name, facts=facts,
                           interface_list=device_interface_list,arp_list=arp_list,ios_output2=ios_output2)
#////////////////////////////////////////////////////////////////////////

#/////////////////////////SaveShowCommandOutPutbyGroup/////////////////////////
@app.route('/saveshowcommand', methods=['GET', 'POST'])
def saveshowcommand():

    group = request.form.get('group')
    command=request.form.get('command')

    def show_configurations(task):
        config_dir = "ShowCommand-archive"
        date_dir = config_dir + "/" + str(date.today())
        command_dir = date_dir + "/" + command
        pathlib.Path(config_dir).mkdir(exist_ok=True)
        pathlib.Path(date_dir).mkdir(exist_ok=True)
        pathlib.Path(command_dir).mkdir(exist_ok=True)
        r = task.run(task=netmiko_send_command, command_string=command)
        task.run(task=write_file,content=r.result,
            filename=f"" + str(command_dir) + "/" + task.host.name + ".txt",
        )

    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    nr.data.reset_failed_hosts()
    hosts=nr.filter(F(groups__contains=group))

    result = hosts.run(name="Creating Show Command Backup Archive", task=show_configurations)

    return render_template('saveshowcommand.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts) )


#///////////////////////////////////SaveShowCommandOutPutbyName///////////////////////////////////
@app.route('/saveshowcommand1', methods=['GET', 'POST'])
def saveshowcommand1():

    name = request.form.get('group1')
    command1=request.form.get('command1')

    def show_configurations(task):
        config_dir = "ShowCommand-archive"
        date_dir = config_dir + "/" + str(date.today())
        command_dir = date_dir + "/" + command1
        pathlib.Path(config_dir).mkdir(exist_ok=True)
        pathlib.Path(date_dir).mkdir(exist_ok=True)
        pathlib.Path(command_dir).mkdir(exist_ok=True)
        r = task.run(task=netmiko_send_command, command_string=command1)
        task.run(task=write_file,content=r.result,
                 filename=f"" + str(command_dir) + "/" + task.host.name + ".txt",
                 )
    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    hosts=nr.filter(F(name__contains=name))

    result = hosts.run(name="Creating Show Command Backup Archive", task=show_configurations)

    return render_template('saveshowcommand.html',  results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))


#//////////////////////////////////////////////////////////////////////
#///////////////////////configfile////////////////////////////
@app.route('/fileconfig', methods=['GET','POST'])
def fileconfig():
    input_days = ''
    if request.method == 'POST':
        input_days = request.form['textbox']
        with open('config_textfile', 'w') as f:
            f.write(str(input_days))
    return render_template('fileconfig.html', days=input_days)

#/////////////////////////////////////////////////////////////
#///////////////////////////////Automation///////////////////////////////////
@app.route('/automate', methods = ['GET', 'POST'])
def automate():
    nr.data.reset_failed_hosts()
    g=request.form.get('config')
    hosts=nr.filter(F(groups__contains=g))
    def automate1(job):
        job.run(task=netmiko_send_config, config_file= "config_textfile")
    results = hosts.run(task = automate1)
    hosts.close_connections()

    return render_template('automate.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))
#////////////////////////////////////////////////////////////////////////////////////
#///////////////////////////////SaveRunningConfig///////////////////////////////////
@app.route('/configsave', methods = ['GET', 'POST'])
def configsave():
    nr.data.reset_failed_hosts()
    command=request.form.get('command')
    c = request.form.get('group')
    hosts=nr.filter(F(groups__contains=c))
    def automate(job):
        job.run(task=netmiko_send_command, command_string = command)
    results = hosts.run(task = automate)

    return render_template('configsave.html', results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))
#//////////////////////////////////////////////////////////////////////////
#/////////////////////////////////// IP FINDER //////////////////////

@app.route('/ipfinder', methods = ['GET', 'POST'])
def ipfinder():
    data=[]
    try:
        data = ipapi.location(ip=request.form.get('search'), output='json')
        print(data)
    except:
        print('Not valid')
    return render_template('ipfinder.html', data=data)

#//////////////////////////// IPADDRESS////////////////////////////////////////
@app.route('/ipaddress', methods=['GET','POST'])
def ipaddr():

    try:
        p = []
        ip = request.form.get('ip')
        print(ip)
        p.append("IP Enter is "+ip)

        net4 = ipaddress.ip_network(ip)
        p.append("Prefix is :")
        p.append(net4.prefixlen )
        p.append("Subnetmask is :")
        p.append(net4.netmask)
        p.append("Total IPs is :")
        p.append(net4.num_addresses)
        p.append("Broadcast is :")
        p.append(net4.broadcast_address)
        p.append("First SubNetwork :")
        for x in net4.subnets():
            p.append(x)


    except:
        print("No")

    return render_template('ipaddress.html', len=len(p), p=p)


#//////////////////////////////////////////////////////////////////

#//////////////////////////// COMMANDER////////////////////////////////////////
@app.route('/commander', methods=['GET','POST'])
def commander():
  z=''
  nr.data.reset_failed_hosts()
  try:
    command = request.form.get('command')
    name =   request.form.get('name')
    hosts=nr.filter(name=name)
    results = hosts.run(task=netmiko_send_command, command_string=command )
    z=results[name][0]
    results=''
    l=''

  except:
      print("Fail to Print")
  return render_template('commander.html',results=nr.data.failed_hosts,l=len(nr.data.failed_hosts),z=z)


#//////////////////////////////////////////////////////////////////
#//////////////////////////////////////Traceroute////////////////////////////////////////

@app.route('/trace/<string:ip>' , methods = ['GET', 'POST'])
def trace(ip):

    os.remove("./static/traceroute_graph.svg")
    hosts = [ip]    
    res,unans = traceroute(hosts)
    res.graph(target=">./static/traceroute_graph.svg")

    return render_template('traceroute.html',ip=ip)

#///////////////////////////////////////////////////////////////////////////////////////
#////////////facts1.html////////////////////////////////////////////////////////////

@app.route('/facts1', methods = ["POST","GET"])
def facts1():
    nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
    getter_output = nr.run(task=napalm_get,on_failed=True, getters=["facts"])
    #Print napalm getters output via print_result function
    print_result(getter_output)
    list = []
    #For loop to get interusting values from the multiple devices output
    for host, task_results in getter_output.items():    
      try:  
       
            #Get the device facts result
            device_output = task_results[0].result
            data = {}
            data["host"] = host
            #From Dictionery get vendor name
            data["vendor"] = device_output["facts"]["vendor"]
            #From Dictionery get model
            data["model"] = device_output["facts"]["model"]
            # From Dictionery get version
            data["hostname"] = device_output["facts"]["hostname"]
            # From Dictionery get serial
            data["ser_num"] = device_output["facts"]["serial_number"]
            # From Dictionery get uptime
            data["uptime"] = device_output["facts"]["uptime"]
            # Append results to a list to be passed to facts.html page
            list.append(data)
            nr.close_connections()
        #print(list)
        #return render_template("facts1.html", resfac=list,results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))      # Send the values of list to the next page for printing
      except:
        
            data["host"] = host
            #From Dictionery get vendor name
            data["vendor"] = ""
            #From Dictionery get model
            data["model"] = ""
            # From Dictionery get version
            data["version"] = ""
            # From Dictionery get serial
            data["ser_num"] = ""
            # From Dictionery get uptime
            data["uptime"] = "Down/FailToConnect"
            # Append results to a list to be passed to facts.html page
            list.append(data)

        #print(list)
    return render_template("facts1.html", resfac=list,results=nr.data.failed_hosts,l=len(nr.data.failed_hosts))

 #//////////////////////////////////////////////////////////////////////////
#//////////////////////////////////////Scan Traffic////////////////////////////////////////

@app.route('/scan/<string:ip>' , methods = ['GET', 'POST'])
def scan(ip):

    hosts = ip
    packet=pyshark.FileCapture("scan.pcap",display_filter="ip.addr == "+ hosts, only_summaries=True,custom_parameters=None)
    packet.close()
    return render_template('scapytable.html',ip=ip,pkt=packet)

#///////////////////////////////////////////////////////////////////////////////////////
#//////////////////////////////////////capture Traffic////////////////////////////////////////

@app.route('/captures/<int:no>' , methods = ['GET', 'POST'])
def captures(no):
    import asyncio
    asyncio.set_event_loop(asyncio.new_event_loop())
    number=no
    print(number)
    afterno=number-1
    cap = pyshark.FileCapture('scan.pcap')
    cap1=(cap[afterno])
    cap.close()
    return render_template('capture.html',pkt=cap1)

#///////////////////////////////////////////////////////////////////////////////////////
#///////////////////////Start Sniffing////////////////////////////



#/////////////////////////////////////////////////////////////
#///////////////////////Stop Program////////////////////////////
@app.route('/exit', methods=['GET','POST'])
def exit():
    global exiting
    exiting = True
    return "Done"
@app.teardown_request
def teardown(exception):
    if exiting:
        os._exit(0)


#/////////////////////////////////////////////////////////////
#///////////////////////Index Inventory////////////////////////////
@app.route('/index', methods=['GET','POST'])
def index():
#Class for CSV TO YAML////////////////////////
 class Csv2NornirSimple:

    def __init__(self, filename):
        self.filename = filename
        self.inventory_data = []

    def inventory_converter(self):
        inventory_list = []
        # Currently not in use

        try:
            with open(self.filename) as csv_file:
                csv_reader = csv.DictReader(csv_file)
                for row in csv_reader:
                    inventory_list.append([
                        row["name"],
                        row["hostname"],
                        row["platform"],
                        row["port"],
                        row["username"],
                        row["password"],
                        row["secret"],
                        row["groups"],
                        row["secret"],



                    ])
                self.inventory_data = inventory_list
        except FileNotFoundError:
            print(f"Please make sure that filename is correct and exists...")
            sys.exit(1)


    # Iterates over the list and creates the csv_inventory.yaml based on the Nornir model

    def make_nornir_inventory(self):
        if len(self.inventory_data) < 1:
            print("The list argument doesn't have any records! Cannot create an inventory file out of an empty list!")
            return ValueError
        try:

            with open("csv_inventory.yaml", "w") as out_file:
                out_file.write("---\n")
                for host in self.inventory_data:
                    out_file.write(f"{host[0]}:\n")
                    out_file.write(f"  hostname: {host[1]}\n")
                    out_file.write(f"  platform: {host[2]}\n")
                    out_file.write(f"  port: {host[3]}\n")
                    out_file.write(f"  username: {host[4]}\n")
                    out_file.write(f"  password: {host[5]}\n")
                    out_file.write(f"  secret: {host[6]}\n")

                    if len(host[7].split("_")) > 0:
                        out_file.write(f"  groups:\n")
                        for group in host[7].split("__"):
                            out_file.write(f"    - {group}\n")

                    else:
                        out_file.write("\n")
                    out_file.write(f"  connection_options:\n")
                    out_file.write(f"    napalm:\n")
                    out_file.write(f"      extras:\n")
                    out_file.write(f"        optional_args:\n")
                    out_file.write(f"          secret: {host[8]}\n")




                #print("Inventory file created...")
        except PermissionError:
            print("An error occurred whilst trying to write into the file... Please make sure that there are enough permission assigned to the user executing the script...")
            sys.exit(1)


 csv2n = Csv2NornirSimple("inventory.csv")
 inventory_list = csv2n.inventory_converter()
 csv2n.make_nornir_inventory()

# Verify that the inventory file is readable

 nr = InitNornir(inventory={"plugin": "nornir.plugins.inventory.simple.SimpleInventory", "options": {"host_file": "csv_inventory.yaml"}})
#//////////////////////////////////////////////
 def load_hosts_inventory(filename):
    return yaml.load(open(filename, "r"), Loader=yaml.SafeLoader)
 hosts = load_hosts_inventory("csv_inventory.yaml")
# print(hosts)
 inventory = []
 for host in hosts:
    inventory.append({"name": host, "mgmt_ip": hosts[host]["hostname"],"group": hosts[host]["groups"], "platform": hosts[host]["platform"]})

 return render_template("index.html", inventory = inventory)
#/////////////////////////////////////////////////////////////////
def job():
    TNOW = datetime.datetime.now().replace(microsecond=0)
    print ('Initiating Sniff at ' + str(TNOW))
    packets=scapy.sniff( count=300)
    pktdump = PcapWriter("scan.pcap", append=True, sync=True)
    pktdump.write(packets)


#/////////////////////////////////////////////////////////////

if __name__ == "__main__":
    #scheduler.add_job(id ='Sniffing task', func = job, trigger = 'interval', seconds = 60)
    #scheduler.start()
    app.run(host="0.0.0.0",port=5000)
    
    