#!/usr/local/bin/python

# Copyright 2016 Joachim 'cranix' Azgin
# This file is part of Passmg-py.
# Passmg-py is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Passmg-py is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Passmg-py.  If not, see <http://www.gnu.org/licenses/>.

from smartcard.util import HexListToBinString, BinStringToHexList
from pbkdf2 import PBKDF2
import os
import sys
import argparse
from getpass import getpass

import commands

parser = argparse.ArgumentParser()
parser.add_argument("-a","--add",action="store_true",help="Adds password")
parser.add_argument("-r","--read",action="store",help="Reads password")
parser.add_argument("-d","--delete",action="store",help="Deletes password")
parser.add_argument("-l","--list",action="store_true",help="Lists all passwords on card")
parser.add_argument("-w","--wipe",action="store_true",help="Deletes all passwords on card")
parser.add_argument("-m","--memory",action="store_true",help="Lists availabole memory")
parser.add_argument("-c","--change-pin",action="store_true",help="Change pin");
parser.add_argument("-g","--generate-master-key",action="store_true",help="Generate master key")

args = parser.parse_args()

passmg = commands.Passmg()

passmg.connect()
data, sw1, sw2 = passmg.select_applet([0xA1,0x00,0x00,0x00,0x00,0x03,0x01])
if sw1 != 144:
    print "Error during selection of applet"
    sys.exit(-1)

pin=BinStringToHexList(str(getpass("Enter pin:")))
data, sw1, sw2 = passmg.authorize(pin) 

if (sw1 != 0x90 or sw2 != 0x00):
    print "Authorisation failed"
    sys.exit(-1)

if args.read:
    data, sw1, sw2 = passmg.read_password(args.read)
    name_len = data[0]
    username_len = data[1]
    password_len = data[2]
    print ("Name: {}").format(HexListToBinString(data[3:3+name_len]))
    print ('Username: {}').format(HexListToBinString(data[3+name_len:3+name_len+username_len]))
    print ('Password: {}').format(HexListToBinString(data[3+name_len+username_len:3+name_len+username_len+password_len]))
    if (sw1 != 0x90 and sw2 != 0x00):
        print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
elif args.add:
    name=raw_input("Enter name of password: ")
    user_name=raw_input("Enter username: ")
    password=str(getpass("Enter password: "))
    password2=str(getpass("Reenter password: "))
    if password==password2:
        data, sw1, sw2 = passmg.add_password(name,user_name,password)
        if (sw1 != 0x90 and sw2 != 0x00):
            print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
    else:
        print "Passwords didn't match!"
        sys.exit(-1)
elif args.list:
    data, sw1, sw2 = passmg.list_passwords()
    if (sw1 != 0x90 and sw2 != 0x00):
        print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
        sys.exit(-1)
    while (data != []):
        length=data.pop(0)
        print HexListToBinString(data[0:length])
        del data[0:length]
elif args.wipe:
    response=raw_input("Actually delete?(Yes/No)")
    if response=="Yes" :
        data, sw1, sw2 = passmg.delete_all_passwords()
        if (sw1 != 0x90 and sw2 != 0x00):
            print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
            sys.exit(-1)
elif args.memory:
    print ("On card is room for {} passwords").format(passmg.get_available_space()[0][0])
elif args.delete:
    data, sw1, sw2 = passmg.delete_password(args.delete)
    if (sw1 != 0x90 and sw2 != 0x00):
        print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
        sys.exit(-1)
elif args.change_pin:
    pin=str(getpass("Enter new pin:"))
    pin2=str(getpass("Confirm:"))
    if pin==pin2:
        data, sw1, sw2=passmg.change_pin(pin)
        if (sw1 != 0x90 and sw2 != 0x00):
            print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
            sys.exit(-1)
    else:
        print "Pins didn't match"
        sys.exit(-1)
elif args.generate_master_key:
    data, sw1, sw2=passmg.generate_master_key()
    if (sw1 != 0x90 and sw2 != 0x00):
        print ("Error: sw1: {} sw2: {}").format(sw1,sw2)
        sys.exit(-1)


