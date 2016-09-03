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
from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes
import struct

from pbkdf2 import PBKDF2
import os
import time
import struct

class Passmg:
    def connect(self):
        cardtype=ATRCardType(toBytes("3B F8 18 00 FF 81 31 FE 45 4A 43 4F 50 76 32 34 31 43"))
        cardrequest=CardRequest(timeout=1, cardType=cardtype)
        self.cardservice=cardrequest.waitforcard()
        self.cardservice.connection.connect()

    def select_applet(self,AID):
        select=[0x00,0xA4,0x04,0x00]
        select.append(len(AID))
        select+=AID
        data, sw1, sw2 = self.cardservice.connection.transmit(select)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during applet selection")
        return (data,sw1,sw2)
    
    def authorize(self,pin):
        #0x20 is number of authorize command
        auth=[0x80,0x20,0x00,0x00]
        auth.append(len(pin))
        auth+=pin
        data, sw1, sw2 = self.cardservice.connection.transmit(auth)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during authorisation")
        return (data,sw1,sw2)
    
    def add_password(self,name,username,password):
        #0x22 is number of add password command
        apdu=[0x80,0x22,0x00,0x00]
        #add_password expects the following format of data:
        #length of name;length of username;length of password;
        #unix timestamp of time when password was added (four ints);
        data=[]
        data.append(len(name))
        data.append(len(username))
        data.append(len(password))
        data+=BinStringToHexList(name)
        data+=BinStringToHexList(username)
        data+=BinStringToHexList(password)
        creation_time=struct.pack("I",int(time.time()))
        data+=BinStringToHexList(creation_time)
        apdu.append(len(data))
        apdu+=data
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            print ("Error: sw1: {} sw2: {}").format(hex(sw1),hex(sw2))
        return (data,sw1,sw2)
        
    def read_password(self,name):
        #0x21 is number of read password command
        #read_password expects length of password followed by name of password
        apdu=[0x80,0x21,0x00,0x00]
        data=[]
        data.append(len(name))
        data+=BinStringToHexList(name)
        apdu.append(len(data))
        apdu+=data
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during reading password")
        return (data,sw1,sw2)
    
    def list_passwords(self):
        #0x24 lis number of list_password command
        apdu=[0x80,0x24,0x00,0x00]
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during listing passwords")
        return (data,sw1,sw2)

    def delete_all_passwords(self):
        #0x26 is number of delete all password command
        apdu=[0x80,0x26,0x00,0x00]
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during wiping all passwords")
        return (data,sw1,sw2)

    def get_available_space(self):
        #0x27 is number of get available space command
        apdu=[0x80,0x27,0x00,0x00]
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during getting aviable space")
        return (data,sw1,sw2)
    
    def delete_password(self,name):
        #0x23 is number of delete password command
        apdu=[0x80,0x23,0x00,0x00]
        apdu.append(len(name)+1)
        apdu.append(len(name))
        apdu+=BinStringToHexList(name)
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during deletion of password")
        return (data,sw1,sw2)
    
    def change_pin(self,pin):
        #0x25 is number of change pin command
        apdu=[0x80,0x25,0x00,0x00]
        apdu.append(len(pin))
        apdu+=BinStringToHexList(pin)
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during pin change")
        return (data,sw1,sw2)
    
    def generate_master_key(self):
        #0x28 is number of generate master key command
        apdu=[0x80,0x28,0x00,0x00]
        data, sw1, sw2 = self.cardservice.connection.transmit(apdu)
        if(sw1!=0x90 or sw2!=0x00):
            raise PassmgException("Error during master key generation")
        return (data,sw1,sw2)

class PassmgException(Exception):
    def __init__(self,arg,code):
        self.args=arg
        self.code=code

