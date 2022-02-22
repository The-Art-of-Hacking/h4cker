#!/usr/bin/env python
#------------------------------------------------------------------
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Co-Author Lilith Wyatt (liwyatt)
#------------------------------------------------------------------
# Copyright (c) 2014-2017 by Cisco Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Cisco Systems, Inc. nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#------------------------------------------------------------------
# Type definitions for the fuzzer
#
# This script defines the various message and data types used in
# the fuzzer, and utility functions used by them.
#------------------------------------------------------------------

class MessageSubComponent(object):
    def __init__(self, message, isFuzzed):
        self.message = message
        self.isFuzzed = isFuzzed
        # This includes both fuzzed messages and messages the user
        # has altered with messageprocessor callbacks
        self._altered = message
    
    def setAlteredByteArray(self, byteArray):
        self._altered = byteArray
    
    def getAlteredByteArray(self):
        return self._altered
    
    def getOriginalByteArray(self):
        return self.message

# Contains all data of a given packet of the session            
class Message(object):
    class Direction:
        Outbound = "outbound"
        Inbound = "inbound"
    
    class Format:
        CommaSeparatedHex = 0 # 00,01,02,20,2a,30,31
        Ascii = 1 # asdf\x00\x01\x02
        Raw = 2 # a raw byte array from a pcap
        
    def __init__(self):
        self.direction = -1
        # Whether any subcomponent is fuzzed - might not be entire message
        # Default to False, set to True as message subcomponents are set below
        self.isFuzzed = False 
        # This will be populated with message subcomponents
        # IE, specified as message 0 11,22,33
        # 44,55,66
        # Then 11,22,33 will be subcomponent 0, 44,55,66 will be subcomponent 1
        # If it's a traditional message, it will only have one element (entire message)
        self.subcomponents = []

    def getOriginalSubcomponents(self):
        return [subcomponent.message for subcomponent in self.subcomponents]
    
    # May or may not have actually been changed
    # Version of subcomponents that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def getAlteredSubcomponents(self):
        return [subcomponent.getAlteredByteArray() for subcomponent in self.subcomponents]
    
    def getOriginalMessage(self):
        return bytearray().join([subcomponent.message for subcomponent in self.subcomponents])
    
    # May or may not have actually been changed
    # Version of message that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def getAlteredMessage(self):
        return bytearray().join([subcomponent.getAlteredByteArray() for subcomponent in self.subcomponents])
    
    def resetAlteredMessage(self):
        for subcomponent in self.subcomponents:
            subcomponent.setAlteredByteArray(subcomponent.message)
    
    # Set the message on the Message
    # sourceType - Format.CommaSeparatedHex, Ascii, or Raw
    # message - Message in above format
    # isFuzzed - whether this message should have its subcomponent
    #   flag isFuzzed set
    def setMessageFrom(self, sourceType, message, isFuzzed):
        if sourceType == self.Format.CommaSeparatedHex:
            message = bytearray([x.decode("hex") for x in message.split(",")])
        elif sourceType == self.Format.Ascii:
            message = self.deserializeByteArray(message)
        elif sourceType == self.Format.Raw:
            message = message
        else:
            raise RuntimeError("Invalid sourceType")
        
        self.subcomponents = [MessageSubComponent(message, isFuzzed)]
        
        if isFuzzed:
            self.isFuzzed = True
    
    # Same arguments as above, but adds to .message as well as
    # adding a new subcomponent
    # createNewSubcomponent - If false, don't create another subcomponent,
    #   instead, append new message data to last subcomponent in message
    def appendMessageFrom(self, sourceType, message, isFuzzed, createNewSubcomponent=True):
        if sourceType == self.Format.CommaSeparatedHex:
            newMessage = bytearray([x.decode("hex") for x in message.split(",")])
        elif sourceType == self.Format.Ascii:
            newMessage = self.deserializeByteArray(message)
        elif sourceType == self.Format.Raw:
            newMessage = message
        else:
            raise RuntimeError("Invalid sourceType")
        
        if createNewSubcomponent:
            self.subcomponents.append(MessageSubComponent(newMessage, isFuzzed))
        else:
            self.subcomponents[-1].message += newMessage

        if isFuzzed:
            # Make sure message is set to fuzz as well
            self.isFuzzed = True
    
    def isOutbound(self):
        return self.direction == self.Direction.Outbound
    
    def __eq__(self, other):
        # bytearray (for message) implements __eq__()
        return self.direction == other.direction and self.message == other.message
    
    @classmethod
    def serializeByteArray(cls, byteArray):
        return repr(str(byteArray))
    
    @classmethod
    def deserializeByteArray(cls, string):
        # This appears to properly reverse repr() without the risks of eval
        return bytearray(string[1:-1].encode('utf8').decode('unicode-escape').encode('utf8'))
    
    def getAlteredSerialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serializedMessage = "{0}{1} {2}\n".format("fuzz " if self.subcomponents[0].isFuzzed else "", self.direction, self.serializeByteArray(self.subcomponents[0].getAlteredByteArray()))
            
            for subcomponent in self.subcomponents[1:]:
                serializedMessage += "sub {0}{1}\n".format("fuzz " if subcomponent.isFuzzed else "", self.serializeByteArray(subcomponent.getAlteredByteArray()))
            
            return serializedMessage
    
    def getSerialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serializedMessage = "{0} {1}{2}\n".format(self.direction, "fuzz " if self.subcomponents[0].isFuzzed else "", self.serializeByteArray(self.subcomponents[0].message))
            
            for subcomponent in self.subcomponents[1:]:
                serializedMessage += "sub {0}{1}\n".format("fuzz " if subcomponent.isFuzzed else "", self.serializeByteArray(subcomponent.message))
            
            return serializedMessage

    # Utility function for setFromSerialized and appendFromSerialized below
    def _extractMessageComponents(self, serializedData):
        firstQuoteSingle = serializedData.find('\'')
        lastQuoteSingle = serializedData.rfind('\'')
        firstQuoteDouble = serializedData.find('"')
        lastQuoteDouble = serializedData.rfind('"')
        firstQuote = -1
        lastQuote = -1
        
        if firstQuoteSingle == -1 or firstQuoteSingle == lastQuoteSingle:
            # If no valid single quotes, go double quote
            firstQuote = firstQuoteDouble
            lastQuote = lastQuoteDouble
        elif firstQuoteDouble == -1 or firstQuoteDouble == lastQuoteDouble:
            # If no valid double quotes, go single quote
            firstQuote = firstQuoteSingle
            lastQuote = lastQuoteSingle
        elif firstQuoteSingle < firstQuoteDouble:
            # If both are valid, go single if further out
            firstQuote = firstQuoteSingle
            lastQuote = lastQuoteSingle
        else:
            # Both are valid but double is further out
            firstQuote = firstQuoteDouble
            lastQuote = lastQuoteDouble
        
        if firstQuote == -1 or lastQuote == -1 or firstQuote == lastQuote:
            raise RuntimeError("Invalid message data, no message found")

        # Pull out everything, quotes and all, and deserialize it
        messageData = serializedData[firstQuote:lastQuote+1]
        # Process the args
        serializedData = serializedData[:firstQuote].split(" ")
        
        return (serializedData, messageData)
    
    # Handles _one line_ of data, either "inbound" or "outbound"
    # Lines following this should be passed to appendFromSerialized() below
    def setFromSerialized(self, serializedData):
        serializedData = serializedData.replace("\n", "")
        (serializedData, messageData) = self._extractMessageComponents(serializedData)
        
        if len(messageData) == 0 or len(serializedData) < 1:
            raise RuntimeError("Invalid message data")
        
        direction = serializedData[0]
        args = serializedData[1:-1]
        
        if direction != "inbound" and direction != "outbound":
            raise RuntimeError("Invalid message data, unknown direction {0}".format(direction))
        
        isFuzzed = False
        if "fuzz" in args:
            isFuzzed = True
            if len(serializedData) < 3:
                raise RuntimeError("Invalid message data")
        
        self.direction = direction
        self.setMessageFrom(self.Format.Ascii, messageData, isFuzzed)
    
    # Add another line, used for multiline messages
    def appendFromSerialized(self, serializedData, createNewSubcomponent=True):
        serializedData = serializedData.replace("\n", "")
        (serializedData, messageData) = self._extractMessageComponents(serializedData)
        
        if createNewSubcomponent:
            if len(messageData) == 0 or len(serializedData) < 1 or serializedData[0] != "sub":
                raise RuntimeError("Invalid message data")
        else:
            # If not creating a subcomponent, we won't have "sub", "fuzz", and the other fun stuff
            if len(messageData) == 0:
                raise RuntimeError("Invalid message data")
        
        args = serializedData[1:-1]
        # Put either "fuzz" or nothing before actual message
        # Can tell the difference even with ascii because ascii messages have '' quotes
        # IOW, even a message subcomponent 'fuzz' will have the 's around it, not be fuzz without quotes
        isFuzzed = False
        if "fuzz" in args:
            isFuzzed = True
        
        self.appendMessageFrom(self.Format.Ascii, messageData, isFuzzed, createNewSubcomponent=createNewSubcomponent)

class MessageCollection(object):
    def __init__(self):
        self.messages = []
    
    def addMessage(self, message):
        self.messages.append(message)
    
    def doClientMessagesMatch(self, otherMessageCollection):
        for i in range(0, len(self.messages)):
            # Skip server messages
            if not self.messages[i].isOutbound():
                continue
            try:
                # Message implements __eq__()
                if self.messages[i] != otherMessageCollection.messages[i]:
                    return False
            except IndexError:
                return False
        
        # All messages passed
        return True

import os
import os.path
from copy import deepcopy

# Handles all the logging of the fuzzing session
# Log messages can be found at sample_apps/<app>/<app>_logs/<date>/
class Logger(object):
    def __init__(self, folderPath):
        self._folderPath = folderPath
        if os.path.exists(folderPath):
            print("Data output directory already exists: %s" % (folderPath))
            exit()
        else:
            try:
                os.makedirs(folderPath)
            except:
                print("Unable to create logging directory: %s" % (folderPath))
                exit()

        self.resetForNewRun()

    # Store just the data, forget trying to make a Message object
    # With the subcomponents and everything, it just gets weird, 
    # and we don't need it
    def setReceivedMessageData(self, messageNumber, data):
        self.receivedMessageData[messageNumber] = data

    def setHighestMessageNumber(self, messageNumber):
        # The highest message # this fuzz session made it to
        self._highestMessageNumber = messageNumber

    def outputLastLog(self, runNumber, messageCollection, errorMessage):
        return self._outputLog(runNumber, messageCollection, errorMessage, self._lastReceivedMessageData, self._lastHighestMessageNumber)

    def outputLog(self, runNumber, messageCollection, errorMessage):
        return self._outputLog(runNumber, messageCollection, errorMessage, self.receivedMessageData, self._highestMessageNumber)

    def _outputLog(self, runNumber, messageCollection, errorMessage, receivedMessageData, highestMessageNumber):
        with open(os.path.join(self._folderPath, str(runNumber)), "w") as outputFile:
            print("Logging run number %d" % (runNumber))
            outputFile.write("Log from run with seed %d\n" % (runNumber))
            outputFile.write("Error message: %s\n" % (errorMessage))

            if highestMessageNumber == -1 or runNumber == 0:
                outputFile.write("Failed to connect on this run.\n")

            outputFile.write("\n")

            i = 0
            for message in messageCollection.messages:
                outputFile.write("Packet %d: %s" % (i, message.getSerialized()))

                if message.isFuzzed:
                    outputFile.write("Fuzzed Packet %d: %s\n" % (i, message.getAlteredSerialized()))
                
                if i in receivedMessageData:
                    # Compare what was actually sent to what we expected, log if they differ
                    if receivedMessageData[i] != message.getOriginalMessage():
                        outputFile.write("Actual data received for packet %d: %s" % (i, Message.serializeByteArray(receivedMessageData[i])))
                    else:
                        outputFile.write("Received expected data\n")

                if highestMessageNumber == i:
                    if message.isOutbound():
                        outputFile.write("This is the last message sent\n")
                    else:
                        outputFile.write("This is the last message received\n")

                outputFile.write("\n")
                i += 1

    def resetForNewRun(self):
        try:
            self._lastReceivedMessageData = deepcopy(self.receivedMessageData)
            self._lastHighestMessageNumber = self._highestMessageNumber
        except AttributeError:
            self._lastReceivedMessageData = {}
            self._lastHighestMessageNumber = -1

        self.receivedMessageData = {}
        self.setHighestMessageNumber(-1)
