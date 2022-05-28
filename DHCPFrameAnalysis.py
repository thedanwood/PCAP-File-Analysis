filename = open(r"C:\Users\Woody\Documents\Uni\Cyber Security\Coursework\CyberSecurity2021.pcap","rb")
file = filename.read()

def reverse(variableName):
    variableName = bytearray.fromhex(variableName)
    variableName.reverse()
    variableName = str(variableName.hex())
    return "0x"+variableName

def formatMacAddress(hexadecimalMacAddress):
    formattedMacAddress = ""
    for index, character in enumerate(hexadecimalMacAddress, start=0):
        if index % 2 == 0:
            formattedMacAddress = formattedMacAddress + hexadecimalMacAddress[index:(index+2)]
            if(index+2 != len(hexadecimalMacAddress)):
                formattedMacAddress=formattedMacAddress+":"
    return formattedMacAddress

def formatIPAddress(hexadecimalIPAddress):
    formattedIPAddress = ""
    for index, character in enumerate(hexadecimalIPAddress, start=0):
        if index % 2 == 0:
            formattedIPAddress = formattedIPAddress + str(int(hexadecimalIPAddress[index:(index+2)],16))
            if(index+2 != len(hexadecimalIPAddress)):
                formattedIPAddress=formattedIPAddress+"."
    return formattedIPAddress

def returnNameOfHostPC(DHCPHeaderOptions):
    CFQDNFound = False
    optionTypeFieldLength = 1
    optionLengthFieldLength = 1
    startIndex = 0
    while CFQDNFound == False:
        optionType = int(DHCPHeaderOptions[startIndex:startIndex+optionTypeFieldLength].hex(),16)
        optionLength = int(DHCPHeaderOptions[startIndex+optionTypeFieldLength:startIndex+optionTypeFieldLength+optionLengthFieldLength].hex(),16)

        if optionType == 81:
            totalOptionLength = optionTypeFieldLength + optionLengthFieldLength + optionLength
            clientName = DHCPHeaderOptions[startIndex+5:startIndex+totalOptionLength]
            clientNameString = clientName.decode('ascii')
            return clientNameString
            CFQDNFound = True

        startIndex=startIndex+optionTypeFieldLength+optionLengthFieldLength+optionLength

globalHeaderLength = 24
globalHeader = file[:globalHeaderLength]

#16 length
packetHeaderLength = 16
packetHeader = file[globalHeaderLength:globalHeaderLength+packetHeaderLength]
secondTimestamp = packetHeader[:4].hex()
secondTimestamp = int(reverse(secondTimestamp),16)
millisecondTimestamp = packetHeader[4:8].hex()
millisecondTimestamp = int(reverse(millisecondTimestamp),16)

fullTimestampString = str(secondTimestamp)+"."+str(millisecondTimestamp)
fullTimestamp = float(fullTimestampString)

import datetime
timeStampDateTime = datetime.datetime.fromtimestamp(fullTimestamp).strftime('%A, %B %d, %Y %I:%M:%S')

#14 length
macHeaderLength = 14
macHeader = file[globalHeaderLength+packetHeaderLength:globalHeaderLength+packetHeaderLength+macHeaderLength]
destinationMacAddress = formatMacAddress(macHeader[:6].hex())
sourceMacAddress = formatMacAddress(macHeader[6:12].hex())


ipv4HeaderVersionAndLength = str(file[54:55].hex())
ipv4HeaderVersion = ipv4HeaderVersionAndLength[0]
ipv4HeaderLength = ipv4HeaderVersionAndLength[1]
ipv4HeaderLengthInteger = (int(ipv4HeaderLength)*4)
ipv4Header = file[54:(54+ipv4HeaderLengthInteger)]
ipv4TotalLength = int(ipv4Header[2:4].hex(),16)
sourceIPAddress = formatIPAddress(ipv4Header[12:16].hex())
destinationIPAddress = formatIPAddress(ipv4Header[16:20].hex())

DHCPFrameLength = ipv4TotalLength+14

DHCPHeader = file[82:(82+DHCPFrameLength)]
DHCPHeaderOptions = DHCPHeader[240:]
nameOfHostPC = returnNameOfHostPC(DHCPHeaderOptions)


print("Timestamp: "+str(fullTimestamp)+"\nTimestamp GMT Time: "+str(timeStampDateTime)+"\nLength of DHCP Frame: "+str(DHCPFrameLength)+"\nSource MAC Address: "+str(sourceMacAddress)+"\nDestination MAC Address: "+str(destinationMacAddress)+"\nSource IP Address: "+str(sourceIPAddress)+"\nDestination IP Address: "+str(destinationIPAddress)+"\nName of Host PC: "+nameOfHostPC)