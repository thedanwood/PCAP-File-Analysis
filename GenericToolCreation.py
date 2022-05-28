filename = open(r"C:\Users\Woody\Documents\Uni\Cyber Security\Coursework\CyberSecurity2021.pcap","rb")

def reverse(variableName):
    variableName = bytearray.fromhex(variableName)
    variableName.reverse()
    variableName = str(variableName.hex())
    return "0x"+variableName

def extractDomainName(data):
    index = 0
    endOfDomainName = False
    domainName = ""
    while endOfDomainName == False:

        wordLength = int(data[index:index+1].hex(),16)
        if wordLength == 0:
             endOfDomainName=True

        if index != 0 and endOfDomainName == False:
            domainName = domainName+"."

        partOfDomainName = (data[index+1:index+wordLength+1]).decode('ascii')
        domainName = domainName+str(partOfDomainName)
        index=index+1+wordLength

    return domainName

globalHeader = filename.read(24)
allPackets = filename.read()
lengthOfPackets = len(allPackets)

listOfPackets = []
listOfDNSPackets = []
listOfDomainNames = []

listOfHTTPPackets = []
getRequestMethodCount = 0
postRequestMethodCount = 0
headRequestMethodCount = 0
putRequestMethodCount = 0
deleteRequestMethodCount = 0
connectRequestMethodCount = 0
optionsRequestMethodCount = 0
traceRequestMethodCount = 0
patchRequestMethodCount = 0

endOfFile = False
startLoopIndexValue = 0 
while endOfFile == False:
    lengthOfPacketStartIndex = startLoopIndexValue+12 
    lengthOfPacketEndIndex = startLoopIndexValue+16
    if lengthOfPackets >= lengthOfPacketEndIndex:
        lengthOfPacket = int(reverse(allPackets[lengthOfPacketStartIndex:lengthOfPacketEndIndex].hex()),16)
        entirePacketStartIndex = startLoopIndexValue + 16
        entirePacketEndIndex = startLoopIndexValue + 16 + lengthOfPacket
        packetData = allPackets[entirePacketStartIndex:entirePacketEndIndex]
        listOfPackets.append(packetData)
        startLoopIndexValue = startLoopIndexValue + lengthOfPacket + 16
    else:
        endOfFile = True

for packet in listOfPackets:
    packetHex = packet.hex()
    protocolNumber = packetHex[46:48]
    protocolNumberInt = int(protocolNumber,16)
    sourcePort = int(packetHex[68:72],16)
    destinationPort = int(packetHex[72:76],16)
    # 11 = 17 in conversion which is udp protocol, 53 is dns
    if protocolNumberInt == 17 and (sourcePort == 53 or destinationPort == 53):
        listOfDNSPackets.append(packet)
    if protocolNumberInt == 6 and (destinationPort == 80):
        listOfHTTPPackets.append(packet)
    

for packet in listOfDNSPackets:
    #mac header
    macHeaderLength = 14
    macHeader = packet[:macHeaderLength]

    #ipv4 header
    ipv4HeaderVersionAndLength = str(packet[14:15].hex())
    ipv4HeaderVersion = ipv4HeaderVersionAndLength[0]
    ipv4HeaderLength = ipv4HeaderVersionAndLength[1]
    ipv4HeaderLengthInteger = (int(ipv4HeaderLength)*4)

    #udp header
    udpHeaderStartIndexValue = macHeaderLength+ipv4HeaderLengthInteger
    udpHeader = packet[udpHeaderStartIndexValue:udpHeaderStartIndexValue+8]
    sourcePort = udpHeader[0:2]
    destinationPort = udpHeader[2:4]
    length = int(udpHeader[4:6].hex(),16)
    checksum = udpHeader[6:8]
    udpHeaderLength = 8

    #dns 
    lengthOfDomainNameSystem = length-ipv4HeaderLengthInteger
    dnsStartIndexValue = udpHeaderStartIndexValue+udpHeaderLength
    domainNameSystem = packet[dnsStartIndexValue:]
    transactionID = domainNameSystem[:2]
    flags = domainNameSystem[2:4]
    numberOfQueries = int(domainNameSystem[4:6].hex(),16)
    numberOfAnswers = int(domainNameSystem[6:8].hex(),16)
    numberOfAuthority = int(domainNameSystem[8:10].hex(),16)
    numberOfAdditional = int(domainNameSystem[10:12].hex(),16)

    queryAndBeyond  = domainNameSystem[12:]
    domainName = extractDomainName(queryAndBeyond)

    if domainName not in listOfDomainNames:
        listOfDomainNames.append(domainName)


stringOfAllDomainNames=""
for index, domain in enumerate(listOfDomainNames):
    if(index == 0):
        stringOfAllDomainNames += domain
    elif(index == len(listOfDomainNames)-1):
        stringOfAllDomainNames=stringOfAllDomainNames+", and "+domain
    else:
        stringOfAllDomainNames=stringOfAllDomainNames+", "+domain


for packet in listOfHTTPPackets:
    #mac header
    macHeaderLength = 14
    macHeader = packet[:macHeaderLength]

    #ipv4 header
    ipv4HeaderVersionAndLength = str(packet[14:15].hex())
    ipv4HeaderVersion = ipv4HeaderVersionAndLength[0]
    ipv4HeaderLength = ipv4HeaderVersionAndLength[1]
    ipv4HeaderLengthInteger = int(ipv4HeaderLength)*4
    ipv4Header = packet[macHeaderLength:macHeaderLength+ipv4HeaderLengthInteger]

    #tcp header
    tcpHeaderAndAfter = packet[macHeaderLength+ipv4HeaderLengthInteger:]
    tcpHeaderlength = str(tcpHeaderAndAfter[12:13].hex())
    tcpHeaderlengthInt = int(tcpHeaderlength[0])*4

    #http
    httpHeader = packet[macHeaderLength+ipv4HeaderLengthInteger+tcpHeaderlengthInt:]
    requestMethod = httpHeader[:10].decode('ascii')
    if "GET" in requestMethod:
        getRequestMethodCount+=1
    elif "POST" in requestMethod:
        postRequestMethodCount+=1
    elif "HEAD" in requestMethod:
        headRequestMethodCount+=1
    elif "PUT" in requestMethod:
        putRequestMethodCount+=1
    elif "DELETE" in requestMethod:
        deleteRequestMethodCount+=1
    elif "CONNECT" in requestMethod:
        connectRequestMethodCount+=1 
    elif "OPTIONS" in requestMethod:
        optionsRequestMethodCount+=1 
    elif "TRACE" in requestMethod:
        traceRequestMethodCount+=1 
    elif "PATCH" in requestMethod:
        patchRequestMethodCount+=1 

domainNameMatches=[]
domainNamesToCheck=["p27dokhpz2n7nvgr.1jw2lx.top"]
for domainName in domainNamesToCheck:
    if domainName in listOfDomainNames:
        domainNameMatches.append(domainName)

stringOfAllDomainNamesFound=""
for index, domainName in enumerate(domainNameMatches):
    if(index == 0):
        stringOfAllDomainNamesFound += domainName
    elif(index == len(domainNameMatches)-1):
        stringOfAllDomainNamesFound=stringOfAllDomainNamesFound+", and "+domainName
    else:
        stringOfAllDomainNamesFound=stringOfAllDomainNamesFound+", "+domainName
if len(domainNameMatches)==0:
    stringOfAllDomainNamesFound="None"

print("Domain Name(s) Found in File From Array Provided: "+stringOfAllDomainNamesFound+"\n\nAll Domain Names Found in File: "+stringOfAllDomainNames+"\n\n"+"Count of GET Request Method Uses: "+str(getRequestMethodCount)+"\nCount of POST Request Method uses: "+str(postRequestMethodCount)+"\nCount of HEAD Request Method uses: "+str(headRequestMethodCount)+"\nCount of PUT Request Method uses: "+str(putRequestMethodCount)+"\nCount of DELETE Request Method uses: "+str(deleteRequestMethodCount)+"\nCount of CONNECT Request Method uses: "+str(connectRequestMethodCount)+"\nCount of OPTIONS Request Method uses: "+str(optionsRequestMethodCount)+"\nCount of TRACE Request Method uses: "+str(traceRequestMethodCount)+"\nCount of PATCH Request Method uses: "+str(patchRequestMethodCount))