filename = open(r"C:\Users\Woody\Documents\Uni\Cyber Security\Coursework\CyberSecurity2021.pcap","rb")

globalHeader = filename.read(24)

magicNumber = globalHeader[:4].hex()
majorVersionNumber = globalHeader[4:6].hex()
minorVersionNumber = globalHeader[6:8].hex()
snapLength = globalHeader[16:20].hex()
dataLinkType = globalHeader[20:24].hex()

def reverse(variableName):
    variableName = bytearray.fromhex(variableName)
    variableName.reverse()
    variableName = str(variableName.hex())
    return "0x"+variableName

endianness = "Big Endianness"
if magicNumber != "a1b2c3d4":
    endianness = "Little Endianness"
    
    #reverse all
    magicNumber = "0x"+magicNumber

    majorVersionNumber = reverse(majorVersionNumber)
    minorVersionNumber = reverse(minorVersionNumber)
    snapLength = reverse(snapLength)
    dataLinkType = reverse(dataLinkType)

print("Length of Global Header = 24\nMagic Number = "+magicNumber+ "\nEndianness = "+endianness+"\nMajor Version Number = "+majorVersionNumber+"\nMinor Version Number = "+minorVersionNumber+"\nSnap Length = "+snapLength+"\nData Link Type = "+dataLinkType)