filename = open(r"C:\Users\Woody\Documents\Uni\Cyber Security\Coursework\CyberSecurity2021.pcap","rb")

file = filename.read()

decodedFile = file.decode('latin-1')

import re
pattern = re.compile('https?://.*\.top?')
listMatches = pattern.findall(decodedFile)
listNonDuplicateMatches = []

for match in listMatches:
    if match not in listNonDuplicateMatches:
        listNonDuplicateMatches.append(match)

print("Susceptible Website: "+listNonDuplicateMatches[0])