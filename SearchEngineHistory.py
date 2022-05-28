filename = open(r"C:\Users\Woody\Documents\Uni\Cyber Security\Coursework\CyberSecurity2021.pcap","rb")
file = filename.read()
decodedFile = file.decode("iso-8859-1")

#TASK 4A

listSearchEngines = ["www.bing.", "www.ask.", "www.yahoo.",
                 "www.ask.", "www.baidu.", "www.duckduckgo.",
                 "www.wolframalpha.", "www.boardreader.", "www.startpage.", 
                 "www.ecosia.", "www.qwant.", "www.searchencrypt.", 
                 "www.searx.","www.yandex.","www.gibiru.","www.disconnectsearch.",
                 "www.yippy.","www.swisscows.","www.lukol.","www.metager."]

listSearchEnginesUsed = []
for searchEngine in listSearchEngines:
    if searchEngine+"com" in decodedFile:
        listSearchEnginesUsed.append(searchEngine+"com")
    elif searchEngine+"co.uk" in decodedFile:
        listSearchEnginesUsed.append(searchEngine+"co.uk")

stringSearchEngines = ""
lengthSearchEnginedUsed = len(listSearchEnginesUsed)
if lengthSearchEnginedUsed == 0:
    print('No Search Engines Used From List Specified')
elif lengthSearchEnginedUsed == 1:
    print('Search Engine Used: '+listSearchEnginesUsed[0])
else:
    for index, searchEngine in enumerate(listSearchEnginesUsed):
        if index == 0:
            stringSearchEngines = stringSearchEngines+searchEngine
        else:
            stringSearchEngines = stringSearchEngines+", "+searchEngine


#TASK 4B

import re
pattern = re.compile('bing.com/search?.*')
listPaths = pattern.findall(decodedFile)

condensedPaths = []
for path in listPaths:
    condensedPath = str(path).split('&',1)
    condensedPaths.append(condensedPath[0])

uniquePaths = list(set(condensedPaths))
stringUniquePath = str(uniquePaths[0])

seperatedPath = stringUniquePath.split('q=',1)
keywords = seperatedPath[1]
individualKeywords = keywords.split("+")

stringOfAllKeywords=""
for index, keyword in enumerate(individualKeywords):
    if(index == 0):
        stringOfAllKeywords += keyword
    elif(index == len(individualKeywords)):
        stringOfAllKeywords=stringOfAllKeywords+", and "+keyword
    else:
        stringOfAllKeywords=stringOfAllKeywords+", "+keyword


#TASK 4C & 4D

check = "url="
urls = []
index = 0
for i in file:
    if index <= len(file):
        newFile = file[index:index+50]
        newFileDecoded = newFile.decode('iso-8859-1')

        if check in newFileDecoded:
            fileExtract = file[index-100:index+300]
            fileExtractDecoded = fileExtract.decode('iso-8859-1')
            if("Referer: http://www.bing.com/search?q=home+improvement+remodeling+your+kitchen" in fileExtractDecoded):
                import re
                pattern = re.compile('url=(.*html?)')
                urls = pattern.findall(fileExtractDecoded)

        index = index+50

import urllib.parse
strUrl = str(urls[0])
specialsRemovedUrl = urllib.parse.unquote(strUrl)

print(stringSearchEngines+'Keywords Used: '+stringOfAllKeywords+'\nWebsite Recommended by Search Engine and Accessed by User: '+specialsRemovedUrl)