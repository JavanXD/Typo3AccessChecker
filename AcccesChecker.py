import requests
import urllib3
import progressbar
import csv
import re
# SSL warnings are diabled for this tool to avoid conflicts with self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AccessChecker:

    last404ErrorPageLength = 91314
    contentLengthErrorPage = 250

    def checkContentLength(self, len):
        if len*1.1 > self.contentLengthErrorPage and len*0.9 < self.contentLengthErrorPage:
            return(False)
        return(True)

    def determineInitial404Size(self, hostUrl):
        print("Determinig initial 404 error size...")
        hostUrl = hostUrl + "/thispagedoesnotexist"
        r = requests.get(hostUrl)
        if (r.status_code == 404):
            self.last404ErrorPageLength == len(r.content)
            print("404 Error Page size is " + str(len(r.content)))

    def checkAccess(self, host, checklistFileName, useragent, proxyDict, headers):
        linesList = [line.rstrip('\r\n')
                     for line in open(checklistFileName, 'r')]
        linesList = [hostString.replace('https://my.domain', host)
                     for hostString in linesList]
        #removing possible double slashes
        linesList = [re.sub(r"([^:]/)(/)+", r"\1", hostString) for hostString in linesList]

        self.determineInitial404Size(host)

        count = 0
        foundStatusCodes = {}
        reportDict = []
        pb = progressbar.ProgressBar(maxval=len(linesList), widgets=[
            progressbar.Bar('=', '0[', '] ' + str(len(linesList))), ' ', progressbar.AnimatedMarker()])
        pb.start()
        for url in linesList:
            scoring = False
            comment = ""
            count = count + 1
            pb.update(count)
            r = requests.get(url, headers=headers, proxies=proxyDict,
                             verify=False, allow_redirects=False)
            if r.status_code not in foundStatusCodes.keys():
                foundStatusCodes[r.status_code] = 0
            foundStatusCodes[r.status_code] = foundStatusCodes[r.status_code] + 1

            checkResult = {
                "url": r.url,
                "status-code": r.status_code,
                "content-length": len(r.content),
                "redirect": r.headers['Location'] if r.headers.get('Location', 0) else False,
                "score": scoring,
                "comment": comment
            }

            # relocating path
            if r.status_code == 301 and (r.url+"/") == r.headers.get('Location', 0):
                scoring = 0

            # redirect to landing page
            if r.status_code == 301 and (host+"/") == r.headers.get('Location', 0):
                scoring = 0

            # accessible content found
            if len(r.content) > 0 and self.checkContentLength(len(r.content)) and self.last404ErrorPageLength != len(r.content):
                scoring = 3
                comment = "Accessible content was found."
                self.last404ErrorPageLength = len(r.content)

            # Big Redirect detected
            if r.status_code == 301 and self.checkContentLength(len(r.content)) and len(r.content) != 0:
                scoring = 5
                comment = "A Big Redirect detected."

            # accessing php file directly
            if (r.status_code == 200 or r.status_code == 500) and len(r.content) == 0:
                scoring = 7
                comment = "It is possible to access a php file directly."

            # Successfull 403 Forbidden
            if r.status_code == 403 and self.checkContentLength(len(r.content)):
                scoring = 0

            # Successfull 404 File Not Found
            if r.status_code == 404 and self.checkContentLength(len(r.content)):
                scoring = 0

            if scoring:
                checkResult['score'] = scoring
                checkResult['comment'] = comment
                reportDict.append(checkResult)

            print(checkResult)

        print('Detected '+str(len(reportDict))+' of ' +
              str(count)+' responses as suspicious.')
        print("Status-code fast check overview:")
        for i in foundStatusCodes:
            print("", i, ":", foundStatusCodes[i])
        self.printCsvReport(host, reportDict)

    def printCsvReport(self, host, reportDict):
        # transforming hostname to a clean representation for filename
        cleanhostname = re.sub(r'[^A-Za-z0-9]', '', host)


        reportDict
        csv_file = "report-"+cleanhostname+".csv"
        csv_columns = ['url', 'status-code',
                       'content-length', 'redirect', 'score', 'comment']
        try:
            with open(csv_file, 'w') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                for data in reportDict:
                    writer.writerow(data)
            print("Report saved to "+csv_file)
        except IOError:
            print("I/O error - Could not write report file.")
