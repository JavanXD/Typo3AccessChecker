#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#  Author: Javan Rasokat (javan.de)
#  Author: Sebastian Schwegler (sebastianschwegler.de)

import AccessChecker as checker
import argparse
import sys
import re
import os

if sys.version_info < (3, 0):
    sys.stdout.write("Requires Python 3.x\n")
    sys.exit(1)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "https://typo3.org"
    checklistFileName = sys.argv[2] if len(sys.argv) > 2 else './checklist.txt'

    parser = argparse.ArgumentParser("Typo3 Access Checker")
    parser.add_argument('host', nargs='+',
                        help='Typo3 instance to scan e.g. https://typo3.org')
    parser.add_argument('checklist', nargs='+',
                        help='Url list to check e.g. checklist.txt')
    parser.add_argument('--proxy', nargs='?',
                        help='Use a proxy like OWASP ZAP or Fiddler: localhost:8080', type=str)
    parser.add_argument('--useragent', nargs='?',
                        help='Define a User-Agent. By default: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0', type=str)
    parser.add_argument('--auth', nargs='+',
                        help='Define a value for Authorization header: "Basic dXNlcjpwYXNz"', type=str)
    parser.add_argument('--cookie', nargs='+',
                        help='Define a value for Cookie header: key=value', type=str)
    parser.add_argument('--verify', nargs='+',
                        choices=["True", "False"], help='Use SSL verifications, default: True', type=str)
    try:
        args = parser.parse_args()
    except Exception as ex:
        print("Error while parsing command line arguments.", ex)
    else:
        useragent = args.useragent if args.useragent else "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0"
        if args.proxy:
            # transform proxy srting with a RegEx that matches http, https and www
            proxy = args.proxy
            url = re.compile(r"https?://(www\.)?")
            proxy = re.sub(url, '', proxy)
            http_proxy = "http://"+proxy
            https_proxy = "https://"+proxy
            proxyDict = {
                "http": http_proxy,
                "https": https_proxy
            }
        else:
            proxyDict = {}

        headers = {
            'User-Agent': useragent
        }
        if args.auth:
            headers['Authorization'] = str(args.auth[0])
        if args.cookie:
            headers['Cookie'] = str(args.cookie[0])
        verify = True
        if args.verify and str(args.verify[0]) == "False":
            verify = False

        checker.AccessChecker(useragent, proxyDict, verify, headers).checkAccess(host, checklistFileName)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
