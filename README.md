# Typo3AccessChecker  [![License: GPL v3](https://img.shields.io/badge/License-GPLv2-blue.svg)](https://www.gnu.org/licenses/gpl-3.0) [![Twitter Follow](https://img.shields.io/twitter/follow/javanrasokat.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=javanrasokat)

Check if TYPO3 [security guidelines](https://docs.typo3.org/m/typo3/reference-coreapi/master/en-us/Security/GuidelinesAdministrators/Index.html) are followed. This tool scans if your typo3 instance is correctly secured by testing restrictions and permissions to important endpoints.

> With great astonishment we had to find out while testing our tool that many of the Typo3 instances on the Internet have obviously skipped the step from the installation manual to secure them.

## Installation
```
git clone https://github.com/JavanXD/Typo3AccessChecker.git
cd Typo3AccessChecker
python3 -m pip install requests progressbar
```

## Usage

Start a Scan of `https://typo3.org` with the default checklist:

```
python3 check_axxess.py https://typo3.org checklist.txt
```

Start a Scan of `https://typo3.org` and use a proxy (e.g. OWASP ZAP/Burp/Fiddler). The proxy function helps you during a manual check by displaying the exact answer you received.

```
python3 check_axxess.py https://typo3.org checklist.txt --proxy localhost:8080  --verify False
```

List of possible arguments:

```
python3 check_axxess.py -h
```

## Checklist
The checklist contains a default set of URLs that should be protected. You can expand the checklist by adding lines in the format `https://my.domain/`. Please do not replace `my.domain` with your real URL, this is done by the application using the host parameter that is passed on startup.


## Contribute
Feel free to open issues / pull requests if you want to contribute to this project.

* [Sebastian Schwegler](http://sebastianschwegler.de/)
* [Blogpost about Securing Typo3](https://javan.de/securing-typo3-cms-new-security-scanner/)
