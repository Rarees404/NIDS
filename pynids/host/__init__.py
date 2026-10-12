"""
Host inspection: the programs and devices behind the traffic.

* :mod:`.codesign`    — code-signature and location checks for executables
* :mod:`.connections` — live socket table (a better netstat / lsof)
* :mod:`.persistence` — launchd jobs that start programs automatically
* :mod:`.dossier`     — external IP facts (reverse DNS, RDAP, Shodan InternetDB)
* :mod:`.lan`         — local network device inventory and optional nmap scans
* :mod:`.inspector`   — joins all of the above for the API and Claude's tools
"""
