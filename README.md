# UTM-Human-Readable-Traffic-Logger
Human Readable Log Traffic Interpreter for Astaro/Sophos UTM

Author:   NeedlesXL
Report bugs to <bug-gzip@needles.nl>

Change log:
Version:  1.00 24-01-2016  Needles   Initial release
Version:  1.01 01-03-2016  Needles   Resolved IP match issue
Version:  1.02 03-03-2016  Needles   Added historic log view feature
Version:  1.03 05-03-2016  Needles   Added GEOIP Country Block logging
Version:  1.04 02-04-2016  Needles   Added Destination name resolution
Version:  1.05 17-04-2016  Needles   Added Exclusion option for known/trusted traffic
Version:  1.06 24-04-2016  Needles   Added DNS Caching option
Version:  1.08 24-04-2016  Needles   Added daemon for permanent DNS Caching (optional)

Dependencies:
External files (auto generated in current dir if not present):
         'excluded_firewall.txt'
         'excluded_proxy.txt'
         'excluded_application.txt'

Run as root user (or with equal permissions)


Usage:
./humanreadable.sh -r <enter>                        (realtime logging)
./humanreadable.sh -h=[number of log lines] <enter>  (historic logging)

Optional parameters:
        -x   |  Use exlusion files for filtering out known traffic
               'excluded_source-destinations.txt'
               'excluded_urls.txt'
        -t   |  Use IP resolution for local devices (slower)
               (requires configured DNS PTR records for your hosts - via UTM webinterface)
        -e   |  Use IP resolution for external (internet) hosts/sites (slower)
               (requires running DNS logging daemon - see below)

Daemon related parameters:
A running DNS caching daemon allows for name resolution for external IP addresses
in addition to the local address resolution provided by the '-t' option.
   status    | Show the current status of the DNS Caching daemon
   start     | Start the DNS Caching daemon
   stop      | Stop the DNS Caching daemon
   restart   | Restart the DNS Caching daemon (same as 'reload')
   install   | Install the DNS Caching daemon to automatically start at system boot
   uninstall | Uninstall the DNS Caching daemon to automatically start at system boot

Examples:
./humanreadable.sh -x -t -h=100
./humanreadable.sh -r -x -t
./humanreadable.sh status

Report bugs to <bug-gzip@needles.nl>


