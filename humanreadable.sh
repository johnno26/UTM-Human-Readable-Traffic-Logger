#!/bin/bash
#
# UTM Human Readable Traffic Logger
#
# Author:   NeedlesXL
# Report bugs to <bug-gzip@needles.nl>
#
# Change log:
# Version:  1.00 24-01-2016  Needles   Initial release
# Version:  1.01 01-03-2016  Needles   Resolved IP match issue
# Version:  1.02 03-03-2016  Needles   Added historic log view feature
# Version:  1.03 05-03-2016  Needles   Added GEOIP Country Block logging
# Version:  1.04 02-04-2016  Needles   Added Destination name resolution
# Version:  1.05 17-04-2016  Needles   Added Exclusion option for known/trusted traffic
# Version:  1.06 24-04-2016  Needles   Added DNS Caching option
# Version:  1.08 24-04-2016  Needles   Added daemon for permanent DNS Caching (optional)
#
# Dependencies:
# External files (auto generated in current dir if not present):
#          'excluded_firewall.txt'
#          'excluded_proxy.txt'
#          'excluded_application.txt'
#
# Run as root user (or with equal permissions)
#



##############################   Variable Definitions   ####################################
PATHTOSCRIPT="/root"
SCRIPTNAME="humanreadable.sh"
LOG_FILE1="/var/log/packetfilter.log"
LOG_FILE2="/var/log/http.log"
LOG_FILE3="/var/log/afc.log"
LOGLINE=""
LEADINGSTRING="###"
TRAILINGSTRING="^^^"
FORWARD_LOOKUP_FILE="/var/tmp/generated_forwardlookup.txt"
FORWARD_LOOKUP_FILE_DEDUP_TMP="/var/tmp/generated_forwardlookupdedup_tmp.txt"
GENERATED_EXCLUSIONS_FILE="/var/tmp/generated_hash_file.txt"
FORWARD_LOOKUP_FILE="/var/tmp/generated_forwardlookup.txt"
DNS_FILE="/var/tmp/generated_output_dns_entries.txt"
DEDUPLICATION_COUNTER=1000
BASE_COUNTER=0
LOG_LINES_TO_KEEP=10000
EXCLUDED_SOURCE_DESTINATIONS="excluded_firewall.txt"
EXCLUDED_URLS="excluded_proxy.txt"
EXCLUDED_APPS="excluded_application.txt"


################################ Start of Function Definitions #############################

function DEDUPLICATE ()
{
tail -n $LOG_LINES_TO_KEEP $FORWARD_LOOKUP_FILE > $FORWARD_LOOKUP_FILE_DEDUP_TMP
mv $FORWARD_LOOKUP_FILE_DEDUP_TMP $FORWARD_LOOKUP_FILE
awk '!a[$0]++' $FORWARD_LOOKUP_FILE > $FORWARD_LOOKUP_FILE_DEDUP_TMP
mv $FORWARD_LOOKUP_FILE_DEDUP_TMP $FORWARD_LOOKUP_FILE
}


function CACHINGCYCLE ()
{


############################   Dedeuplicate exported files   ###############################
DEDUPLICATE


#####################################   TCPDump Loop   #####################################
while read -r LOGLINE ; do
	BASE_COUNTER=$(expr $BASE_COUNTER + 1 )
	FQDN=$(echo $LOGLINE | grep "\+ \[1au\] A" | grep -o '1au] A.*' | awk -F" " '{print $3}' )
	if [[ $FQDN != "" ]] ; then
		while read -r LOGLINE ; do
			IP_ADDRESS=$(echo $LOGLINE | awk -F" " '{print $2}' )
			if [[ $IP_ADDRESS != "" ]] ; then
				echo $IP_ADDRESS $FQDN
				echo "s/###"$IP_ADDRESS"^^^/"$FQDN"/g" >> $FORWARD_LOOKUP_FILE
			fi
		if (( $BASE_COUNTER >= $DEDUPLICATION_COUNTER )) ; then
			DEDUPLICATE
			BASE_COUNTER=0
		fi
		done< <(exec nslookup $FQDN | grep "Address" | grep -v "127\.0\.0\.1")
	fi
done< <(exec tcpdump -n -l port 53)
}


function STARTDAEMON ()
{
$PATHTOSCRIPT/$SCRIPTNAME running 0<&- &>/dev/null &
}


function LOG_INTERPRETER()
{
                TIME_STAMP=""
                URL=""
                PROTO=""
                ENTRY_NAME=""
		HASH=""
		SRC_HOSTNAME=""
		DST_HOSTNAME=""
		PROXY_LOG_HIT=0
		AFC_LOG_HIT=0
                TIME_STAMP=$(echo $LOGLINE | awk -F " " '{print $1 }' )
                DROPACCEPT=$(echo $LOGLINE | grep -o 'action=.*' | awk -F\" '{print $2 }' )
                SCR_IP=$(echo $LOGLINE | grep -o 'srcip=.*' | awk -F\" '{print $2 }' )
                DST_IP=$(echo $LOGLINE | grep -o 'dstip=.*' | awk -F\" '{print $2 }' )

		if [[ $TRANSLATE_LOCAL_IP == 1 ]] ; then
                	TRUE_SRCIP=$SCR_IP
                	TRUE_DSTIP=$SCR_IP
			SCR_IP=$LEADINGSTRING$SCR_IP$TRAILINGSTRING
                	SRC_HOSTNAME=$(echo $SCR_IP | sed -f $DNS_FILE )
			if [[ $TRANSLATE_EXT_IP == 1 ]] && [[ $SRC_HOSTNAME == "$SCR_IP" ]] ; then
                        	SRC_HOSTNAME=$(echo $SCR_IP | sed -f $FORWARD_LOOKUP_FILE )
                	fi
			SRC_HOSTNAME=$(echo $SRC_HOSTNAME | sed -e 's/###//g' )
			SRC_HOSTNAME=$(echo $SRC_HOSTNAME | sed -e 's/\^\^\^//g' )
                	DST_IP=$LEADINGSTRING$DST_IP$TRAILINGSTRING
                	DST_HOSTNAME=$(echo $DST_IP | sed -f $DNS_FILE )
			if [[ $TRANSLATE_EXT_IP == 1 ]] && [[ $DST_HOSTNAME == "$DST_IP" ]] ; then
                		DST_HOSTNAME=$(echo $DST_IP | sed -f $FORWARD_LOOKUP_FILE )
			fi
                	DST_HOSTNAME=$(echo $DST_HOSTNAME | sed -e 's/###//g' )
                	DST_HOSTNAME=$(echo $DST_HOSTNAME | sed -e 's/\^\^\^//g' )

			MAXHOSTNAMELENGTH=24
                        USABLEHOSTNAMELENGTH=$(expr $MAXHOSTNAMELENGTH - 3)
			SRC_HOSTNAMELENGTH=${#SRC_HOSTNAME}
			if [[ $SRC_HOSTNAME != "$TRUE_SRCIP" ]] && [[ $SRC_HOSTNAMELENGTH -ge $MAXHOSTNAMELENGTH ]] ; then
				SRC_HOSTNAME=$(echo ...${SRC_HOSTNAME:(-$USABLEHOSTNAMELENGTH)})
			fi

			MAXHOSTNAMELENGTH=27
                        USABLEHOSTNAMELENGTH=$(expr $MAXHOSTNAMELENGTH - 3)
			DST_HOSTNAMELENGTH=${#DST_HOSTNAME}
                        if [[ $DST_HOSTNAME != "$TRUE_DSTIP" ]] && [[ $DST_HOSTNAMELENGTH -ge $MAXHOSTNAMELENGTH ]] ; then
                                DST_HOSTNAME=$(echo ...${DST_HOSTNAME:(-$USABLEHOSTNAMELENGTH)})
                        fi
                else
			SRC_HOSTNAME=$SCR_IP
			DST_HOSTNAME=$DST_IP
		fi

		APPL_NR=$(echo $LOGLINE | grep -o 'app=.*' | awk -F\" '{print $2 }' )
                PROTO=$(echo $LOGLINE | grep -o 'proto=.*' | awk -F\" '{print $2 }' )
                ENTRY_NAME=$(echo $LOGLINE | grep -o 'name=.*' | awk -F\( '{print $2 }' | awk -F\) '{print $1 }' )
                AFC_NAME=$(echo $LOGLINE | grep -o 'name=.*' | awk -F\" '{print $2 }' )
                APP_NAME=$(echo $LOGLINE | grep -o 'afcname=.*' | awk -F\= '{print $2 }' )
                DST_PORT=$(echo $LOGLINE | grep -o 'dstport=.*' | awk -F\" '{print $2 }' )
                URL=$(echo $LOGLINE | grep -o 'url=.*' | awk -F\" '{print substr($2,0,80) }' )
                FW_RULE=$(echo $LOGLINE | grep -o 'fwrule=.*' | awk -F\" '{print $2 }' )
                INITF=$(echo $LOGLINE | grep -o 'initf=.*' | awk -F\" '{print $2 }' )
                OUT_INTERFACE=$(echo $LOGLINE | grep -o 'outitf=.*' | awk -F\" '{print $2 }' )
                if [[ "$FW_RULE" == "600"* ]] ; then FW_RULE="ImplicitDeny" ; fi
                if [[ "$ENTRY_NAME" == "GEOIP" ]] ; then FW_RULE="CountryBlock" ; fi
                if [[ "$PROTO" == "1" ]] ; then PROTO="ICMP" ; DST_PORT="0" ; fi
                if [[ "$PROTO" == "2" ]] ; then PROTO="IGMP" ; DST_PORT="0" ; fi
                if [[ "$PROTO" == "6" ]] ; then PROTO="TCP" ; fi
                if [[ "$PROTO" == "17" ]] ; then PROTO="UDP" ; fi
                if [[ "$TIME_STAMP" != "" && "$TIME_STAMP" != "==>" ]] ; then

                        if [[ "$AFC_NAME" == "AFC Alert" ]] ; then
                                LOG_SOURCE="Application"
				TABLE_FORMAT="%-20s %-11s %-7s %-24s %-27s %-5s %-9s %-14s %-8s %-10s\n"

                                if [[ $USE_EXCLUSION_FILES == 1 ]] ; then
                                        while read -r LOGLINE ; do
                                                if [[ $APP_NAME =~ $LOGLINE ]] ; then
                                                        AFC_LOG_HIT=1
                                                fi
                                        done< <(exec cat $GENERATED_EXCLUSIONS_FILE )

                                        if [[ $AFC_LOG_HIT != 1 ]] ; then
						printf "$TABLE_FORMAT" $TIME_STAMP $LOG_SOURCE $DROPACCEPT $SRC_HOSTNAME $DST_HOSTNAME $PROTO $DST_PORT $FW_RULE $OUT_INTERFACE $APP_NAME
                                        fi
                                else
					printf "$TABLE_FORMAT" $TIME_STAMP $LOG_SOURCE $DROPACCEPT $SRC_HOSTNAME $DST_HOSTNAME $PROTO $DST_PORT $FW_RULE $OUT_INTERFACE $APP_NAME
                                fi
                        fi

                        if [[ "$PROTO" != "" && "$AFC_NAME" != "AFC Alert" ]] ; then
                                LOG_SOURCE="Firewall"
				TABLE_FORMAT="%-20s %-11s %-7s %-24s %-27s %-5s %-9s %-14s %-8s %-10s\n"
				if [[ $USE_EXCLUSION_FILES == 1 ]] ; then
					HASH=$LOG_SOURCE$DROPACCEPT$SRC_HOSTNAME$DST_HOSTNAME$PROTO$DST_PORT
       	         			HASH=$(echo $HASH | sed -e 's/^^^//g' | md5sum |  awk -F" " '{print $1 }' )
					if ! grep -q $HASH "$GENERATED_EXCLUSIONS_FILE" ; then
                                		printf "$TABLE_FORMAT" $TIME_STAMP $LOG_SOURCE $DROPACCEPT $SRC_HOSTNAME $DST_HOSTNAME $PROTO $DST_PORT $FW_RULE $INITF
					fi
				else
                                	printf "$TABLE_FORMAT" $TIME_STAMP $LOG_SOURCE $DROPACCEPT $SRC_HOSTNAME $DST_HOSTNAME $PROTO $DST_PORT $FW_RULE $INITF
				fi
                        fi
                        if [[ "$URL" != "" ]] ; then
                                LOG_SOURCE="Proxy"
				TABLE_FORMAT="%-20s %-11s %-7s %-24s %-27s\n"
				if [[ $USE_EXCLUSION_FILES == 1 ]] ; then
					while read -r LOGLINE ; do
						if [[ $URL =~ $LOGLINE ]] ; then
							PROXY_LOG_HIT=1
						fi
					done< <(exec cat $GENERATED_EXCLUSIONS_FILE )

            				if [[ $PROXY_LOG_HIT != 1 ]] ; then
                       	 			printf "$TABLE_FORMAT" $TIME_STAMP $LOG_SOURCE $DROPACCEPT $SRC_HOSTNAME $URL
                        		fi
				else
                       	 		printf "$TABLE_FORMAT" $TIME_STAMP $LOG_SOURCE $DROPACCEPT $SRC_HOSTNAME $URL
				fi
                        fi

                fi
                echo $printline | column -t
}


function printheading()
{
        echo ""
        echo "Human Readable UTM FW/Proxy Log Interpreter"
        echo ""
        echo "Timestamp            Log Source  Action  Source                   Destination                 Protocol/Port   FW Rule        Int      Appl"
        echo "==============================================================================================================================================="
}




##########################   Checking for script prerequisites   ###########################

if [[ ! -e /var/log/packetfilter.log ]]
then
	echo
	echo "$0 is only intended for use on a Sophos UTM installation."
	echo "now exiting..."
	echo
	exit
fi


TRUE_FULL_PATH=$(echo $(readlink -f $0)) &> /dev/null
CONFIGURED_FULL_PATH=$(echo $PATHTOSCRIPT/$SCRIPTNAME)
if [[ $TRUE_FULL_PATH != $CONFIGURED_FULL_PATH ]]
then
	echo
	echo "Incorrect script location..."
	echo
	echo "Update script variables 'PATHTOSCRIPT' and 'SCRIPTNAME'"
	echo "- or move script to default location: $CONFIGURED_FULL_PATH"
	echo
	echo "and try again..."
	echo
	exit
fi

> $GENERATED_EXCLUSIONS_FILE


if [[ ! -e $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS ]]
then
	echo "File '$EXCLUDED_SOURCE_DESTINATIONS' not present- creating file..."
	echo

	> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
	echo "Usage Example (select - copy - paste from logging results as can be seen below):   "  >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
	echo "									          	 "  >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
	echo "Firewall    accept  storage01_data           dome_cam_side_garden        UDP   5003"  >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
        echo "Firewall    accept  mediaportal              storage01_data              TCP   445"   >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
        echo "Firewall    accept  ypsilon                  beta_download_server        ICMP  0"     >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
	echo "									          	 "  >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
	echo "Enter your own exclusions below this line:                                         "  >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
	echo "-----------------------------------------------------------------------------------"  >> $PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS
fi

if [[ ! -e $PATHTOSCRIPT/$EXCLUDED_URLS ]]
then
        echo "File '$EXCLUDED_URLS' not present- creating file..."
        echo

        > $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "Usage Example (enter url's, domain names or parts of them - all will be excluded from logging results):   "  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "                                                                                   "  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "exampledomainname.com"  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "sub.exampledomainname.com"  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "sub.exampledomainname.com/stats/"  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "                                                                                   "  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "Enter your own exclusions below this line:                                         "  >> $PATHTOSCRIPT/$EXCLUDED_URLS
        echo "-----------------------------------------------------------------------------------"  >> $PATHTOSCRIPT/$EXCLUDED_URLS
fi

if [[ ! -e $PATHTOSCRIPT/$EXCLUDED_APPS ]]
then
        echo "File '$EXCLUDED_APPS' not present- creating file..."
        echo

        > $PATHTOSCRIPT/$EXCLUDED_APPS
        echo "Usage Example (enter upplication abbreviations known to the UTM, as can be seen in the log output):   "  >> $PATHTOSCRIPT/$EXCLUDED_APPS
        echo "                                                                                   "  >> $PATHTOSCRIPT/$EXCLUDED_APPS
        echo "WHATSAPP"  >> $PATHTOSCRIPT/$EXCLUDED_APPS
        echo "                                                                                   "  >> $PATHTOSCRIPT/$EXCLUDED_APPS
        echo "Enter your own exclusions below this line:                                         "  >> $PATHTOSCRIPT/$EXCLUDED_APPS
        echo "-----------------------------------------------------------------------------------"  >> $PATHTOSCRIPT/$EXCLUDED_APPS
fi

########################   Checking for running instances of daemon  #######################

CHECKFORRUNNING=$(ps -ef | grep $0 | grep running | tail -1)

if [[ $CHECKFORRUNNING == "" ]]
then
        STATUS="inactive"
else
        STATUS="active"
        PID=$(echo $CHECKFORRUNNING | awk -F" " {'print $2'})
fi

if [[ ! -e /etc/init.d/rc3.d/S99dns_caching ]]
then
	INSTALLED_DAEMON=0
else
	INSTALLED_DAEMON=1
fi

##############################   Handling input parameters   ###############################

for i in "$@"
do
	case $i in
		--help)
		MAIN_MODE="help"
		shift
	;;
    		-h=*|--extension=*)
		if [[ $MAIN_MODE == "realtime" ]] ; then
			MAIN_MODE=""
		else
    			TAIL_LENGTH="${i#*=}"
			MAIN_MODE="historical"
		fi
    		shift
    	;;
    		-r)
		if [[ $MAIN_MODE == "historical" ]] ; then
			MAIN_MODE=""
		else
			MAIN_MODE="realtime"
		fi
    		shift
    	;;
    		-x)
		SUB_MODE=1
		USE_EXCLUSION_FILES=1
    		shift
    	;;
                -t)
                SUB_MODE=1
                TRANSLATE_LOCAL_IP=1
                shift
        ;;
                -e)
                SUB_MODE=1
                TRANSLATE_EXT_IP=1
                TRANSLATE_LOCAL_IP=1
		if [[ $STATUS == "inactive" ]]
		then
			echo
			echo "-e option requires a running DNS Caching daemon..."
			echo "use --help for more info."
			echo
			exit
		fi
                shift
        ;;
    		start)
		MAIN_MODE="daemonmode"
        	if [[ $STATUS == "inactive" ]]
        	then
                	echo
         		echo "Starting..."
			STARTDAEMON
			sleep 1
        		echo "Done."
                	echo
        	else
                	echo
                	echo "Daemon is already running..."
                	echo
        	fi
        ;;
    		stop)
		MAIN_MODE="daemonmode"
        	if [[ $STATUS == "inactive" ]]
        	then
                	echo
                	echo "Daemon is not running..."
                	echo
        	else
                	echo
                	echo "Stopping daemon..."
                	kill -15 $PID
			sleep 1
                	kill -9 $PID &> /dev/null
                	echo "Done."
                	echo
        	fi
        ;;
    		restart|reload)
		MAIN_MODE="daemonmode"
        	if [[ $STATUS == "inactive" ]]
        	then
                	echo
                	echo "Daemon is not running..."
                	echo
        	else
                	echo
                	echo "Stopping daemon..."
                	kill -15 $PID
                	sleep 1
                	kill -9 $PID &> /dev/null
                	echo "Starting..."
			STARTDAEMON
                	sleep 1
                	echo "Done."
                	echo
        	fi
        ;;
    		status)
		MAIN_MODE="daemonmode"
		if [[ $STATUS == "inactive" ]]
		then
			echo
			echo "Daemon is not running..."
			echo
		else
			echo
			echo "Daemon is running (Process ID=$PID)"
			echo
        	fi
		if [[ $INSTALLED_DAEMON == 0 ]]
		then
			echo "Daemon configured to run at boot: NO"
			echo
		else
			echo "Daemon configured to run at boot: YES"
			echo
		fi
	;;
               install)
                MAIN_MODE="daemonmode"
		echo
		echo "Installing daemon..."
		ln -s $CONFIGURED_FULL_PATH /etc/init.d/rc3.d/S99dns_caching &> /dev/null
		sleep 1
		echo "Done."
		echo
        ;;
               uninstall)
                MAIN_MODE="daemonmode"
                echo
                echo "Removing daemon..."
                rm /etc/init.d/rc3.d/S99dns_caching &> /dev/null
                sleep 1
                echo "Done."
                echo
        ;;
    		running)
		CACHINGCYCLE
	;;
    		*)
		MAIN_MODE=""
    	;;
	esac
done



##############################   Start of Main controls   ##################################

if [[ $MAIN_MODE != "daemonmode" ]] ; then
	cat /var/sec/chroot-bind/zones/static/*.in-addr.arpa.zone | egrep "IN PTR|IN A" | tr -d '\"\n' | sed -e 's/\PTR/\n/g ; s/\.@//g ; s/\@//g' | awk -F" " '{print "s/###" $5 "^^^/" $1 "/g"}' | sed -e 's/\/\//\/ignore\/ignore/g' > $DNS_FILE
	echo -e "$(sed '1d' $DNS_FILE)\n" > $DNS_FILE

	while read -r LOGLINE ; do
        	echo $LOGLINE | sed -e 's/ //g' | md5sum |  awk -F" " '{print $1 }' >> $GENERATED_EXCLUSIONS_FILE
	done< <(exec cat "$PATHTOSCRIPT/$EXCLUDED_SOURCE_DESTINATIONS" | grep -vE '^(\s*$|#)' | sed -n '/---/,$p' | grep -v "\-\-\-")

	while read -r LOGLINE ; do
        	echo $LOGLINE >> $GENERATED_EXCLUSIONS_FILE
	done< <(exec cat "$PATHTOSCRIPT/$EXCLUDED_URLS" | grep -vE '^(\s*$|#)' | sed -n '/---/,$p' | grep -v "\-\-\-")

        while read -r LOGLINE ; do
                echo $LOGLINE >> $GENERATED_EXCLUSIONS_FILE
        done< <(exec cat "$PATHTOSCRIPT/$EXCLUDED_APPS" | grep -vE '^(\s*$|#)' | sed -n '/---/,$p' | grep -v "\-\-\-")
fi


if [[ $MAIN_MODE == "realtime" ]] ; then
	printheading

	while read -r LOGLINE ; do
		LOG_INTERPRETER
	done< <(exec tail -F "$LOG_FILE1" "$LOG_FILE2" "$LOG_FILE3" | afc-mark-filter.pl)
	exit
fi


if [[ $MAIN_MODE == "historical" ]] ; then
	printheading

	while read -r LOGLINE ; do
		LOG_INTERPRETER
	done< <(exec tail -n $TAIL_LENGTH "$LOG_FILE1" "$LOG_FILE2" "$LOG_FILE3" | grep -v afcd | afc-mark-filter.pl | sort -k1n)
	exit
fi


if [[ $MAIN_MODE == "help" ]] ; then
        echo ""
        echo "Human Readable UTM FW/Proxy Log Interpreter"
        echo ""
        echo -e "\e[4mUsage:\e[0m"
        echo "${0%*} -r <enter>                        (realtime logging)"
        echo "${0%*} -h=[number of log lines] <enter>  (historic logging)"
        echo ""
        echo -e "\e[4mOptional parameters:\e[0m"
        echo "        -x   |  Use exlusion files for filtering out known traffic"
        echo "               'excluded_source-destinations.txt'"
        echo "               'excluded_urls.txt'"
        echo "        -t   |  Use IP resolution for local devices (slower)"
        echo "               (requires configured DNS PTR records for your hosts - via UTM webinterface)"
        echo "        -e   |  Use IP resolution for external (internet) hosts/sites (slower)"
        echo "               (requires running DNS logging daemon - see below)"
        echo ""
        echo -e "\e[4mDaemon related parameters:\e[0m"
        echo "A running DNS caching daemon allows for name resolution for external IP addresses"
        echo "in addition to the local address resolution provided by the '-t' option."
        echo "   status    | Show the current status of the DNS Caching daemon"
        echo "   start     | Start the DNS Caching daemon"
        echo "   stop      | Stop the DNS Caching daemon"
        echo "   restart   | Restart the DNS Caching daemon (same as 'reload')"
        echo "   install   | Install the DNS Caching daemon to automatically start at system boot"
        echo "   uninstall | Uninstall the DNS Caching daemon to automatically start at system boot"
        echo ""
        echo -e "\e[4mExamples:\e[0m"
        echo "${0%*} -x -t -h=100"
        echo "${0%*} -r -x -t"
        echo "${0%*} status"
        echo ""
        echo "Report bugs to <bug-gzip@needles.nl>"
        echo ""
fi

if [[ $MAIN_MODE == "" ]] ; then
        echo "usage: $0 [-r] [-x] [-t] [-e] [-h= number]"
	echo "                          [start|stop|restart|reload|install|uninstall|status]"
	echo "                          --help (for more information)"
        echo ""
        echo "Report bugs to <bug-gzip@needles.nl>"
fi
