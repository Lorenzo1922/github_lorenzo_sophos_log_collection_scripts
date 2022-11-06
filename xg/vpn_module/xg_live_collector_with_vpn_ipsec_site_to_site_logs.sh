#!/bin/sh
####################################
#
#xg basic log collector for ipsec site to site vpn issues
#
####################################
#the esp packets are needed to understand why the vpn is not connecting

#### function to kill jobs with trap ####
cleanup()
{
	echo "cleanup"
    kill -9 $program_1_pid          
    kill -9 $program_2_pid          
    kill -9 $program_3_pid  
    kill -9 $program_4_pid 
    kill -9 $program_5_pid
    kill -9 $program_6_pid
    kill -9 $program_7_pid
    kill -9 $program_8_pid
    kill -9 $program_9_pid
    kill -9 $program_10_pid
    kill -9 $program_11_pid
    kill -9 $program_12_pid
    kill -9 $program_13_pid

	exit	
}

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT 

#### what the script does ####
echo -en '\n'
echo "this script will help you with ipsec site to site vpn issues"
echo "it can be used with the following issues:"
echo "      - ipsec site to site vpn not extablished"
echo "      - routing though the ipsec site to site vpn not working"
echo "      - ipsec remote access issues"
echo -en '\n'

#### script guide ####
echo -en '\n'
echo -en '\n'
echo "HOW TO USE THE SCRIPT:"
echo "      - reply to the initial questions"
echo "      - press enter if you do not know the answer of the questions"
echo "      - do not type special characters in the answers and do not delete caracters. If so, then press CTRL + C and start the script again"
echo "      - press CTRL + C if you would like to stop the log collection"
echo "      - do not close the terminal till the script finishes to save the files"
echo "      - if you need to run the script multiple times, add different answers to the 1st question like <case_number>_test_2"
echo -en '\n'
echo -en '\n'

#### variables ####
read -p "Which is the sophos case number? " case_number
echo -en '\n'

echo psql corporate nobody -x -c "select connectionid, connectionname from tblvpnconnection"
psql corporate nobody -x -c "select connectionid, connectionname from tblvpnconnection"                               
read -p "Which is the vpn name (check output of the previous command? " vpn_name
read -p "Whis is the source ip you are going to test? " source_ip
read -p "Whis is the destination ip you are going to test? " destination_ip
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

sleep 2
echo -en '\n'

xg_serial_number=$(nvram get  '#li.serial')
event_timestamp=$(date)
xg_incoming_interface=$(ip -o route get $source_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
remote_gateway_ip=$(psql corporate nobody -x -c "select remoteserver from tblvpnconnection where connectionname='$vpn_name'" | grep remoteserver | awk '{print $3}')
xg_outgoing_interface_to_remote_gateway=$(ip -o route get $remote_gateway_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_outgoing_interface_to_destination_ip=$(ip -o route get $destination_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_outgoing_interface_to_destination_ip_MTU=

echo I am creating a folder that will contain all the logs we will collect named: ${case_number}_${xg_serial_number}
mkdir /tmp/${case_number}_${xg_serial_number}

echo I am creating a report file that will contained all the info about what we tested named: report_${case_number}_${xg_serial_number}
touch /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

#psql corporate nobody -x -c "select * from tblvpnconnection" > /tmp/ipsec_debug/tblvpnconnection.db
psql corporate nobody -x -c "select * from tblvpnconnection where connectionname='Clone_testrbvpn'"
psql corporate nobody -x -c "select * from tblvpnpolicy" > /tmp/${case_number}_${xg_serial_number}/ipsec_debug/tblvpnpolicy.db

echo -en '\n'
echo -en '\n'

#### enable debug mode on modules ####
echo "I AM PUTTING THE FOLLOWING PROCESSES IN DEBUG MODE"
echo -en '\n'
echo STRONGSWAN
service strongswan:debug -ds nosync
strongswan_status=$(service -S | grep strongswan)
echo the access sever status is: $'\n'$strongswan_status

echo -en '\n'
echo ACCESS SERVER
service access_server:debug -ds nosync
access_server_status=$(service -S | grep access_server)
echo the access sever status is: $'\n'$access_server_status

echo -en '\n'
echo CSC
csc custom debug

sleep 2
echo -en '\n'

#### log collection commands ####
echo I AM STARTING COLLECTING THE LOGS
echo -en '\n'
tcpdump -eni any -c 10000 -s0 -w  -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_any_host_any_port_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_1_pid=$!

tcpdump -envvi $xg_outgoing_interface_to_remote_gateway host $remote_gateway_ip and esp -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_wan_interface_${xg_incoming_interface}_and_remote_gateway_ip_${remote_gateway_ip}_and_esp_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_2_pid=$!

tcpdump -envvi $xg_outgoing_interface_to_remote_gateway "port 500 or port 4500" and host $remote_gateway_ip -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_wan_interface_${xg_incoming_interface}_and_remote_gateway_ip_${remote_gateway_ip}_and_upd_port_500_4500_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_3_pid=$!

tcpdump -envvi $xg_outgoing_interface_to_remote_gateway -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_wan_interface_${xg_incoming_interface}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_4_pid=$!

tcpdump -envvi $xg_outgoing_interface_to_destination_ip host $destination_ip -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_interface_to_destination_ip_${xg_incoming_interface}_and_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_5_pid=$!

conntrack -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

drppkt host $remote_gateway_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtered_by_remote_gateway_ip_${remote_gateway_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

drppkt host $destination_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtered_by_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

tail -f /log/strongswan.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

tail -f /log/charon.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_charon_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_10_pid=$!

tail -f /log/applog.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_applog_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_11_pid=$!

tail -f /log/access_server.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_12_pid=$!

tail -f /log/csc.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_13_pid=$!

sleep $time_to_test             #wait enough time for someone to replicate the issue

#### kill running jobs in background ####
kill -9 $program_1_pid          
kill -9 $program_2_pid          
kill -9 $program_3_pid  
kill -9 $program_4_pid 
kill -9 $program_5_pid 
kill -9 $program_6_pid
kill -9 $program_7_pid
kill -9 $program_8_pid
kill -9 $program_9_pid
kill -9 $program_10_pid
kill -9 $program_11_pid
kill -9 $program_12_pid
kill -9 $program_13_pid

#### remove debug mode from modules ####
echo -en '\n'
echo REMOVE DEBUG ON PROCESSES

service strongswan:debug -ds nosync
strongswan_status=$(service -S | grep strongswan)
echo the access sever status is: $'\n'$strongswan_status

service access_server:debug -ds nosync
access_server_status=$(service -S | grep access_server)
echo the access sever status is: $'\n'$access_server_status

echo the csc service it not on debug
csc custom debug

### info to add into the sap note ####
echo -en '\n'
echo ---- SAP Case $case_number ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      issue description" = >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      error message" =  >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

echo ---- DATA ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      new configuration" =  >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      serial number = $xg_serial_number" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      product  = $(cish -c system diagnostics show version-info | grep "Appliance Model" | awk {'print $3'})" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "      firmware version  = $(cish -c system diagnostics show version-info | grep "Firmware Version" | awk {'print $4'})" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
#echo "      access id  = $(psql -U nobody -d corporate -c "select * from tblsupportaccess" | grep "sophos.com")" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "      customer phone number  =" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "      sophos ftp credentials  = $ftp_username:$ftp_password" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "      frequency of the issue  =" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      customer language = english" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      vpn $vpn_name connection details" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
psql corporate nobody -x -c "select connectionid,connectionname,policyid,connmode,conntype,authtype,localgateway,localid,localidtype,remoteserver,remoteid,remoteidtype from tblvpnconnection where connectionname='$vpn_name'"
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      timestamp = $event_timestamp" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tested source ip = $source_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "          the xg reaches the source ip using the incoming interface = $xg_incoming_interface" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tested destination ip = $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "          the xg reaches the destination ip using the outcoming interface = $xg_outgoing_interface_to_destination_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tested remote gateway = $remote_gateway_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "          the xg reaches the remote gateway ip using the outcoming interface = $xg_outgoing_interface_to_remote_gateway" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "       " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

echo ---- COMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tcpdump envvi any -C 100" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_outgoing_interface_to_remote_gateway host $remote_gateway_ip and esp" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface_to_remote_gateway "port 500 or port 4500" and host $remote_gateway_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface_to_remote_gateway" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface_to_destination_ip host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      conntrack" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $remote_gateway_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/strongswan.log" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/charon.log" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/applog.log" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/access_server.log" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/csc.log" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 
echo "       " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo ---- COLLECTED LOGS FILENAMES ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
search_dir=/tmp/${case_number}_${xg_serial_number}/
for file in $search_dir*;
do
  echo "    ${file##*/}" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
done
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

echo ---- LOG ANALYSIS ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_*.log | grep $vpn_name" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_*.log | grep $affected_username >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "    IPSEC STATUSALL" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
ipsec statusall >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "    IP XFRM STATE" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
ip xfrm state >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "    IP XFRM POLICY" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
ip xfrm policy >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "     cat /tmp/ipsec/connections/*" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/ipsec/connections/* >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "     cat /proc/net/xfrm_stat" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /proc/net/xfrm_stat >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface_to_remote_gateway host $remote_gateway_ip and esp" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_wan_interface_${xg_incoming_interface}_and_remote_gateway_ip_${remote_gateway_ip}_and_esp_in_date_* >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface_to_remote_gateway "port 500 or port 4500" and host $remote_gateway_ip" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_wan_interface_${xg_incoming_interface}_and_remote_gateway_ip_${remote_gateway_ip}_and_upd_port_500_4500_in_date_* >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "		this will mean the network objects on either end match exactly down to the correct subnets and even individual addresses"  >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "the received traffic selectors did not match">> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "Local and remote network did not match">> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "		this will mean there is IKE version mismatch with the configured policy of the firewalls"  >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "no IKE config found for" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "sending NO_PROPOSAL_CHOSEN" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "generating INFORMATIONAL_V1 request" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "parsed INFORMATIONAL_V1 request" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "received NO_PROPOSAL_CHOSEN error notify" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "		this will mean there’s a mismatched local and remote connection ID configured"  >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "no matching peer config found" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "ALERT: peer authentication failed" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "		this will mean Preshared Key mismatch for the configured IPsec connection"  >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "invalid HASH_V1 payload length, decryption failed" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "could not decrypt payloads" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "message parsing failed" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "AUTH_FAILED" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "received AUTHENTICATION_FAILED notify error" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "IKE_SA AUTHENTICATION_FAILED" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "but MAC mismatched" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_strongswan_in_date_* | grep "peer authentication failed" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo ---- FOLLOWED KB ---- >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "   Sophos XG Firewall: Troubleshooting site to site IPsec VPN issues  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      https://community.sophos.com/sophos-xg-firewall/f/recommended-reads/123740/sophos-xg-firewall-troubleshooting-site-to-site-ipsec-vpn-issues" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "   [Internal] GES MER - Sophos Firewall - VPN  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "      https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008xX7QAI/view" >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt

#### display the sap note ####
echo -en '\n'
echo -en '\n'
echo SCRATCH SAP NOTE
echo -en '\n'
cat /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt 

#### compress everything ####
tar -czvf /tmp/${case_number}_${xg_serial_number}_compressed.tar.gz /tmp/${case_number}_${xg_serial_number}/ > /dev/null 2>&1        #compress the folder to export

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'


#### other logs to collect ####
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  in case of routing issue, please collect also"
echo "      - routing table of the tested source"
echo "          open cmd, run route print, send us the output"
echo "  " >> /tmp/${case_number}_${xg_serial_number}/report_${case_number}_${xg_serial_number}.txt
echo "  in case of issue that involve the ipsec remote access, please collect also"
echo "      - logs from the sophos connect client"
echo "          open sophos connect client -> click on the 3 dots -> about -> generate technical support report"
echo "    "
echo " "
echo "  in case you would like to collect the log bundle, you can use this command"
echo "    tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /log/*.log"

