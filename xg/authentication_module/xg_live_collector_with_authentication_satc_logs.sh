#!/bin/sh
####################################
#
#xg basic log collector for SATC authentication issues
#
####################################

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
    kill -9 $program_14_pid

	exit	
}

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT 

#### what the script does ####
echo -en '\n'
echo "THIS SCRIPT WILL HELP YOU WITH SATC AUTHENTICATION ISSUES"
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
read -p "Whis is the user username you are going to test? " affected_username
read -p "Whis is tested user session id number (you can find it in XG gui -> current activities -> live users? " affected_username_session_id
read -p "Whis is the url you are going to test? " url
read -p "Which will be the tested destination port number? " dst_port
read -p "Whis is the destination ip you are going to test (nslookup domain)? " destination_ip
read -p "Whis is the terminal server (citrix) ip address ( cish -c system auth thin-client show) ? " terminal_server
read -p "Which is the sophos central remote access UID number? " sophos_central_UID
read -p "Which is the SATC version number you are using? " satc_version_number
read -p "If you are using the xg as web proxy which is the port number (3128 or 8080 etc...)? " proxy_port
read -p "Which is the browser name you are going to use for the test? " browser_name
read -p "Can you confirm the IPS feature is turned on (Server Protection > Policies > Threat Protection > Select the relevant policy > Settings > Runtime Protection)? " ips_feature_status
read -p "Which is the firewall rule id number that supposed to allow the traffic with Match known user enabled? " firewall_rule_id
read -p "Are you using other authentication methods at the same time with SATC and if yes which one? " other_authentication_methods
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

sleep 2
echo -en '\n'

xg_serial_number=$(nvram get  '#li.serial')
event_timestamp=$(date)
xg_incoming_interface=$(ip -o route get $terminal_server | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_outgoing_interface=$(ip -o route get $destination_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_interface_to_authentication_server=$(ip -o route get $authentication_server_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')

echo I am creating a folder that will contain all the logs we will collect named: ${case_number}_${xg_serial_number}
mkdir /tmp/${case_number}_${xg_serial_number}

echo I am creating a report file that will contained all the info about what we tested named: report_${case_number}_${xg_serial_number}
touch /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo -en '\n'

#### enable debug mode on modules ####
echo "I AM PUTTING THE FOLLOWING PROCESSES IN DEBUG MODE"
echo -en '\n'
echo IPS
service ips:debug -ds nosync     
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L7; done          
ips_module_status=$(service -S | grep ips)
echo the ips module status is:  $'\n'$ips_module_status

echo -en '\n'
echo ACCESS SERVER
service access_server:debug -ds nosync
access_server_status=$(service -S | grep access_server)
echo the access sever status is: $'\n'$access_server_status

echo -en '\n'
echo AWARRENHTTP
echo "mask=296283 # 0x4855B debug plus auth" > /sdisk/tmp/debug.cfg
service -ds nosync awarrenhttp:debug 
awarrenhttp_status=$(service -S | grep awarrenhttp)
echo the access sever status is: $'\n'$awarrenhttp_status

echo CSC
csc custom debug

#### log collection commands ####
echo -en '\n'
tcpdump -envvi $xg_incoming_interface host $terminal_server and port $dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${terminal_server}_destination_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_1_pid=$! 

tcpdump -envvi $xg_outgoing_interface host $terminal_server and port $dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_source_ip_${terminal_server}_destination_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_2_pid=$! 

tcpdump -envvi any host $terminal_server or host $destination_ip and port $dst_port -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_source_ip_${terminal_server}_destination_ip_${destination_ip}_destination_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_3_pid=$!

tcpdump -ni any host ${terminal_server} 'and (port 6060 or port 443 or port 80)' -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_terminal_server_ip_${terminal_server}_and_port_6060_80_443_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_4_pid=$!

tcpdump -ni any host ${terminal_server} and port ${proxy_port} -s0 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_terminal_server_ip_${terminal_server}_and_proxy_port_${proxy_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_5_pid=$!

tcpdump -envvi any host $terminal_server and port 53 -w /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_source_ip_${terminal_server}_destination_ip_${destination_ip}_destination_port_53_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_6_pid=$!

conntrack -s $terminal_server -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

drppkt host $terminal_server > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_by_terminal_server_ip_${terminal_server}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

drppkt host $destination_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_by_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

tail -f /log/ips.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_ips_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_10_pid=$!

tail -f /log/access_server.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_11_pid=$!

tail -f /log/awarrenhttp.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_12_pid=$!

tail -f /log/csc.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_13_pid=$!

tail -f /log/awarrenhttp_access.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_access_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_14_pid=$!

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
kill -9 $program_14_pid

#### remove debug mode from modules ####
for x in /tmp/snort[0-9]* ; do daq_control $x 18 -text D4L4 ; done       #to remove debug mode from ips module
service ips:debug -ds nosync                                             #to remove debug mode from ips module
service access_server:debug -ds nosync                                   #to remove debug mode from access_server module
rm /sdisk/tmp/debug.cfg                                                  #to remove debug mode from awarrenhttp module
service -ds nosync awarrenhttp:debug                                     #to remove debug mode from awarrenhttp module

echo -en '\n'

### info to add into the sap note ####
echo ---- SAP Case $case_number ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      issue description" = >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      error message" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- DATA ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      new configuration" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      serial number = $xg_serial_number" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      product  = $(cish -c system diagnostics show version-info | grep "Appliance Model" | awk {'print $3'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      firmware version  = $(cish -c system diagnostics show version-info | grep "Firmware Version" | awk {'print $4'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      access id  = $(psql -U nobody -d corporate -c "select * from tblsupportaccess" | grep "sophos.com")" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      customer phone number  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      sophos ftp credentials  = $ftp_username:$ftp_password" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      frequency of the issue  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      customer language = english" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      sophos central remote access UID number = ${sophos_central_UID}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      terminal server ip address provided by the customer = ${terminal_server}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          terminal server ip address retrieved via cli = $(cish -c system auth thin-client show | awk {'print $5'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      SATC version number = ${satc_version_number}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      proxy port number configure = ${proxy_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      browser tested = ${browser_name}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      firewall rule id that supposed to allow the traffic = ${firewall_rule_id}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      is customer using other authentication methods = ${other_authentication_methods}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      ips enabled status in Server Protection > Policies > Threat Protection > Select the relevant policy > Settings > Runtime Protection = ${ips_feature_status}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      timestamp = $event_timestamp" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested user username = $affected_username" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      testes user session id from xg gui -> current activities -> live users = ${affected_username_session_id}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested source ip = $terminal_server" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      the xg reaches the source ip using the incoming interface = $xg_incoming_interface" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination ip = $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested url = $url" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      the xg reaches the destination ip using the outcoming interface = $xg_outgoing_interface" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination port = $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- ASSESSMENT ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      What you think the real problem is" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- TROUBLESHOOTING STEPS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      replicated the issue collecting the logs" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check if there is the affected user registered in the XG database" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          sqlite_client 0 6061 0 "select * from tblliveuser" | grep ${affected_username}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
sqlite_client 0 6061 0 "select * from tblliveuser" | grep ${affected_username} >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      conntrack entries and ipset info regarding the users" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  ipset -L ${terminal_server}_cusers" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
ipset -L ${terminal_server}_cusers >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check routing order" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cish -c system route_precedence show >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check if firewall acceleration is enabled" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cish -c system firewall-acceleration show >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check if there is bypass rules configured" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cish -c show advanced-firewall >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COMMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_incoming_interface host $terminal_server and port $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_outgoing_interface host $terminal_server and port $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi any host $terminal_server and host $destination_ip and port $dst_port" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -ni any host ${terminal_server} 'and (port 6060 or port 443 or port 80)'" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -ni any host ${terminal_server} and port ${proxy_port}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi any host $terminal_server and port 53" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      conntrack filtered by $terminal_server" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $terminal_server" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/ips.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/access_server.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/awarrenhttp.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tail -f /log/csc.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/awarrenhttp.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/awarrenhttp_access.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COLLECTED LOG FILENAMES ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
search_dir=/tmp/${case_number}_${xg_serial_number}/
for file in $search_dir*;
do
  echo "    ${file##*/}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
done
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG ANALYSIS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check tcpdump filtered by terminal server ip ${terminal_server} and port 6060" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
tcpdump -ttttnnr /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_terminal_server_ip_${terminal_server}_and_port_6060_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check tcpfump filtered by port 6060" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -ttttnnr /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_any_interfaces_and_port_6060_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check dropped packet filtering by terminal server ip ${terminal_server}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_by_terminal_server_ip_${terminal_server}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      check dropped packet filtering by destination ip ${destination_ip}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_by_destination_ip_${destination_ip}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_* | grep $affected_username" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_* | grep $affected_username >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_filtered_by_source_ip_${terminal_server}_in_date_*" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_in_date_*.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_access_in_date_*" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_awarrenhttp_access_in_date_** >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- FOLLOWED KB ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: SATC with Server Protection  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000ga3ZQAQ/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: STAS conflicts with SATC  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008tyiQAA/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Configure Sophos Authentication for Thin Client (SATC)  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000sjj6QAA/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Thin Client (SATC) users cannot sign in  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008pZmQAI/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Set up SATC with Sophos Server Protection  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://docs.sophos.com/nsg/sophos-firewall/19.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Authentication/SophosAuthenticationForThinClient/SATC/AuthenticationSetupSATCUsingEndpointProtection/index.html" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  GES MER - Sophos Firewall - Authentication  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008hNLQAY/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Diagnostic Utility (SDU): Locate and download  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://support.sophos.com/support/s/article/KB-000033500?language=en_US" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Troubleshooting authentication" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://docs.sophos.com/nsg/sophos-firewall/19.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Authentication/TroubleshootingAuthentication/index.html" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Diagnostic Utility (SDU): Locate and download" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://support.sophos.com/support/s/article/KB-000033500?language=en_US" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

#### compress everything ####
tar -czvf /tmp/${case_number}_${xg_serial_number}_compressed.tar.gz /tmp/${case_number}_${xg_serial_number}/ > /dev/null 2>&1        #compress the folder to export

#### display the sap note ####
echo -en '\n'
echo -en '\n'
echo THIS IS THE SCRATCT SAP NOTE THAT HAS BEEN CREATED
echo -en '\n'
cat /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'

#### info to collect for stat issue ####
echo -en '\n'
echo -en '\n'
echo " CAN YOU PROVIDE THE SDU FROM THE ENDPOINT"
echo "    eventually customer can generate the SDY from the affected end-point via command line"
echo "      C:\Users\Username\AppData\Local\Temp\sdu"
echo "      x86: C:\Program Files\Sophos\Sophos Diagnostic Utility\sdugui.exe"
echo "      x64: C:\Program Files (x86)\Sophos\Sophos Diagnostic Utility\sdugui.exe"
echo "INSIDE THE SDU YOU SHOULD FIND THESE LOG FILES TO ATTACH IN THE CASE?"
echo "      {C:\ProgramData\Sophos\Sophos Network Threat Protection\Logs\SntpService.log}"
echo "      {C:\ProgramData\Sophos\Sophos Network Threat Protection\Logs\SophosNetFilter.log}"
echo "      REG-HKLM-Software-Sophos.xml"
echo "          and inside this file look for these lines"
echo "            {HKEY_LOCAL_MACHINE\SOFTWARE\Sophos\Sophos Network Threat Protection\}"
echo -en '\n'

#### other logs to collect ####
echo "IN CASE YOU WOULD LIKE TO COLLECT A LOG DUMP FROM THE XG YOU CAN USE THIS COMMAND"
echo "      tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /log/*.log"
echo -en '\n'
echo -en '\n'