#!/bin/sh
####################################
#
#xg basic log collector for waf issues
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
echo "this script will help you with waf issues"
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
echo "please consider during the log collection we will need to restart the waf process that will cause an approx 10 seconds of web server disconnection for all"
read -p "Which is the sophos case number? " case_number
echo "please collect in the mean time the .har file (with google chrome pressing F12) or the wireshark traffic from the tested source"
read -p "Whis is the source ip you are going to test? " source_ip
read -p "Whis is the url you are going to test? " url
read -p "Which will be the tested destination port number open outside (is the same port you are using in the url)? " dst_port_outside
read -p "Which will be the tested destination port number open inside (local web server listening port)? " dst_port_inside
read -p "How you are resolving the url domain (do nslookup <afected domain)>? " destination_ip
read -p "Whis is the DNS ip address in use (is in the output of the nslookup command)? " dns_server_ip
read -p "Whis is the web server private ip you are going to test? " web_server_private_ip
read -p "Whis is the firewall rule id number that supposed to allow the traffic? " firewall_rule_id
read -p "Are you using an authentication mechanism (type yes or not)? " authentication_mechanism_if_enabled
read -p "If yes, which is the name of the authentication mechanism you are using? " authentication_mechanism_name
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds (higher than 15sec) you need to replicate the issue? " time_to_test

sleep 2
echo -en '\n'

xg_serial_number=$(nvram get  '#li.serial')
event_timestamp=$(date)
xg_incoming_interface=$(ip -o route get $source_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
xg_outgoing_interface=$(ip -o route get $web_server_private_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')

echo I am creating a folder that will contain all the logs we will collect named: ${case_number}_${xg_serial_number}
mkdir /tmp/${case_number}_${xg_serial_number}

echo I am creating a report file that will contained all the info about what we tested named: sap_note_${case_number}_${xg_serial_number}
touch /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo -en '\n'

#### enable debug mode on modules ####
echo "I AM PUTTING THE FOLLOWING PROCESSES IN DEBUG MODE"
echo -en '\n'
echo WAF MODULE 
mount -w -o remount / 
sed -i 's/LogLevel notice/LogLevel debug/g' /usr/apache/conf/httpd.conf
sed -i 's/#LoadModule pcap_module/LoadModule pcap_module/g' /usr/apache/conf/httpd.conf
sed -i 's/#PcapFileName/PcapFileName/g' /usr/apache/conf/httpd.conf
sed -i 's/#PcapNetworkProtocol ip/PcapNetworkProtocol ip/g' /usr/apache/conf/httpd.conf
service WAF:restart -ds nosync
echo -en '\n'
echo "THE WAF SERVICE IS RESTARTING"

echo -en '\n'
echo ACCESS SERVER
service access_server:debug -ds nosync
access_server_status=$(service -S | grep access_server)
echo the access sever status is: $'\n'$access_server_status

echo -en '\n'
echo CSC
csc custom debug

sleep 10
echo -en '\n'

#### log collection commands ####
echo I AM STARTING COLLECTING THE LOGS
echo -en '\n'
tcpdump -eni any -c 10000 -bw /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_any_host_any_port_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_1_pid=$!

tcpdump -envi $xg_incoming_interface host $source_ip and port $dst_port_outside -bw /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_incoming_interface_${xg_incoming_interface}_source_ip_${source_ip}_and_dst_port_${dst_port_outside}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_2_pid=$! 

tcpdump -envi $xg_outgoing_interface host $web_server_private_ip and port $dst_port_inside -bw /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_outgoing_interface_${xg_outgoing_interface}_webserver_private_ip_${web_server_private_ip}_and_dst_port_${dst_port_inside}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_3_pid=$! 

tcpdump -envi any host $source_ip and host $destination_ip -bw /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_capture_xg_any_interface_source_ip_${source_ip}_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap &
program_4_pid=$!

conntrack -s $source_ip -E -o timestamp | awk -F "[\t]" '{ gsub(/(\[)/,"",$1) ;gsub(/(\])/,"",$1); print strftime("%c",$1) " " $2 }' > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_filtered_by_source_ip_${source_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_5_pid=$!

drppkt host $destination_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtred_by_destination_ip_${destination_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

drppkt host $web_server_private_ip > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_drppkt_xg_filtred_by_destination_ip_${web_server_private_ip}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

tail -f /log/ips.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_ips_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_8_pid=$!

tail -f /log/reverseproxy.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_reverseproxy_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_9_pid=$!

tail -f /log/access_server.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_access_server_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_10_pid=$!

tail -f /log/csc.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_11_pid=$!

tail -f /log/postgres.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_postgres_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_12_pid=$!

tail -f /log/syslog.log > /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_syslog_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_13_pid=$!

sleep $time_to_test             #wait enough time for someone to replicate the issue

curl -i -k $url >> /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_curl_url_to_check_authentication_mechanism.log

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

cp /tmp/WAF.pcap /tmp/${case_number}_${xg_serial_number}/

#### remove debug mode from modules ####
echo -en '\n'
echo "I AM REMOVING THE FOLLOWING PROCESSES FROM DEBUG"

echo -en '\n'
echo WAF MODULE 
sed -i 's/LogLevel debug/LogLevel notice/g' /usr/apache/conf/httpd.conf
sed -i 's/LoadModule pcap_module/#LoadModule pcap_module/g' /usr/apache/conf/httpd.conf
sed -i 's/PcapFileName/#PcapFileName/g' /usr/apache/conf/httpd.conf
sed -i 's/PcapNetworkProtocol ip/#PcapNetworkProtocol ip/g' /usr/apache/conf/httpd.conf
mount -r -o remount /
service WAF:restart -ds nosync
echo -en '\n'
echo "THE WAF SERVICE IS RESTARTING"

echo -en '\n'
echo ACCESS_SERVER
service access_server:debug -ds nosync
access_server_status=$(service -S | grep access_server)
echo the access sever status is: $'\n'$access_server_status

### info to add into the sap note ####
echo -en '\n'
echo ---- SAP NOTE CASE $case_number ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      issue description" = >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      error message" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- DATA ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      new configuration" =  >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      serial number = $xg_serial_number" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      product  = $(cish -c system diagnostics show version-info | grep "Appliance Model" | awk {'print $3'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      firmware version  = $(cish -c system diagnostics show version-info | grep "Firmware Version" | awk {'print $4'})" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      access id | how long it last | when it was enabled = $(psql -U nobody -d corporate -c "select * from tblsupportaccess" | grep "sophos.com")" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      customer phone number  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      sophos ftp credentials  = $ftp_username:$ftp_password" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      frequency of the issue  =" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      customer language = english" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      firewall rule that supposed to allow the traffic = id $firewall_rule_id" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      authentication mechanism enabled  = $authentication_mechanism_if_enabled" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          authentication mechanism name  = $authentication_mechanism_name" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      timestamp = $event_timestamp" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested source ip = $source_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          the xg reaches the source ip using the incoming interface = $xg_incoming_interface" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tested destination ip = $web_server_private_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          the xg reaches the destination ip using the outcoming interface = $xg_outgoing_interface" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "          tested url = $url" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      used DNS server ip = $dns_server_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "       " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- ASSESSMENT ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      What you think the real problem is" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- TROUBLESHOOTING STEPS ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      replicated the issue collecting the logs" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ----  POA  ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      Plan of action with next steps clearly stated on the ticket" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- COMMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump envvi any -C 100" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 
echo "      tcpdump -envvi $xg_incoming_interface host $source_ip and port $dst_port_outside" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi $xg_outgoing_interface host $web_server_private_ip and port $dst_port_inside" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tcpdump -envvi any host $source_ip and host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      conntrack -s $source_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      drppkt host $web_server_private_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/ips.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/reverseproxy.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/access_server.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /tmp/WAF.pcap" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/csc.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/postgres.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      tail -f /log/syslog.log" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "      curl -i -k $url" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
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
echo "  check conntrack filtering by source ip ${source_ip} and web server public port ${dst_port_outside}" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_conntrack_xg_filtered_by_source_ip_${source_ip}_in_date_* >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check reverseproxy.log filtering by source ip $source_ip and id of the rule" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_reverseproxy_in_date_* | grep $source_ip | grep security2:error | grep mypublishedurl >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check reverseproxy.log filtering by source ip $source_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_reverseproxy_in_date_* | grep $source_ip >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check WAF.pcap filtering by source ip $source_ip and destination ip $destination_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -ttttnnr /tmp/${case_number}_${xg_serial_number}/WAF.pcap | grep "${source_ip}\|${destination_ip}" | head -n40 >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -ttttnnr /tmp/${case_number}_${xg_serial_number}/WAF.pcap | grep "${source_ip}\|${destination_ip}" | grep -B1 RST >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r WAF.pcap | grep -A5 -B5  ${source_ip}  | head -n20 >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r WAF.pcap | grep -A5 -B5  ${source_ip}  | grep -B2 SYN >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
tcpdump -qns 0 -A -r WAF.pcap | grep -A2 -B2 ${source_ip}  | grep -B1 RST >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
#tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/WAF.pcap | grep $source_ip >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
#echo "  check WAF.pcap filtering by web server priate ip $web_server_private_ip" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
#tcpdump -qns 0 -A -r /tmp/${case_number}_${xg_serial_number}/WAF.pcap | grep $web_server_private_ip >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check csc.log filtering by word fail or error" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_csc_in_date_* | grep 'fail\|error' >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check postgress.log filtering by word fail or error" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_postgres_in_date_* | grep 'fail\|error' >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  check syslog.log filtering by word fail or error" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
cat /tmp/${case_number}_${xg_serial_number}/${xg_serial_number}_syslog_in_date_* | grep 'fail\|error' >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

echo ---- FOLLOWED KB ---- >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  [Internal] GES MER - Sophos Firewall - WAF  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008xXqQAI/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  [Internal] Sophos XG Firewall: Capture traffic using the WAF  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008oMUQAY/view" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: WAF troubleshooting  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://support.sophos.com/support/s/article/KB-000036242?language=en_US" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: WAF configuration guides  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://support.sophos.com/support/s/article/KB-000036712?language=en_US" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  Sophos Firewall: Bypass individual WAF rules  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008o2UQAQ/view?0.source=aloha" >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt
echo "  " >> /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt

#### display the sap note ####
echo -en '\n'
echo -en '\n'
echo SCRATCH SAP NOTE
echo -en '\n'
cat /tmp/${case_number}_${xg_serial_number}/sap_note_${case_number}_${xg_serial_number}.txt 

#### compress everything ####
tar -czvf /tmp/${case_number}_${xg_serial_number}_compressed.tar.gz /tmp/${case_number}_${xg_serial_number}/ > /dev/null 2>&1        #compress the folder to export

#### sends logs to sophos ftp server ####
echo "RUN THE FOLLOWING COMMANDS TO SEND THE LOGS TO SOPHOS FTP SERVER"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_${xg_serial_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'

#### other logs to collect ####
echo "in case you would like to collect a log dump you can use this command"
echo "tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /log/*.log"
echo -en '\n'
echo -en '\n'

