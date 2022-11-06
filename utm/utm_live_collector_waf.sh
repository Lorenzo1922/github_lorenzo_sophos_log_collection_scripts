#!/bin/sh
####################################
#
#utm log collector for  waf issues 
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

	exit	
}

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT    

#### script guide ####
echo -en '\n'
echo -en '\n'
echo "THIS SCRIPT WILL HELP YOU COLLECTING THE WAF LOGS"
echo "HOW TO USE THE SCRIPT:"
echo "      - reply to the initial questions"
echo "      - press enter if you do not know the answer of the questions"
echo "      - do not type special characters in the answers and do not delete caracters. If so, then press CTRL + C and start the script again"
echo "      - press CTRL + C if you would like to stop the log collection"
echo "      - do not close the terminal till the scrip finishes to save the files"
echo "      - if you need to run the script multiple times, add different answers to the 1st question like <case_number>_test_2"
echo "      - the script will restart the reverseproxy service that will cause a connection drop of approx 5 sec to all users using WAF"
echo -en '\n'
echo -en '\n'

#### variables ####
read -p "Which is the sophos case number? " case_number
read -p "Whis is the source ip you are going to test? " source_ip
read -p "Can you provide a description of the tested source like android phone, apple iphone, windows pc ect...? " source_type
read -p "Which is the destination url you are going to test? " url
read -p "Whis is the destination ip you are going to test (public ip you can obtain with nslookup <domain>)? " destination_ip
read -p "Which will be the tested destination port number open outside (is the same port you are using in the url)? " dst_port_outside
read -p "Which will be the tested destination port number open inside (local web server listening port)? " dst_port_inside
read -p "Which is the DNS server ip you are using (you can find it into the nslookup output)? " dns_server_ip
read -p "Which is the web server private ip address? " web_server_private_ip
read -p "If you are using an authentication mechanism on the web server, which one is it? " authentication_mechanism_name
read -p "Which is the firewall rule that supposed to allow the traffic? " firewall_rule_id
read -p "Which is the sophos ftp username? " ftp_username
read -p "Which is the sophos ftp password? " ftp_password 
read -p "How many seconds you need to replicate the issue? " time_to_test

sleep 2
echo -en '\n'

#utm_serial_number=$(nvram get  '#li.serial')
event_timestamp=$(date)
utm_incoming_interface=$(ip -o route get $source_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')
utm_outgoing_interface=$(ip -o route get $web_server_private_ip | perl -nle 'if ( /dev\s+(\S+)/ ) {print $1}')

echo I am creating a folder that will contain all the logs we will collect named: ${case_number}
mkdir /tmp/${case_number}

echo I am creating a report file that will contained all the info about what we tested named: sap_note_${case_number}_${xg_serial_number}
touch /tmp/${case_number}/sap_note_${case_number}.txt

echo -en '\n'

#### enable debug mode on modules ####
echo "I AM PUTTING THE REVERSEPROXY MODULE IN DEBUG MODE"
          
#enable debug on reverse proxy module
sed -i 's/LogLevel notice/LogLevel debug/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
sed -i 's/#LoadModule pcap_module/LoadModule pcap_module/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
sed -i 's/#PcapFileName/PcapFileName/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
sed -i 's/#PcapNetworkProtocol ip/PcapNetworkProtocol ip/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
/var/mdw/scripts/reverseproxy restart

sleep 10

#### log collection commands ####
echo I AM STARTING COLLECTING THE LOGS
tcpdump -envvi $utm_incoming_interface host $source_ip and port $dst_port_outside -s0 -w /tmp/${case_number}/capture_utm_incoming_interface_${utm_incoming_interface}_and_source_ip_${source_ip}_and_dst_port_${dst_port_outside}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_1_pid=$! 

tcpdump -envvi $utm_outgoing_interface host $source_ip and port $dst_port_inside -s0 -w /tmp/${case_number}/capture_utm_outgoing_interface_${utm_outgoing_interface}_and_source_ip_${source_ip}_and_dst_port_${dst_port_inside}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_2_pid=$! 

tcpdump -envvi any -c 10000 host $source_ip and host $destination_ip and port $dst_port -s0 -w /tmp/${case_number}/capture_utm_any_interface_and_source_ip_${source_ip}_and_dst_ip_${destination_ip}_and_dst_port_${dst_port}_in_date_$(date +"%Y_%m_%d_%I_%M_%p").pcap -b &
program_3_pid=$!

tail -f /var/log/packetfilter.log > /tmp/${case_number}/packetfilter_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_4_pid=$!

tail -f /var/log/httpd.log > /tmp/${case_number}/httpd_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_5_pid=$!

tail -f /var/log/http.log > /tmp/${case_number}/http_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_6_pid=$!

tail -f /var/log/reverseproxy.log > /tmp/${case_number}/reverseproxy_in_date_$(date +"%Y_%m_%d_%I_%M_%p").log &
program_7_pid=$!

#### exit when customer finished to replicate the issue early ####
echo "PRESS CTRL + C IF YOU WANT TO STOP THE SCRIPT"
trap cleanup SIGINT               

sleep $time_to_test             #wait enough time for someone to replicate the issue

cp /var/storage/chroot-reverseproxy/tmp/WAF.pcap /tmp/${case_number}/

#### kill running jobs in background ####
kill -9 $program_1_pid          
kill -9 $program_2_pid          
kill -9 $program_3_pid  
kill -9 $program_4_pid 
kill -9 $program_5_pid
kill -9 $program_6_pid
kill -9 $program_7_pid

#### remove debug mode from modules ####
echo -en '\n'
echo "I AM REMOVING THE DEBUG MODE ON REVERSEPROXY PROCESS"
sed -i 's/LogLevel debug/LogLevel notice/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
sed -i 's/LoadModule pcap_module/#LoadModule pcap_module/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
sed -i 's/PcapFileName/#PcapFileName/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
sed -i 's/PcapNetworkProtocol ip/#PcapNetworkProtocol ip/g' /var/chroot-reverseproxy/usr/apache/conf/httpd.conf
/var/mdw/scripts/reverseproxy restart

### info to add into the sap note ####
echo -en '\n'
echo ---- SAP NOTE CASE $case_number ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      issue description" = >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      error message" =  >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- DATA ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      new configuration" =  >> /tmp/${case_number}/sap_note_${case_number}.txt
#echo "      serial number = $utm_serial_number" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      product  = $(version | grep Hardware | awk {'print $3'})" >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "      firmware version  = $(version | grep software | awk {'print $4'})" >> /tmp/${case_number}/sap_note_${case_number}.txt 
#echo "      access id | how long it last | when it was enabled = $(psql -U nobody -d corporate -c "select * from tblsupportaccess" | grep "sophos.com")" >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "      customer phone number  =" >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "      sophos ftp credentials  = $ftp_username:$ftp_password" >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "      frequency of the issue  =" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      customer language = english" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      firewall rule that supposed to allow the traffic = id $firewall_rule_id" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      authentication mechanism name  = $authentication_mechanism_name" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- LOG COLLECTION EVENT DETAILS ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      timestamp = $event_timestamp" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tested source ip = $source_ip" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      source description = $source_type" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "          the xg reaches the source ip using the incoming interface = $utm_incoming_interface" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tested destination ip = $web_server_private_ip" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "          the xg reaches the destination ip using the outcoming interface = $utm_outgoing_interface" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "          tested url = $url" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tested destination ip = $destination_ip"
echo "      tcp/udp port utm has open outside to receive the request = $dst_port_outside" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tcp/udp port utm has open outside to send the request to the private web server ip = $dst_port_inside" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      used DNS server ip = $dns_server_ip" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "       " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- ASSESSMENT ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      What you think the real problem is" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- TROUBLESHOOTING STEPS ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      replicated the issue collecting the logs" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      collect the httpd.conf file" >> /tmp/${case_number}/sap_note_${case_number}.txt
cp /var/storage/chroot-reverseproxy/usr/apache/conf/httpd.conf 
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ----  POA  ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      Plan of action with next steps clearly stated on the ticket" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- COMMANDS USED DURING THE LOG COLLECTION ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tcpdump -envvi $utm_incoming_interface host $source_ip and port $dst_port_outside" >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "      tcpdump -envvi $utm_outgoing_interface host $source_ip and port $dst_port_inside" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tcpdump -envvi any -c 10000 host $source_ip and host $destination_ip and port $dst_port" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tail -f /var/log/packetfilter.log" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tail -f /var/log/httpd.log" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tail -f /var/log/http.log" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tail -f /var/log/reverseproxy.log" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tail -f /log/ips.log" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      tail -f /log/reverseproxy.log" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "      cp /var/storage/chroot-reverseproxy/tmp/WAF.pcap" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "       " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- COLLECTED LOG FILENAMES ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
search_dir=/tmp/${case_number}_${xg_serial_number}/
for file in $search_dir*;
do
  echo "    ${file##*/}" >> /tmp/${case_number}/sap_note_${case_number}.txt
done
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- LOG ANALYSIS ---- >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  check reverseproxy.log filtered by tested source ip ${source_ip} and word ModSecurity" >> /tmp/${case_number}/sap_note_${case_number}.txt
cat /tmp/${case_number}/reverseproxy_in_date_* | grep ${source_ip} | grep ModSecurity >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  check reverseproxy.log filtered by authentication impossible for unsupported authentication methods" >> /tmp/${case_number}/sap_note_${case_number}.txt
cat /tmp/${case_number}/reverseproxy_in_date_* | grep "authentication impossible" >> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  check reverseproxy.log filtered by tested source ip ${source_ip} and word statuscode and 4" >> /tmp/${case_number}/sap_note_${case_number}.txt
cat /tmp/${case_number}/reverseproxy_in_date_* | grep ${source_ip} | grep statuscode= | grep 4>> /tmp/${case_number}/sap_note_${case_number}.txt 
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

echo ---- FOLLOWED KB ---- >> /tmp/${case_number}/sap_note_${case_number}.txt >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  [Internal] Sophos Firewall and Sophos UTM: WAF blocking email attachments greater than 1 MB on Microsoft Exchange 2016  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000gc5wQAA/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  [Internal] Sophos UTM: Capture traffic using WAF  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008oHoQAI/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos Firewall & Sophos UTM: Enable WAF Debug Logs  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008p7uQAA/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos UTM: WAF filter rules  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008mbIQAQ/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos UTM: WAF not working - [proxy_http:error] read less bytes of request body than expected  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000T485QAC/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos UTM: Bypass individual WAF rules  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008tuCQAQ/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos UTM: Create a site path route for WAF  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z000000gc6zQAA/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos UTM: Web Application Firewall (WAF): supported authentication method  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000004fUSQAY/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  Sophos UTM: Configure the WAF profile  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008oINQAY/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  [Internal] Sophos UTM: Fix WAF showing garbled content  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008ofqQAA/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  [Internal] Sophos UTM: Turn off the weak cipher in WAF  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "    https://sophos.lightning.force.com/lightning/r/Knowledge__kav/ka03Z0000008ogUQAQ/view" >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt
echo "  " >> /tmp/${case_number}/sap_note_${case_number}.txt

#### compress all logs collected ####
tar -czvf /tmp/${case_number}_compressed.tar.gz /tmp/${case_number}/ > /dev/null 2>&1        #compress the folder with the logs collected

#### display the sap note ####
echo -en '\n'
echo -en '\n'
echo SCRATCH SAP NOTE
echo -en '\n'
cat /tmp/${case_number}/sap_note_${case_number}.txt 

#### other logs to collect ####
echo "in case you would like to send all the logs collected now into the sophos ftp server"
echo "      curl --ftp-ssl ftp://ftp.sophos.com:990 -u ${ftp_username}:${ftp_password} -v -T {/tmp/${case_number}_compressed.tar.gz}"
echo -en '\n'
echo -en '\n'
echo "in case you would like to collect a log dump you can use this command"
echo "      tar -czvf /tmp/logbundle_$(date +"%Y_%m_%d_%I_%M_%p").tar.gz /var/log/*.log"
echo -en '\n'
echo -en '\n'