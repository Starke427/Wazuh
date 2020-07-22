#!/bin/bash

# Install Wazuh 3.13 on Elastic 7.8
# Deployed on CentOS 7.6
# Written by Wazuh, automated by Jeff Starke

# This script will install Wazuh and Elastic on a stand-alone CentOS host.
# It currently does not configure an nginx proxy for TLS  encyprtion.
# By default, the manager can recieve syslog over UDP/514.
# This Manager has been configured to use TCP/1514 for on-going communication with agents.

# Introduction ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
local_ip=$(ifconfig | grep -w "inet" -m 1 | cut -d " " -f 10) # Grab server ip

cat << EOF
Initiating installation of Wazuh on localhost...

This host should be configured with a static IP.
Currently that IP appears to be: $local_ip

Keep in mind, you should be running the following services on your network.
If they are not present you should interupt this script and configure them now.
  - NTP
  - DNS

Wazuh will also need a number of network ports open between itself and the hosts
you intend to monitor. For a full list of requirements, please refer to:
https://documentation.wazuh.com/3.x/getting-started/architecture.html
EOF
echo ""
echo "List of IPs associated with this server:"
echo "$(ifconfig | grep -w "inet" | cut -d " " -f 10)"
echo ""
read -p "Please set the static IP of this server: " -i $local_ip -e local_ip
echo "$local_ip will now be configured as the IP of this server..."
sleep 5

# Install Wazuh ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
curl --silent --location https://rpm.nodesource.com/setup_10.x | bash -
yum install nodejs -y
yum install wazuh-manager-3.13.* wazuh-api-3.13.* -y
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo # Disable Wazuh repo

# Install Elastic ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
yum install filebeat-7.8.0 -y
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v3.13.0/extensions/filebeat/7.x/filebeat.yml
chmod go+r /etc/filebeat/filebeat.yml
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v3.13.0/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz | sudo tar -xvz -C /usr/share/filebeat/module
sed -i "s/YOUR_ELASTIC_SERVER_IP/$local_ip/g" /etc/filebeat/filebeat.yml #localhost is IP address of the Elasticsearch server
systemctl daemon-reload
systemctl enable filebeat.service
systemctl start filebeat.service
yum install elasticsearch-7.8.0 -y
sed -i '/^#.*node.name/s/^#//' /etc/elasticsearch/elasticsearch.yml
#sed -i 's/"node-1"/"node_name"/g' /etc/elasticsearch/elasticsearch.yml
sed -i '/^#.*network.host/s/^#//' /etc/elasticsearch/elasticsearch.yml
sed -i "s/192.168.0.1/$local_ip/g" /etc/elasticsearch/elasticsearch.yml #local_ip is IP address of the Elasticsearch server
sed -i '/^#.*cluster.initial_master_nodes/s/^#//' /etc/elasticsearch/elasticsearch.yml
sed -i 's/"node-1", "node-2"/"node-1"/g' /etc/elasticsearch/elasticsearch.yml
#sed -i "s/TimeoutStopSec=0/TimeoutStopSec=900/g" /usr/lib/systemd/system/elasticsearch.service #Extend service timeout
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl start elasticsearch.service
filebeat setup --index-management -E setup.template.json.enabled=false
sleep 5
yum install kibana-7.8.0 -y
cd /usr/share/kibana
sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-3.13.0_7.8.0.zip
sed -i '/\#server.host/s/^#//g' /etc/kibana/kibana.yml
sed -i "s/localhost/$local_ip/g" /etc/kibana/kibana.yml # May be redundant
sed -i '/elasticsearch.hosts/s/^#//g' /etc/kibana/kibana.yml
sed -i "s/\/localhost/\/$local_ip/g" /etc/kibana/kibana.yml
systemctl daemon-reload
systemctl enable kibana.service
systemctl start kibana.service
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo # Disable Elastic repo

# Configure Wazuh Manager ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cat > /var/ossec/etc/ossec.conf << EOF
<!--
Wazuh - Manager - Default configuration for centos 7.6
More info at: https://documentation.wazuh.com
Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->
<ossec_config>
	<global>
		<jsonout_output>yes</jsonout_output>
		<alerts_log>yes</alerts_log>
		<logall>yes</logall>
		<logall_json>no</logall_json>
		<email_notification>no</email_notification>
		<smtp_server>smtp.example.wazuh.com</smtp_server>
		<email_from>ossecm@example.wazuh.com</email_from>
		<email_to>recipient@example.wazuh.com</email_to>
		<email_maxperhour>12</email_maxperhour>
		<email_log_source>alerts.log</email_log_source>
	</global>
	<alerts>
		<log_alert_level>3</log_alert_level>
		<email_alert_level>12</email_alert_level>
	</alerts>
	<!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
	<logging>
		<log_format>plain</log_format>
	</logging>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>10.0.0.0/8</allowed-ips>
    <allowed-ips>172.16.0.0/12</allowed-ips>
    <allowed-ips>192.168.0.0/16</allowed-ips>
    <local_ip>$local_ip</local_ip>
  </remote>
	<remote>
		<connection>secure</connection>
		<port>1514</port>
		<protocol>tcp</protocol>
		<queue_size>131072</queue_size>
	</remote>
	<!-- Policy monitoring -->
	<rootcheck>
		<disabled>no</disabled>
		<check_files>yes</check_files>
		<check_trojans>yes</check_trojans>
		<check_dev>yes</check_dev>
		<check_sys>yes</check_sys>
		<check_pids>yes</check_pids>
		<check_ports>yes</check_ports>
		<check_if>yes</check_if>
		<!-- Frequency that rootcheck is executed - every 12 hours -->
		<frequency>43200</frequency>
		<rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
		<rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
		<skip_nfs>yes</skip_nfs>
	</rootcheck>
	<wodle name="open-scap">
		<disabled>yes</disabled>
		<timeout>1800</timeout>
		<interval>1d</interval>
		<scan-on-start>yes</scan-on-start>
		<content path="ssg-centos-7-ds.xml" type="xccdf">
			<profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
			<profile>xccdf_org.ssgproject.content_profile_common</profile>
		</content>
	</wodle>
	<wodle name="cis-cat">
		<disabled>yes</disabled>
		<timeout>1800</timeout>
		<interval>1d</interval>
		<scan-on-start>yes</scan-on-start>
		<java_path>wodles/java</java_path>
		<ciscat_path>wodles/ciscat</ciscat_path>
	</wodle>
	<!-- Osquery integration -->
	<wodle name="osquery">
		<disabled>yes</disabled>
		<run_daemon>yes</run_daemon>
		<log_path>/var/log/osquery/osqueryd.results.log</log_path>
		<config_path>/etc/osquery/osquery.conf</config_path>
		<add_labels>yes</add_labels>
	</wodle>
	<!-- System inventory -->
	<wodle name="syscollector">
		<disabled>no</disabled>
		<interval>1h</interval>
		<scan_on_start>yes</scan_on_start>
		<hardware>yes</hardware>
		<os>yes</os>
		<network>yes</network>
		<packages>yes</packages>
		<ports all="no">yes</ports>
		<processes>yes</processes>
	</wodle>
	<sca>
		<enabled>yes</enabled>
		<scan_on_start>yes</scan_on_start>
		<interval>12h</interval>
		<skip_nfs>yes</skip_nfs>
		<policies>
			<policy>cis_rhel7_linux_rcl.yml</policy>
			<policy>system_audit_rcl.yml</policy>
			<policy>system_audit_ssh.yml</policy>
			<policy>system_audit_pw.yml</policy>
		</policies>
	</sca>
	<wodle name="vulnerability-detector">
		<disabled>yes</disabled>
		<interval>5m</interval>
		<ignore_time>6h</ignore_time>
		<run_on_start>yes</run_on_start>
		<feed name="ubuntu-18">
			<disabled>yes</disabled>
			<update_interval>1h</update_interval>
		</feed>
		<feed name="redhat">
			<disabled>yes</disabled>
			<update_from_year>2010</update_from_year>
			<update_interval>1h</update_interval>
		</feed>
		<feed name="debian-9">
			<disabled>yes</disabled>
			<update_interval>1h</update_interval>
		</feed>
	</wodle>
	<!-- File integrity monitoring -->
	<syscheck>
		<disabled>no</disabled>
		<!-- Frequency that syscheck is executed default every 12 hours -->
		<frequency>43200</frequency>
		<scan_on_start>yes</scan_on_start>
		<!-- Generate alert when new file detected -->
		<alert_new_files>yes</alert_new_files>
		<!-- Don't ignore files that change more than 'frequency' times -->
		<auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
		<!-- Directories to check  (perform all possible verifications) -->
		<directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
		<directories check_all="yes">/bin,/sbin,/boot</directories>
		<!-- Files/directories to ignore -->
		<ignore>/etc/mtab</ignore>
		<ignore>/etc/hosts.deny</ignore>
		<ignore>/etc/mail/statistics</ignore>
		<ignore>/etc/random-seed</ignore>
		<ignore>/etc/random.seed</ignore>
		<ignore>/etc/adjtime</ignore>
		<ignore>/etc/httpd/logs</ignore>
		<ignore>/etc/utmpx</ignore>
		<ignore>/etc/wtmpx</ignore>
		<ignore>/etc/cups/certs</ignore>
		<ignore>/etc/dumpdates</ignore>
		<ignore>/etc/svc/volatile</ignore>
		<ignore>/sys/kernel/security</ignore>
		<ignore>/sys/kernel/debug</ignore>
		<ignore>/dev/core</ignore>
		<!-- File types to ignore -->
		<ignore type="sregex">^/proc</ignore>
		<ignore type="sregex">.log\$|.swp\$</ignore>
		<!-- Check the file, but never compute the diff -->
		<nodiff>/etc/ssl/private.key</nodiff>
		<skip_nfs>yes</skip_nfs>
	</syscheck>
	<!-- Active response -->
	<global>
		<white_list>127.0.0.1</white_list>
		<white_list>^localhost.localdomain\$</white_list>
		<white_list>192.168.100.99</white_list>
		<white_list>8.8.8.8</white_list>
	</global>
	<command>
		<name>disable-account</name>
		<executable>disable-account.sh</executable>
		<expect>user</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>restart-ossec</name>
		<executable>restart-ossec.sh</executable>
		<expect/>
	</command>
	<command>
		<name>firewall-drop</name>
		<executable>firewall-drop.sh</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>host-deny</name>
		<executable>host-deny.sh</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>route-null</name>
		<executable>route-null.sh</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>win_route-null</name>
		<executable>route-null.cmd</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>win_route-null-2012</name>
		<executable>route-null-2012.cmd</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>netsh</name>
		<executable>netsh.cmd</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<command>
		<name>netsh-win-2016</name>
		<executable>netsh-win-2016.cmd</executable>
		<expect>srcip</expect>
		<timeout_allowed>yes</timeout_allowed>
	</command>
	<!--
			  <active-response>
						    #active-response options here
			  </active-response>
			  -->
	<!-- Log analysis -->
	<localfile>
		<log_format>command</log_format>
		<command>df -P</command>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
		<alias>netstat listening ports</alias>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<command>last -n 20</command>
		<frequency>360</frequency>
	</localfile>
	<ruleset>
		<!-- Default ruleset -->
		<decoder_dir>ruleset/decoders</decoder_dir>
		<rule_dir>ruleset/rules</rule_dir>
		<rule_exclude>0215-policy_rules.xml</rule_exclude>
		<list>etc/lists/audit-keys</list>
		<list>etc/lists/amazon/aws-eventnames</list>
		<list>etc/lists/security-eventchannel</list>
		<!-- User-defined ruleset -->
		<decoder_dir>etc/decoders</decoder_dir>
		<rule_dir>etc/rules</rule_dir>
	</ruleset>
	<!-- Configuration for ossec-authd -->
	<auth>
		<disabled>no</disabled>
		<port>1515</port>
		<use_source_ip>no</use_source_ip>
		<force_insert>yes</force_insert>
		<force_time>0</force_time>
		<purge>yes</purge>
		<use_password>yes</use_password>
		<limit_maxagents>yes</limit_maxagents>
		<ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
		<!-- <ssl_agent_ca></ssl_agent_ca>
						 -->
		<ssl_verify_host>no</ssl_verify_host>
		<ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
		<ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
		<ssl_auto_negotiate>no</ssl_auto_negotiate>
	</auth>
	<cluster>
		<name>wazuh</name>
		<node_name>node01</node_name>
		<node_type>master</node_type>
		<key/>
		<port>1516</port>
		<bind_addr>0.0.0.0</bind_addr>
		<nodes>
			<node>NODE_IP</node>
		</nodes>
		<hidden>no</hidden>
		<disabled>yes</disabled>
	</cluster>
</ossec_config>
<ossec_config>
	<localfile>
		<log_format>audit</log_format>
		<location>/var/log/audit/audit.log</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/ossec/logs/active-responses.log</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/messages</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/secure</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/maillog</location>
	</localfile>
</ossec_config>
EOF


# Agent configuration files ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
mkdir /var/ossec/etc/shared/linux # Create linux group
cat > /var/ossec/etc/shared/linux/agent.conf << EOF # Linux agent.conf
<!--
  Wazuh - Agent - Default configuration for centos 7.6
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->
<ossec_config>
  <client>
    <server>
      <address>$local_ip</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>centos, centos7, centos7.6</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <!-- Agent buffer options -->
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>

    <!-- Frequency that rootcheck is executed - every 2 hours -->
    <frequency>7200</frequency>

    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>

    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="open-scap">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <content type="xccdf" path="ssg-centos-7-ds.xml">
      <profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
      <profile>xccdf_org.ssgproject.content_profile_common</profile>
    </content>
  </wodle>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>

    <policies>
      <policy>cis_rhel7_linux_rcl.yml</policy>
      <policy>system_audit_rcl.yml</policy>
      <policy>system_audit_ssh.yml</policy>
      <policy>system_audit_pw.yml</policy>
    </policies>
  </sca>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 2 hours -->
    <frequency>7200</frequency>

    <scan_on_start>yes</scan_on_start>

    <!-- Directories to check  (perform all possible verifications) -->
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>

    <!-- Files/directories to ignore -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore>/sys/kernel/security</ignore>
    <ignore>/sys/kernel/debug</ignore>
    <ignore>/dev/core</ignore>

    <!-- File types to ignore -->
    <ignore type="sregex">^/proc</ignore>
    <ignore type="sregex">.log\$|.swp\$</ignore>

    <!-- Check the file, but never compute the diff -->
    <nodiff>/etc/ssl/private.key</nodiff>

    <skip_nfs>yes</skip_nfs>
  </syscheck>

  <!-- Log analysis -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <!-- Choose between "plain", "json", or "plain,json" for the format of internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

</ossec_config>

<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/maillog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

</ossec_config>
EOF
chown ossec:ossec -R /var/ossec/etc/shared/linux


mkdir /var/ossec/etc/shared/windows # Create windows group
cat > /var/ossec/etc/shared/windows/agent.conf << EOF # Windows agent.conf
<!--
  Wazuh - Agent - Default configuration for Windows
  More info at: https://documentation.wazuh.com
  Mailing list: https://groups.google.com/forum/#!forum/wazuh
-->
<ossec_config>

  <client>
    <server>
      <address>$local_ip</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- Agent buffer options -->
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Log analysis -->
  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and
      EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and
      EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907 and
      EventID != 5152 and EventID != 5157]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>active-response\active-responses.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <!-- Policy monitoring -->
  <rootcheck>
    <disabled>no</disabled>
    <windows_apps>./shared/win_applications_rcl.txt</windows_apps>
    <windows_malware>./shared/win_malware_rcl.txt</windows_malware>
  </rootcheck>

  <!-- Security Configuration Assessment -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>

    <policies>
      <policy>win_audit_rcl.yml</policy>
    </policies>
  </sca>

  <!-- File integrity monitoring -->
  <syscheck>

    <disabled>no</disabled>

    <!-- Frequency that syscheck is executed default every 2 hours -->
    <frequency>7200</frequency>

    <!-- Default files to be monitored. -->
    <directories check_all="yes">%WINDIR%\regedit.exe</directories>
    <directories check_all="yes">%WINDIR%\system.ini</directories>
    <directories check_all="yes">%WINDIR%\win.ini</directories>

    <directories check_all="yes">%WINDIR%\SysNative\at.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\attrib.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\cacls.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\cmd.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\drivers\etc</directories>
    <directories check_all="yes">%WINDIR%\SysNative\eventcreate.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\ftp.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\lsass.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\net.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\net1.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\netsh.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\reg.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\regedt32.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\regsvr32.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\runas.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\sc.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\schtasks.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\sethc.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\subst.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\wbem\WMIC.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\WindowsPowerShell\v1.0\powershell.exe</directories>
    <directories check_all="yes">%WINDIR%\SysNative\winrm.vbs</directories>

    <!-- 32-bit programs. -->
    <directories check_all="yes">%WINDIR%\System32\at.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\attrib.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\cacls.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\cmd.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\drivers\etc</directories>
    <directories check_all="yes">%WINDIR%\System32\eventcreate.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\ftp.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\net.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\net1.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\netsh.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\reg.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\regedit.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\regedt32.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\regsvr32.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\runas.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\sc.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\schtasks.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\sethc.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\subst.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\wbem\WMIC.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe</directories>
    <directories check_all="yes">%WINDIR%\System32\winrm.vbs</directories>
    <directories check_all="yes" realtime="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>

    <ignore>%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini</ignore>

    <ignore type="sregex">.log\$|.htm\$|.jpg\$|.png\$|.chm\$|.pnf\$|.evtx\$</ignore>

    <!-- Windows registry entries to monitor. -->
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\cmdfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\comfile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\exefile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\piffile</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\AllFilesystemObjects</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Directory</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Folder</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Classes\Protocols</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Policies</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Security</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer</windows_registry>

    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg</windows_registry>

    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\URL</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>

    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components</windows_registry>

    <!-- Windows registry entries to ignore. -->
    <registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\Security\SAM\Domains\Account\Users</registry_ignore>
    <registry_ignore type="sregex">\Enum\$</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\AppCs</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\DHCP</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\IPTLSIn</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\IPTLSOut</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\RPC-EPMap</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\Teredo</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PolicyAgent\Parameters\Cache</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</registry_ignore>
    <registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ADOVMPPackage\Final</registry_ignore>

    <!-- Frequency for ACL checking (seconds) -->
    <windows_audit_interval>300</windows_audit_interval>
  </syscheck>

  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <!-- CIS policies evaluation -->
  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <java_path>\\server\jre\bin\java.exe</java_path>
    <ciscat_path>C:\cis-cat</ciscat_path>
  </wodle>

  <!-- Osquery integration -->
  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <bin_path>C:\ProgramData\osquery\osqueryd</bin_path>
    <log_path>C:\ProgramData\osquery\log\osqueryd.results.log</log_path>
    <config_path>C:\ProgramData\osquery\osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <!-- Choose between plain or json format (or both) for internal logs -->
  <logging>
    <log_format>plain</log_format>
  </logging>

</ossec_config>

<!-- END of Default Configuration. -->
EOF
chown ossec:ossec -R /var/ossec/etc/shared/windows

mkdir /var/ossec/etc/shared/macos # Create macos group
#cat > /var/ossec/etc/shared/windows/agent.conf << EOF # MacOS agent.config
# MacOS Configuration needed
#EOF
chown ossec:ossec -R /var/ossec/etc/shared/macos


systemctl restart wazuh-manager

cat << EOF
Please navigate to http://$local_ip:5601 to configure the Kibana App.

EOF

touch elastic_status.txt
while ! grep "green" elastic_status.txt
do
  curl -XGET "http://$local_ip:9200/_cluster/health?pretty" > elastic_status.txt 2>/dev/null
  echo "Waiting for elasticsearch to finish setup..."
  sleep 10
done 2>/dev/null
rm -f elastic_status.txt
echo ""
echo "Please navigate to http://$local_ip:5601 to configure the Kibana App."
