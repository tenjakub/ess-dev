#!/bin/bash

#change the working directory to the script directory
WORKDIR=$(dirname "$0")
cd "${WORKDIR}"

#required packages for the script; this string will be printed in the istallation process
#and it will also be used to install these packages; write the packages separated by spaces
DEPENDENCIES="curl zip tar expect openssl jq"

#define script work name. This name will be used for the script directory and logging naming scheme
DEFNAME="ess-install"

#set the default port for the Kibana web interface (can be changed during the installation process)
DEFKIBPORT=8443

#define default script work path used for storing certificate and other files
DEFDIR=/opt/
DEFDIR="${DEFDIR}${DEFNAME}/"

#define the elasticsearch paths
ESPATH=/etc/elasticsearch/
ESCONF=/etc/elasticsearch/elasticsearch.yml

#define the kibana paths
KIBPATH=/etc/kibana/
KIBCONF=/etc/kibana/kibana.yml

#define the logstash paths
LGSTPATH=/etc/logstash/

#define custom functions

#log status output to both terminal and logfile
infu () {
    echo "$1"
    echo "$(date) $1" >> "${LOGFILE}"
}

#modify config file line
#usage: modcol "parameter" "value" "/path/to/file"
modcol () {
    local find=$1 #should end with: (eg. host.name:)
    local add=$2 #gets added to the line
    local file=$3

    replace="${find} ${add}"

    if grep -q "^${find}" "${file}"; then
        sed -i "/^${find}/c\\${replace}" "${file}"
    else
        if grep -q "^#${find}" "${file}"; then
            sed -i "/^#${find}/c\\${replace}" "${file}"
        else
            echo "${replace}" >> "${file}"
        fi
    fi
}

#replace directory
#usage: repdir "name of the folder I want to move" "path to the directory I need to check (without the final directory itself)" "where I want to save the files"
#both path and target should end with a slash (/)
repdir () {
    local foldername=$1
    local path=$2
    local target=$3

    if [ -d  "${path}${foldername}" ]; then
        if [ ! -d ${target} ]; then
            mkdir -p "${target}"
        fi
        mv "${path}${foldername}" "${target}${foldername}-$(date +%H-%M-%S-%F)"
        echo "Moved the ${path}${foldername} directory to a ${target} reserve directory"
    fi
    mkdir -p "${path}${foldername}"
    if [ -d  "${path}${foldername}" ]; then
        echo "Created the ${path}${foldername} directory"
    fi
}

#check whether whiptail is installed
if ! which whiptail >> /dev/null 2>&1; then
    echo "ERROR: This script requires whiptail to be installed in order to function. Please make sure that whiptail is installed and try again."
    exit 21
fi

#check whether the command is run by the root user
if [ ! $UID -eq "0"  ]; then
    whiptail --title "ROOT REQUIRED" --msgbox "This installation script has to be run under the \"root\" user. Run this script with the root user." 8 78
    exit 22
fi

#modify the permissions of the all the files used by the instalaltion
chmod 644 ./api-requests/*
chmod 644 ./config-files/*
chmod 744 ./expect/*

#create script work directory
if [ ! -d "${DEFDIR}" ]; then
    mkdir -p "/${DEFDIR}"
fi

#create the cript logfile
LOGFILE="${DEFDIR}${DEFNAME}.log"
if [ ! -f "${LOGFILE}" ]; then
    touch "${LOGFILE}"
fi

#create a directory for reserve files
RSVDIR="${DEFDIR}reserve/"
if [ ! -d  "${RSVDIR}" ]; then
    sudo mkdir -p "${RSVDIR}"
    infu "Created reserve files directory"
fi

#inform about the script startup
infu "==== SCRIPT STARTED ===="
infu "Working at: ${WORKDIR}"

#determine the system distribution; distro output value is DISTRO
if [[ ! -z $(grep "^ID_LIKE=" /etc/os-release) ]]; then
    DISTROLIKE=$(grep "^ID_LIKE=" /etc/os-release | cut -d '=' -f2 | tr -d '"')
elif [[ ! -z $(grep "^ID=" /etc/os-release) ]]; then
    DISTROLIKE=$(grep "^ID=" /etc/os-release | cut -d '=' -f2 | tr -d '"')
fi

case "${DISTROLIKE}" in
    *rhel*|*fedora*|*centos*) DISTRO="redhat";;
    *ubuntu*|*debian*) 
        DISTRO="debian"
        apt-get update -y
    ;;
    *)OTHERDISTRO=$(whiptail --title "No supported linux distribution detected" --menu "No supported linux distribution has been found on your system. Choose how the script should interact with the system.\nWARNING: The script might not work properly!" 20 78 2 "RedHat" "based distributions using YUM/DNF package manager" "Debian" "based distributions using apt-get package manager" 3>&1 1>&2 2>&3)
        exitstatus=$?
        if [ $exitstatus == 0 ]; then
            if [[ ! -z "${OTHERDISTRO}" ]]; then
                if [ "${OTHERDISTRO}" == "RedHat" ]; then
                    DISTRO="redhat"
                elif [ "${OTHERDISTRO}" == "Debian" ]; then
                    DISTRO="debian"
                    apt-get update -y
                fi
            fi
        else
            exit 23
        fi
    ;;
esac
infu "System distribution determined as ${DISTRO}"

#inform the user about the required packages
if ! whiptail --title "Script dependencies" --yesno "This script needs the following packages available on the system in order to work properly. Any required packages will be installed automatically.\n\n${DEPENDENCIES}\n\nIs this alright?" 12 78; then
    infu "User chose to exit the installation process"
    exit 24
fi

#enter and check the server IP address
REPEAT=1
INP_ERR=""

while [ "${REPEAT}" == "1" ]; do
    IPADDR=$(whiptail --inputbox "Enter the server IPv4 address you want the Elastic SIEM application to operate on.\n${INP_ERR}" 9 78 "" --title "SET IP ADDRESS" 3>&1 1>&2 2>&3)
    exitstatus=$?

    if [ $exitstatus = 0 ]; then
        if [[ "${IPADDR}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            INP_ERR=""
            REPEAT=0
        else
            INP_ERR="ERROR: Please input a valid IP address"
        fi
    else
        exit 10
    fi
done

#enter and check the Kibana web server port
REPEAT=1
INP_ERR=""

while [ "${REPEAT}" == "1" ]; do
    KIBPORT=$(whiptail --inputbox "Set the port for the Kibana web interface. This is the port you will use to connect to the system web interface. The default value often used for Kibana is 5601, however you can choose one you prefer.\n${INP_ERR}" 9 78 "${DEFKIBPORT}" --title "SET KIBANA WEB INTERFACE PORT" 3>&1 1>&2 2>&3) 
    exitstatus=$?

    if [ $exitstatus = 0 ]; then
        if [[ "${KIBPORT}" =~ ^[0-9]+$ ]]; then
            INP_ERR=""
            REPEAT=0
        else
            INP_ERR="ERROR: Please input a valid port number"
        fi
    else
        exit 10
    fi
done

#enter the server/cluster name
SERVERNAME=$(whiptail --inputbox "Enter the server name you want your server to use. This name is used mainly for display purposes. It will also be used as the cluster name." 9 78 "" --title "SET SERVER NAME" 3>&1 1>&2 2>&3)
exitstatus=$?
if [ ! $exitstatus = 0 ]; then
    exit 10
fi

#set the superuser password
REPEAT=1
SUPPASS_ERR=""
MINPASSLENGTH=6

while [ "${REPEAT}" == "1" ]; do
    SUPPASS=$(whiptail --passwordbox "Please enter the password for the Elastic Stack superuser (elastic). This user will have the highest privilages, so keep this password secure.\n${SUPPASS_ERR}" 9 78 "" --title "SET SUPERUSER PASSWORD" 3>&1 1>&2 2>&3)
    exitstatus=$?
    if [ $exitstatus = 0 ]; then
        if [ "${#SUPPASS}" -ge "${MINPASSLENGTH}" ]; then
            SUPPASS_ERR=""
            SUPPASS2=$(whiptail --passwordbox "Please repeat the password." 9 78 "" --title "SET SUPERUSER PASSWORD" 3>&1 1>&2 2>&3)
            exitstatus=$?
            if [ $exitstatus = 0 ]; then
                if [ "${SUPPASS}" == "${SUPPASS2}" ]; then
                    SUPPASS_ERR=""
                    infu "Superuser password succesfully set"
                    REPEAT=0
                else
                    SUPPASS_ERR="The passwords do not match."
                fi
            else
                exit 10
            fi
        else
            SUPPASS_ERR="The superuser password must be at least 6 characters long"
        fi
    else
        exit 10
    fi
done

#ask the user about automatic services start after boot-up
if whiptail --title "START WITH STARTUP" --yesno "Would you like to enable auto-start for the installed services after the installation finishes? This will configure the services to automatically start each time the system boots up." 12 78; then
    AUTOSTART=1
else
    AUTOSTART=0
fi

#inform the user that the installation is about to begin
if ! whiptail --title "INSTALLATION ABOUT TO START" --yesno "The installation is about to start, and it cannot be terminated from now on.\nDo you want to continue?" 12 78; then
    infu "User chose to exit the installation process"
    exit 100
fi

#generate internal user passwords
KIBSPASS=$(openssl rand -base64 12)
if [ $? = 0 ]; then
    infu "Kibana System password has been created"
else
    infu "ERROR: Kibana System password has not been created."
    exit 30
fi

LOGIPASS=$(openssl rand -base64 12)
if [ $? = 0 ]; then
    infu "Logstash Internal password has been created"
else
    infu "ERROR: Logstash Internal password has not been created."
    exit 31
fi

#install required packages
case "${DISTRO}" in
    redhat) dnf install ${DEPENDENCIES} -y -q;;
    debian) apt-get install ${DEPENDENCIES} -y;;
esac

#add the elasticsearch repository
case "${DISTRO}" in
    redhat)
        REPOFILE="/etc/yum.repos.d/elasticsearch.repo"
        if [ ! -e "${REPOFILE}" ]; then
            touch "${REPOFILE}"
        fi
        #edit the repository source file
        echo "[elasticsearch-8.x]" > "${REPOFILE}"
        echo "name=Elasticsearch repository for 8.x packages" >> "${REPOFILE}"
        echo "baseurl=https://artifacts.elastic.co/packages/8.x/yum" >> "${REPOFILE}"
        echo "gpgcheck=1" >> "${REPOFILE}"
        echo "gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch" >> "${REPOFILE}"
        echo "enabled=1" >> "${REPOFILE}"
        echo "autorefresh=1" >> "${REPOFILE}"
        echo "type=rpm-md" >> "${REPOFILE}"
        echo "" >> "${REPOFILE}"
        #enable the repository
        sudo dnf --enablerepo=elasticsearch-8.x group
        infu "YUM repository added"
    ;;
    debian) 
        REPOFILE="/usr/share/keyrings/elasticsearch-keyring.gpg"
        if [ ! -e "${REPOFILE}" ]; then
            wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
        fi
        echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
        infu "Debian repository added"

        #check if there is the apt-transport-https package installed (reccomended by the official documentation)
        dpkg -s apt-transport-https &> /dev/null
        exitstatus=$?
        if [ $exitstatus = 1 ]; then
            sudo apt-get install apt-transport-https -y
            infu "installed apt-transport-https"
        fi
    ;;
esac

#stop the default Security Autoconfiguration
if [ ! -d  /etc/elasticsearch/ ]; then
    mkdir /etc/elasticsearch/
fi
if [ ! -e  /etc/elasticsearch/elasticsearch.yml ]; then
    touch /etc/elasticsearch/elasticsearch.yml
    infu "Created spoofing configuration file"
fi
if [ ! -s /etc/elasticsearch/elasticsearch.yml ]; then
    echo "xpack.security.autoconfiguration.enabled: false" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.enrollment.enabled: false" >> /etc/elasticsearch/elasticsearch.yml
    echo "" >> /etc/elasticsearch/elasticsearch.yml
fi

#installing the services + updates
infu "Starting installation. This process might take some time."
case "${DISTRO}" in
    redhat) 
        sudo dnf update -y -q
        sudo dnf install elasticsearch -y -q
        sudo dnf install kibana -y -q
        sudo dnf install logstash -y
    ;;
    debian) 
        sudo apt-get update -y
        sudo apt-get -o Dpkg::Options::="--force-confold" install elasticsearch -y
        sudo apt-get install kibana -y
        sudo apt-get install logstash -y
    ;;
esac

#create directories for ceritifaces
repdir "windows" "${DEFDIR}agents/" "${RSVDIR}agents/"
repdir "linux" "${DEFDIR}agents/" "${RSVDIR}agents/"
repdir "ssl" "${DEFDIR}" "${RSVDIR}"
repdir "certs" "${ESPATH}" "${RSVDIR}elasticsearch/"
repdir "certs" "${KIBPATH}" "${RSVDIR}kibana/"
repdir "certs" "${LGSTPATH}" "${RSVDIR}logstash/"
if [ ! -d  "${DEFDIR}ssl/agents/" ]; then
    mkdir -p "${DEFDIR}ssl/agents/"
    infu "Created Agents certificates directory"
fi

#replace the spoofing configuration file
if [ -e /etc/elasticsearch/elasticsearch.yml.rpmnew ]; then
    mv /etc/elasticsearch/elasticsearch.yml "${RSVDIR}elasticsearch.yml-$(date +%H-%M-%S-%F)"
    mv /etc/elasticsearch/elasticsearch.yml.rpmnew /etc/elasticsearch/elasticsearch.yml
    infu "Replaced the spoofing configuration file"
fi
if [ -e /etc/elasticsearch/elasticsearch.yml.dpkg-dist ]; then
    mv /etc/elasticsearch/elasticsearch.yml "${RSVDIR}elasticsearch.yml-$(date +%H-%M-%S-%F)"
    mv /etc/elasticsearch/elasticsearch.yml.dpkg-dist /etc/elasticsearch/elasticsearch.yml
    infu "Replaced the spoofing configuration file"
fi

#modify the elasticsearch configuration configuration file
modcol "cluster.name:" "${SERVERNAME}" "${ESCONF}"
modcol "node.name:" "${SERVERNAME}" "${ESCONF}"
modcol "xpack.security.enabled:" "true" "${ESCONF}"
modcol "discovery.type:" "single-node" "${ESCONF}"
modcol "xpack.security.http.ssl.enabled:" "true" "${ESCONF}"
modcol "xpack.security.http.ssl.certificate:" "${ESPATH}certs/es-http.crt" "${ESCONF}"
modcol "xpack.security.http.ssl.key:" "${ESPATH}certs/es-http.key" "${ESCONF}"

infu "Modified Elasticsearch configuration file"

#generate certificate authority
repdir "ca" "${DEFDIR}ssl/" "${RSVDIR}"
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --out "${DEFDIR}ssl/es-ca.zip" --pem -s
unzip -qq "${DEFDIR}ssl/es-ca.zip" -d "${DEFDIR}ssl/"
rm -f "${DEFDIR}ssl/es-ca.zip"
infu "Created a certificate authority"

#generate certificates for elasticsearch
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert "${DEFDIR}ssl/ca/ca.crt" --ca-key "${DEFDIR}ssl/ca/ca.key" --days 1826 --name es-http --out "${DEFDIR}ssl/es-http.zip" --ip "${IPADDR}",127.0.0.1 --pem -s
unzip -qq "${DEFDIR}ssl/es-http.zip" -d "${DEFDIR}ssl/"
rm -f "${DEFDIR}ssl/es-http.zip"
mv "${DEFDIR}ssl/es-http/"* /etc/elasticsearch/certs/
rmdir "${DEFDIR}ssl/es-http/"
infu "Generated Elasticsearch certificates"

#generate certificates for kibana
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert "${DEFDIR}ssl/ca/ca.crt" --ca-key "${DEFDIR}ssl/ca/ca.key" --days 1826 --name kibana-server --out "${DEFDIR}ssl/kibana-server.zip" --ip "${IPADDR}" --pem -s
unzip -qq "${DEFDIR}ssl/kibana-server.zip" -d "${DEFDIR}ssl/"
rm -f "${DEFDIR}ssl/kibana-server.zip"
mv "${DEFDIR}ssl/kibana-server/"* /etc/kibana/certs/
rmdir "${DEFDIR}ssl/kibana-server/"
cp "${DEFDIR}ssl/ca/ca.crt" /etc/kibana/certs
infu "Generated Kibana certificates"

#modify the kibana configuration file
KIBCA=["\"${KIBPATH}certs/ca.crt\""]

modcol "server.port:" "${KIBPORT}" "${KIBCONF}"
modcol "server.host:" "${IPADDR}" "${KIBCONF}"
modcol "server.name:" "${SERVERNAME}" "${KIBCONF}"
modcol "server.ssl.enabled:" "true" "${KIBCONF}"
modcol "server.ssl.certificate:" "${KIBPATH}certs/kibana-server.crt" "${KIBCONF}"
modcol "server.ssl.key:" "${KIBPATH}certs/kibana-server.key" "${KIBCONF}"
modcol "elasticsearch.hosts:" '["https://127.0.0.1:9200"]' "${KIBCONF}"
modcol "elasticsearch.username:" "kibana_system" "${KIBCONF}"
modcol "elasticsearch.ssl.certificateAuthorities:" "${KIBCA}" "${KIBCONF}"

if grep -q "^xpack.encryptedSavedObjects.encryptionKey:" "${KIBCONF}" || grep -q "^xpack.reporting.encryptionKey:" "${KIBCONF}" || grep -q "^xpack.security.encryptionKey:" "${KIBCONF}"; then
    infu "Kibana object encryption already set up"
else
    echo "" >> "${KIBCONF}"
    echo "# =================== ELASTIC SIEM AUTOCONFIGURATION ===================" >> "${KIBCONF}"
    /usr/share/kibana/bin/kibana-encryption-keys generate -q -f >> "${KIBCONF}"
    echo "" >> "${KIBCONF}"
    infu "Added kibana object encryption"
fi

#create the kibana keystore
if [ ! -e "${KIBPATH}"kibana.keystore ]; then
    ./expect/create-kibana-keystore
fi

#add the kibana_systemuser password
./expect/add-kibana-keystore-esuser "${KIBSPASS}"

#start the elasticsearch service
/usr/share/elasticsearch/bin/elasticsearch-keystore upgrade
systemctl start elasticsearch.service

#reset the elastic user password
./expect/reset-elastic-password "${SUPPASS}"

#reset the kibana system user password
./expect/reset-kibana-system-password "${KIBSPASS}"

#Create a role for the internal Logstash user for Elasticsearch, together with the user itself
LOGIROLE_RESP=$(curl --silent --output  -X POST "https://127.0.0.1:9200/_security/role/logstash_writer" -u "elastic:${SUPPASS}" --cacert "${DEFDIR}ssl/ca/ca.crt" -H "Content-Type: application/json" -d '{ "cluster": ["manage_index_templates", "monitor", "manage_ilm"], "indices": [ { "names": [ "*" ], "privileges": ["write","create","create_index","manage","manage_ilm"] } ] }')

if [[ "${LOGIROLE_RESP}" == *"true"* ]]; then
    infu "Logstash writer role succesfully created"
    LOGIUSER_RESP=$(curl --silent --output  -X POST "https://127.0.0.1:9200/_security/user/logstash_internal" -u "elastic:${SUPPASS}" --cacert "${DEFDIR}ssl/ca/ca.crt" -H "Content-Type: application/json" -d "{ \"password\" : \"${LOGIPASS}\", \"roles\" : [ \"logstash_writer\"], \"full_name\" : \"Internal Logstash User\" }")
    if [[ "${LOGIROLE_RESP}" == *"true"* ]]; then
        infu "Logstash internal user succesfully created"
    else
        infu "ERROR: Logstash internal user has NOT been created"
    fi
else
    infu "ERROR: Logstash writer role has NOT been created"
fi

#create logstash and agent transport certificates
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert "${DEFDIR}ssl/ca/ca.crt" --ca-key "${DEFDIR}ssl/ca/ca.key" --days 1826 --name logstash-input --out "${DEFDIR}ssl/logstash-input.zip" --ip "${IPADDR}" --pem -s
unzip -qq "${DEFDIR}ssl/logstash-input.zip" -d "${DEFDIR}ssl/"
mv "${DEFDIR}ssl/logstash-input/"* /etc/logstash/certs
rm -f "${DEFDIR}ssl/logstash-input.zip"
cp "${DEFDIR}ssl/ca/ca.crt" /etc/logstash/certs

/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert "${DEFDIR}ssl/ca/ca.crt" --ca-key "${DEFDIR}ssl/ca/ca.key" --days 1826 --name es-agent --out "${DEFDIR}ssl/agents/es-agent.zip" --pem -s
unzip -qq "${DEFDIR}ssl/agents/es-agent.zip" -d "${DEFDIR}ssl/agents/"
rm -f "${DEFDIR}ssl/agents/es-agent.zip"
cp "${DEFDIR}ssl/ca/ca.crt" "${DEFDIR}ssl/agents/es-agent"

#create the logstash keystore
if [ ! -e "${LGSTPATH}"logstash.keystore ]; then
    ./expect/create-logstash-keystore
fi

#add values to the logstash keystore
./expect/add-logstash-keystore-user logstash_internal
./expect/add-logstash-keystore-password "${LOGIPASS}"

#create configuration files for logstash pipelines
if [ ! -e /etc/logstash/conf.d/beats.conf ]; then
    cp ./config-files/beats.conf /etc/logstash/conf.d/
    infu "Logstash Beats pipeline configuration file copied"
else
    infu "Detected an existing Beats pipeline configuration file"
    infu "If you did explicitely modify it and want the default configuration to be used, you can find it at ${WORKDIR}config-files/beats.conf"
fi
if [ ! -e /etc/logstash/conf.d/agents.conf ]; then
    cp ./config-files/agents.conf /etc/logstash/conf.d/
    infu "Logstash Elastic agent pipeline configuration file copied"
else
    infu "Detected an existing Elastic agent pipeline configuration file"
    infu "If you did explicitely modify it and want the default configuration to be used, you can find it at ${WORKDIR}config-files/agents.conf"
fi

#start the kibana and logstash services
systemctl start logstash
systemctl start kibana

#check whether the Kibana API is available
KIBSTATUS_REPEAT=1
KIBSTATUS_START=$(date +%s)
KIBSTATUS_TIMEOUT=181

infu "starting Kibana"
while [ "${KIBSTATUS_REPEAT}" -eq "1" ]; do
  if [ $(date +%s) -lt $((KIBSTATUS_START + KIBSTATUS_TIMEOUT)) ]; then
    if ! curl --fail --silent --output /dev/null -u "elastic:${SUPPASS}" --cacert "${DEFDIR}ssl/ca/ca.crt" "https://${IPADDR}:${KIBPORT}"; then
      sleep 5
    else
      KIBSTATUS_REPEAT=0
    fi
  else
    infu "Timeout on Kibana startup has been reached. The agent policies have NOT been added."
  fi
done

infu "Kibana API is now available!"

#create a Windows agent policy
WINPLC_RESP=$(curl --silent --output /dev/null -X POST "https://${IPADDR}:${KIBPORT}/api/fleet/agent_policies?sys_monitoring=true" --cacert "${DEFDIR}ssl/ca/ca.crt" -u "elastic:${SUPPASS}" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{ "name": "windows-agents-default", "description": "The default policy to for use with Windows Elastic Agents", "namespace": "default", "monitoring_enabled": ["logs", "metrics"], "inactivity_timeout": 1209600, "is_protected": false}')
if [[ "${WINPLC_RESP}" == *"\"updated_by\":"* ]]; then
    infu "Windows agent policy succesfully created"
else
    infu "ERROR: Windows agent policy has NOT been created"
fi

#create a Linux agent policy
LNXPLC_RESP=$(curl --silent --output /dev/null -X POST "https://${IPADDR}:${KIBPORT}/api/fleet/agent_policies?sys_monitoring=true" --cacert "${DEFDIR}ssl/ca/ca.crt" -u "elastic:${SUPPASS}" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{ "name": "linux-agents-default", "description": "The default policy to for use with Linux Elastic Agents", "namespace": "default", "monitoring_enabled": ["logs", "metrics"], "inactivity_timeout": 1209600, "is_protected": false}')
if [[ "${LNXPLC_RESP}" == *"\"updated_by\":"* ]]; then
    infu "Linux agent policy succesfully created"
else
    infu "ERROR: Linux agent policy has NOT been created"
fi

#get the policy IDs
WINPLC_ID=$(curl --silent --output /dev/null -u "elastic:${SUPPASS}" --cacert "${DEFDIR}ssl/ca/ca.crt" "https://${IPADDR}:${KIBPORT}/api/fleet/agent_policies" | jq -r '.items[] | select(.name == "windows-agents-default") | .id')
LNXPLC_ID=$(curl --silent --output /dev/null -u "elastic:${SUPPASS}" --cacert "${DEFDIR}ssl/ca/ca.crt" "https://${IPADDR}:${KIBPORT}/api/fleet/agent_policies" | jq -r '.items[] | select(.name == "linux-agents-default") | .id')

#replace the policy IDs for the integration add templates
sed -i "/policy_id/c\\  \"policy_id\": \"${WINPLC_ID}\"," "./api-requests/add-windows-integration"
sed -i "/policy_id/c\\  \"policy_id\": \"${LNXPLC_ID}\"," "./api-requests/add-linux-auditd-integration"

#add the Windows integration to the agent policy
WININT1_RESPT=$(curl --silent --output /dev/null -X POST "https://${IPADDR}:${KIBPORT}/api/fleet/package_policies" --cacert "${DEFDIR}ssl/ca/ca.crt" -u "elastic:${SUPPASS}" -H "Content-Type: application/json" -H "kbn-xsrf: true" --data "@./api-requests/add-windows-integration")
if [[ "${WININT1_RESPT}" == *"\"updated_by\":"* ]]; then
    infu "Windows integration succesfully added to agent policy"
else
    infu "ERROR: Windows integration has NOT been added to agent policy"
fi

#add the Linux Auditd integration to the agent policy
LNXINT1_RESPT=$(curl --silent --output /dev/null -X POST "https://${IPADDR}:${KIBPORT}/api/fleet/package_policies" --cacert "${DEFDIR}ssl/ca/ca.crt" -u "elastic:${SUPPASS}" -H "Content-Type: application/json" -H "kbn-xsrf: true" --data "@./api-requests/add-linux-auditd-integration")
if [[ "${LNXINT1_RESPT}" == *"\"updated_by\":"* ]]; then
    infu "Linux Auditd integration succesfully added to agent policy"
else
    infu "ERROR: Linux Auditd integration has NOT been added to agent policy"
fi

#enable the services, if the user chose to do so
if [[ "${AUTOSTART}" -eq "1" ]]; then
    systemctl enable elasticsearch
    systemctl enable kibana
    systemctl enable logstash
fi

#Inform the user about the succesful completion of the script
whiptail --title "INSTALLATION SUCCESFULL" --msgbox "The script has succesfully completed the Elastic SIEM installation process. Check if the software works fine, or use the official documentation to fix any problems." 9 78
infu "The istallation has succesfully completed!"
echo "==============================================================================================================================================================="
infu "The application web interface is now available at https://${IPADDR}:${KIBPORT}"
infu "Make sure to enable ports 5044, 5055 and ${KIBPORT} on this machine's firewall!"
infu "For full functionality of the system, security rules have to be imported manually. Please refer to the included documentation in the README.md file or the official documentation."
infu "Elastic Agents manual installation process can also be found in the included documentation in the README.md file or the official documentation"
echo "==============================================================================================================================================================="
echo "Here you can see the passwords for the system internal passwords. THIS IS THE ONLY TIME THEY WILL BE SHOWN TO YOU. It is advised to copy them to a secure location, so that you can use them if you need to."
echo "KIBANA SYSTEM PASSWORD: ${KIBSPASS}"
echo "LOGSTASH INTERNAL PASSWORD: ${LOGIPASS}"
exit 0
