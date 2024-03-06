!/bin/bash
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;35m'
NC='\033[0m'
success=0
fail=0
yum update -y && yum install wget -y
#################################################################
#Ensure permissions on /etc/ssh/sshd_config are configured
echo
echo -e "${RED}1.${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
chown root:root /etc/ssh/sshd_config && chmod og-rwx /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/ssh/sshd_config are
configured"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/ssh/sshd_config
are configured"
 fail=$((fail + 1))
fi

#Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${RED}2.${NC} Ensure SSH IgnoreRhosts is enabled"
egrep -q "^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\1IgnoreRhosts yes\2/" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH IgnoreRhosts is enabled"
  fail=$((fail + 1))
fi

#Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${RED}3.${NC} Ensure SSH HostbasedAuthentication is disabled"
egrep -q "^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\1HostbasedAuthentication no\2/" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH HostbasedAuthentication is disabled"
  fail=$((fail + 1))
fi


#Ensure SSH root login is disabled
echo
echo -e "${RED}4.${NC} Ensure SSH root login is disabled"
egrep -q "^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\1PermitRootLogin no\2/" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH root login is disabled"
  fail=$((fail + 1))
fi
 
#Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${RED}5.${NC} Ensure SSH PermitEmptyPasswords is disabled"
egrep -q "^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\1PermitEmptyPasswords no\2/" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitEmptyPasswords is disabled"
  fail=$((fail + 1))
fi
#Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${RED}6.${NC} Ensure SSH PermitUserEnvironment is disabled"
egrep -q "^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)PermitUserEnvironment\s+\S+(\s*#.*)?\s*$/\1PermitUserEnvironment no\2/" /etc/ssh/sshd_config || echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disabled"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH PermitUserEnvironment is disabled"
  fail=$((fail + 1))
fi
#Ensure only approved MAC algorithms are used
echo
echo -e "${RED}7.${NC} Ensure only approved MAC algorithms are used"
egrep -q "^(\s*)MACs\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)MACs\s+\S+(\s*#.*)?\s*$/\1MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\2/" /etc/ssh/sshd_config || echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure only approved MAC algorithms are used"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure only approved MAC algorithms are used"
  fail=$((fail + 1))
fi

#Ensure SSH Idle Timeout Interval is configured
echo
echo -e "${RED}5.2.12${NC} Ensure SSH Idle Timeout Interval is configured"
egrep -q "^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\1ClientAliveInterval 300\2/" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
egrep -q "^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\1ClientAliveCountMax 0\2/" /etc/ssh/sshd_config || echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH Idle Timeout Interval is configured"
success=$((success + 1))
#Ensure SSH LoginGraceTime is set to one minute or less
echo
echo -e "${RED}5.2.13${NC} Ensure SSH LoginGraceTime is set to one minute or less"
egrep -q "^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$" /etc/ssh/sshd_config && sed -ri "s/^(\s*)LoginGraceTime\s+\S+(\s*#.*)?\s*$/\1LoginGraceTime 60\2/" /etc/ssh/sshd_config || echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
  echo -e "${GREEN}Remediated:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  success=$((success + 1))
else
  echo -e "${RED}UnableToRemediate:${NC} Ensure SSH LoginGraceTime is set to one minute or less"
  fail=$((fail + 1))
fi
#Ensure permissions on /etc/passwd are configured
echo
echo -e "${RED}10.${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd && chmod 644 /etc/passwd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are
configured"
 success=$((success + 1))
else
17
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd are
configured"
 fail=$((fail + 1))
fi
#Ensure permissions on /etc/shadow are configured
echo
echo -e "${RED}11.${NC} Ensure permissions on /etc/shadow are configured"
chown root:root /etc/shadow && chmod 000 /etc/shadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are
configured"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow are
configured"
 fail=$((fail + 1))
fi
#Ensure permissions on /etc/group are configured
echo
echo -e "${RED}12.${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group && chmod 644 /etc/group
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are
configured"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/group are
configured"
 fail=$((fail + 1))
fi
#Ensure permissions on /etc/gshadow are configured
echo
echo -e "${RED}13.${NC} Ensure permissions on /etc/gshadow are configured"
chown root:root /etc/gshadow && chmod 000 /etc/gshadow
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are
configured"
 success=$((success + 1))
else
18
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/gshadow are
configured"
 fail=$((fail + 1))
fi
#Ensure permissions on /etc/passwd- are configured
echo
echo -e "${RED}14.${NC} Ensure permissions on /etc/passwd- are configured"
chown root:root /etc/passwd- && chmod u-x,go-wx /etc/passwd▒policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are
configured"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/passwd- are
configured"
 fail=$((fail + 1))
fi
#Ensure permissions on /etc/shadow- are configured
echo
echo -e "${RED}15.${NC} Ensure permissions on /etc/shadow- are configured"
chown root:root /etc/shadow- && chmod 000 /etc/shadow▒policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are
configured"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure permissions on /etc/shadow- are
configured"
 fail=$((fail + 1))
fi

#Ensure password expiration is 365 days or less
echo
echo -e "${RED}5.4.1.1${NC} Ensure password expiration is 365 days or less"
egrep -q "^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 90\2/" /etc/login.defs || echo "PASS_MAX_DAYS 90" >> /etc/login.defs
getent passwd | cut -f1 -d ":" | xargs -n1 chage --maxdays 90
echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 365 days or less"
success=$((success + 1))
#Ensure Samba is not enabled
echo
echo -e "${RED}17.${NC} Ensure Samba is not enabled"
systemctl disable smb
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure Samba is not enabled"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure Samba is not enabled"
 fail=$((fail + 1))
fi
#Ensure HTTP server is not enabled
echo
echo -e "${RED}18.${NC} Ensure HTTP server is not enabled"
systemctl disable httpd
policystatus=$?
if [[ "$policystatus" -eq 0 ]]; then
 echo -e "${GREEN}Remediated:${NC} Ensure HTTP server is not enabled"
 success=$((success + 1))
else
 echo -e "${RED}UnableToRemediate:${NC} Ensure HTTP server is not enabled"
 fail=$((fail + 1))
fi
#################################################################
echo
echo -e "${GREEN}Remediation script for CentOS Linux 7 executed successfully!!${NC}"
echo
echo -e "${YELLOW}Summary:${NC}"
echo -e "${YELLOW}Remediation Passed:${NC} $success"
echo -e "${YELLOW}Remediation Failed:${NC} $fail"