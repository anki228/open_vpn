#!/bin/bash -e

APP=$(basename $0)
LOCKFILE="/tmp/$APP.lock"

trap "rm -f ${LOCKFILE}; exit" INT TERM EXIT
if ! ln -s $APP $LOCKFILE 2>/dev/null; then
    echo "ERROR: script LOCKED" >&2
    exit 15
fi

function usage {
  echo "Usage: $0 [<options>] [command [arg]]"
  echo "Options:"
  echo " -i : Init (Create server keys and configs)"
  echo " -c : Create new user"
  echo " -d : Delete user" 
  echo " -u <user> : User identifier (uniq field for vpn account)"
  echo " -s <server> : Server host for user connection"
  echo " -p : Print user config"
  echo " -h : Usage"
  exit 1
}

unset USER
umask 0077

HOME_DIR="/etc/openvpn"
EASY_RSA_DIR="/etc/openvpn/easy-rsa"
SERVER_NAME="server"

while getopts ":icdpu:s:h" opt; do
  case $opt in
     i) INIT=1 ;;
     c) CREATE=1 ;;
     d) DELETE=1 ;;
     p) PRINT_USER_CONFIG=1 ;;
     u) USER="$OPTARG" ;;
     s) SERVER_ENDPOINT="$OPTARG" ;;
     h) usage ;;
    \?) echo "Invalid option: -$OPTARG" ; exit 1 ;;
     :) echo "Option -$OPTARG requires an argument" ; exit 1 ;;
  esac
done

[ $# -lt 1 ] && usage

function init {
    if [ -z "$SERVER_ENDPOINT" ]; then
        echo "ERROR: Server host required" >&2
        exit 1
    fi

    if [ -f "$HOME_DIR/server.conf" ]; then
        echo "Server already initialized"
        exit 0
    fi

    # Save server endpoint
    echo "$SERVER_ENDPOINT" > "$HOME_DIR/.server"

    # Setup Easy-RSA
    if [ ! -d "$EASY_RSA_DIR" ]; then
        make-cadir "$EASY_RSA_DIR"
        cd "$EASY_RSA_DIR" || exit 1
        
        # Create fresh vars file with default values
        cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY     "US"
set_var EASYRSA_REQ_PROVINCE    "California"
set_var EASYRSA_REQ_CITY        "San Francisco"
set_var EASYRSA_REQ_ORG         "OpenVPN"
set_var EASYRSA_REQ_EMAIL       "admin@example.com"
set_var EASYRSA_REQ_OU          "OpenVPN"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_ALGO            ec
set_var EASYRSA_CURVE           prime256v1
set_var EASYRSA_CA_EXPIRE       3650
set_var EASYRSA_CERT_EXPIRE     3650
EOF

        # Initialize PKI
        ./easyrsa init-pki
        echo -e "\n\n" | ./easyrsa build-ca nopass
        ./easyrsa gen-dh
        ./easyrsa build-server-full server nopass
        ./easyrsa gen-crl
        
        # Generate TLS key
        openvpn --genkey --secret "$HOME_DIR/tls-crypt.key"
    fi

    # Create server config
    cat > "$HOME_DIR/server.conf" <<EOF
port 1194
proto udp
dev tun
ca $EASY_RSA_DIR/pki/ca.crt
cert $EASY_RSA_DIR/pki/issued/$SERVER_NAME.crt
key $EASY_RSA_DIR/pki/private/$SERVER_NAME.key
dh $EASY_RSA_DIR/pki/dh.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-crypt $HOME_DIR/tls-crypt.key
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
explicit-exit-notify 1
EOF

    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p

    # Enable and start service
    systemctl enable openvpn@server
    systemctl start openvpn@server

    echo "Server initialized successfully"
    exit 0
}

function create_user {
    if [ -z "$USER" ]; then
        echo "ERROR: User name required" >&2
        exit 1
    fi

    cd "$EASY_RSA_DIR" || exit 1
    
    # Check if user already exists
    if [ -f "pki/issued/$USER.crt" ]; then
        echo "User $USER already exists"
        exit 0
    fi
    
    # Create user certificate
    ./easyrsa build-client-full "$USER" nopass
    
    # Generate client config
    SERVER_PUBLIC_IP=$(cat "$HOME_DIR/.server" 2>/dev/null || echo "$SERVER_ENDPOINT")
    
    cat > "$HOME_DIR/client-configs/$USER.ovpn" <<EOF
client
dev tun
proto udp
remote $SERVER_PUBLIC_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
verb 3
<ca>
$(cat "$EASY_RSA_DIR/pki/ca.crt")
</ca>
<cert>
$(openssl x509 -in "$EASY_RSA_DIR/pki/issued/$USER.crt")
</cert>
<key>
$(cat "$EASY_RSA_DIR/pki/private/$USER.key")
</key>
<tls-crypt>
$(cat "$HOME_DIR/tls-crypt.key")
</tls-crypt>
EOF

    echo "User $USER created successfully"
}

function delete_user {
    if [ -z "$USER" ]; then
        echo "ERROR: User name required" >&2
        exit 1
    fi

    cd "$EASY_RSA_DIR" || exit 1
    
    # Revoke certificate
    if [ -f "pki/issued/$USER.crt" ]; then
        ./easyrsa revoke "$USER"
        ./easyrsa gen-crl
        cp pki/crl.pem "$HOME_DIR/crl.pem"
        chmod 644 "$HOME_DIR/crl.pem"
    fi
    
    # Remove config file
    rm -f "$HOME_DIR/client-configs/$USER.ovpn"
    
    echo "User $USER deleted successfully"
}

cd "$HOME_DIR" || exit 1

# Create necessary directories
mkdir -p "$HOME_DIR/client-configs"

if [ $INIT ]; then
    init
    exit 0
fi

if [ ! -f "$EASY_RSA_DIR/pki/issued/$SERVER_NAME.crt" ]; then
    echo "ERROR: Run init script before" >&2
    exit 2
fi

if [ -z "${USER}" ] && [ $CREATE ] || [ $DELETE ] || [ $PRINT_USER_CONFIG ]; then
    echo "ERROR: User required" >&2
    exit 1
fi

if [ $CREATE ]; then
    create_user
fi

if [ $DELETE ]; then
    delete_user
fi

if [ $PRINT_USER_CONFIG ]; then
    if [ ! -f "$HOME_DIR/client-configs/$USER.ovpn" ]; then
        echo "ERROR: User config not found" >&2
        exit 1
    fi
    cat "$HOME_DIR/client-configs/$USER.ovpn"
fi

exit 0
