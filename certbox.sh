#!/bin/bash

: <<USAGE
$0 helps with certificate updates.

OS integration commands:

$0 validate_update <CERT_FILE> <HOSTNAME> [<PORTNAME>] downloads a new certificate, validates, and checks if update is needed

$0 update_etc <HOSTNAME> [<PORTNAME=443>]

Will download, verify, and update certificate at /etc/ssl/<HOSTNAME>

$0 init <HOSTNAME> [<PORTNAME=443>]

Script install itself into running OS, schedule daily updates for <HOSTNAME>

$0 update_etc <HOSTNAME> [<PORTNAME=443>]
USAGE

####################

# usage generation
usage () {
    local SUFFIX=""
    if [[ -n "$1" ]] ; then SUFFIX="_$1" ; fi
    if [[ -n "$2" ]] ; then echo "$2" ; fi # the reason why usage shown
    local ESC_CMD="${0//\//\\\/}"
    echo

    sed -ne "/USAGE$SUFFIX\$/,/^USAGE$SUFFIX\$/p" "$0" | sed "s/\$0/$ESC_CMD/g" | grep -v "USAGE$SUFFIX"; echo ; exit "${3:-1}";
}

if [[ "$1" == "-h"  || "$1" == "--help" || "$1" == "help" ]] ; then
    usage
fi

if [[ "$2" == "-h" || "$2" == "--help" ]] ; then
    usage "$1"
fi

########################
# platform differences #
########################

ETC_CERT_DIR=/etc/ssl/certs

UNAME=$(uname -s)

case "$UNAME" in
    Linux*)     
        QUIET_OPT="-verify_quiet"
        DATE_FLAGS="-u"
        DATE_PARSE_FORMAT="-d" # bit hacky, but linux parses time string from openssl just fine
        TAC_CMD=tac
        ;;
    Darwin*)    
        # QUIET_OPT="-quiet"
        DATE_FLAGS="-ujf"
        DATE_PARSE_FORMAT="%b %e %H:%M:%S %Y %Z"
        TAC_CMD="tail -r"
        ;;
esac

date_format () {
    DATE="$1"
    FORMAT="$2"

    if [[ -z "$DATE_PARSE_FORMAT" ]] ; then
        date "$DATE_FLAGS" "$DATE" "$FORMAT"
    else
        date "$DATE_FLAGS" "$DATE_PARSE_FORMAT" "$DATE" "$FORMAT"
    fi
}

date_difference () {
    DATE1="$1"
    DATE2="$2"
    # macos cert date parse
    # date -ujf "%b %e %H:%M:%S %Y %Z" "<DATE>" +"%Y-%m-%d %H:%M:%S"

    # linux
    # date -d "<DATE>" '+%s'
    
    SECONDS1=$(date_format "$DATE1" '+%s')
    SECONDS2=$(date_format "$DATE2" '+%s')

    SECONDS_DIFF=$(( SECONDS1 - SECONDS2 ))

    echo "$SECONDS_DIFF"

}

########################
# certificate download #
########################
: <<USAGE_download_cert
Usage: $0 download <HOSTNAME> [<PORT>]

Download certificate chain from host.

Examples:

$0 download site.com

USAGE_download_cert

download_cert () {
    HOSTNAME=$1
    PORTNUM=${2:-443}
    
    S_CLIENT_OPTIONS="$QUIET_OPT -connect $HOSTNAME:$PORTNUM -servername $HOSTNAME"

    # openssl s_client $S_CLIENT_OPTIONS 2>&1 </dev/null | openssl x509 2>/dev/null 1>$HOSTNAME.pem

    openssl s_client $S_CLIENT_OPTIONS -showcerts 2>&1 </dev/null | sed -n -e '/-.BEGIN/,/-.END/ p' 2>/dev/null

    return;

    CERT_CHAIN="$(<"$HOSTNAME".full.pem)"

    CERT_DOWNLOADED="$(<"$HOSTNAME".pem)"

    CERT_ONLY="${CERT_CHAIN%%-----END CERTIFICATE-----*}-----END CERTIFICATE-----"
    # BEFORE_CERTS="${BEFORE_CERTS%-----BEGIN CERTIFICATE-----*}"

    echo ""
    echo "111111111"

    echo "$CERT_DOWNLOADED"

    echo "222222222"

    echo "$CERT_ONLY"

    echo "333333333"

    if [[ "$CERT_DOWNLOADED" == "$CERT_ONLY" ]] ; then
        echo "the same"
    else
        echo "differs"
    fi

}

# strips all but site certificate from certificate chain
strip_chain () {
    CERT_CHAIN="$1"
    CERT_ONLY="${CERT_CHAIN%%-----END CERTIFICATE-----*}-----END CERTIFICATE-----"
    echo "$CERT_ONLY"
}

# basically it is the same as sed -n -e '/-.BEGIN/,/-.END/ p', but without sed
cert_clean () {
    local NEW_CERT_BUNDLE="$1"
    CLEAN_START_CERTS="-----BEGIN CERTIFICATE-----${NEW_CERT_BUNDLE#*-----BEGIN CERTIFICATE-----}"
    CLEAN_AROUND_CERTS="${CLEAN_START_CERTS%-----END CERTIFICATE-----*}-----END CERTIFICATE-----"

    local LOOP_CERT=
    local BEFORE_CERTS="$CLEAN_AROUND_CERTS"
    local CERT_CLEAN=

    while [ "$LOOP_CERT" != "$BEFORE_CERTS" ] ; do
        LOOP_CERT="-----BEGIN CERTIFICATE-----${BEFORE_CERTS##*-----BEGIN CERTIFICATE-----}"
        if [ -z "$CERT_CLEAN" ] ; then
            CERT_CLEAN="$LOOP_CERT"
        else
            CERT_CLEAN="$LOOP_CERT\
$CERT_CLEAN"
        fi
        DIRTY_BEFORE_CERTS="${BEFORE_CERTS%-----BEGIN CERTIFICATE-----*}"
        BEFORE_CERTS="${DIRTY_BEFORE_CERTS%-----END CERTIFICATE-----*}-----END CERTIFICATE-----"
    done

    echo "$CERT_CLEAN"
}

: <<USAGE_validate_update

$0 validate_update <CERT_FILE> <HOSTNAME> [<PORTNAME>] downloads a new certificate, validates, and checks if update is needed

Verify possible certificate update against locally stored certificate.

CERT_FILE is a certificate filename, '/etc/ssl/certs' will be prepended if file is missing from the current directory

HOSTNAME is a hostname to source a certificate. It can be omitted if CERT_FILE basename equals HOSTNAME

Examples:

$0 validate_update site.com

Will download a certificate from https://site.com, checks if local certificate from '/etc/ssl/certs/site.com' has the same key, certificate chain is valid, and remote certificate have a later expiration date that a local one.

Zero exit code means that certificate can be updated,
Local certificate file is missing            - 1,
Certificate download problem                 - 2,
Key for local certificate and remote differs - 3,
Problem with certificate chain               - 4,
Remote certicate is not newer that local one - 5.

USAGE_validate_update

validate_update () {

    local CERT_FILENAME="$1"
    local HOSTNAME="${2:-${CERT_FILENAME##*/}}"
    local PORTNUM=${3:-443}

    local NEW_CERT_BUNDLE="${4:-}"

    if [[ ! -f "$CERT_FILENAME" ]] && [[ -f "$ETC_CERT_DIR/$CERT_FILENAME" ]] ; then
        CERT_FILENAME="$ETC_CERT_DIR/$CERT_FILENAME"
    fi

    # TODO: assert
    if [[ ! -f "$CERT_FILENAME" ]] ; then
        usage "verify" "Error: No certificate file" 1;
    fi
    
    # 1. download cert from some resource within the same domain

    if [[ -z "$NEW_CERT_BUNDLE" ]] ; then
        NEW_CERT_BUNDLE=$(download_cert "$HOSTNAME" "$PORTNUM")
    fi

    if [[ -z "$NEW_CERT_BUNDLE" ]] ; then
        usage "verify" "Error: Certificate download problem, use following cmd to figure out what's happening: command openssl s_client -verify_quiet -connect $HOSTNAME:$PORTNUM -servername $HOSTNAME -showcerts 2>&1 </dev/null" 2;
    fi

    NEW_CERT=$(strip_chain "$NEW_CERT_BUNDLE")

    # 2. check if this cert matches existing private key

    # cert modulus
    NEW_CERT_MODULUS=$(openssl x509 -modulus -noout -in <(echo -e "$NEW_CERT") | openssl md5)

    # if [[ -n "$VERBOSE" ]] ; then echo "Certificate modulus:  $NEW_CERT_MODULUS" ; fi

    # pri key modulus
    # openssl rsa -noout -modulus -in cs_privkey.txt | openssl md5

    # pub key modulus
    # openssl rsa -pubin -noout -modulus -in pub_key.txt | openssl md5

    LOCAL_MODULUS=$(openssl rsa -pubin -noout -modulus -in <(openssl x509 -pubkey -noout -in "$CERT_FILENAME") | openssl md5)

    # if [[ -n "$VERBOSE" ]] ; then echo "Local pubkey modulus: $LOCAL_MODULUS" ; fi

    if [[ "$NEW_CERT_MODULUS" != "$LOCAL_MODULUS" ]] ; then
        echo "Error: remote certificate and local one have different key,"
        echo "CA may be compromised, possible MitM attack after certificate install."
        echo "Local modulus: $LOCAL_MODULUS Remote modulus: $NEW_CERT_MODULUS"
        echo "Cannot continue."
        exit 3
    fi

    # 3. check if this cert have proper certificate chain

    # echo "$NEW_CERT_BUNDLE"

    # Sometimes certificates contains extra data before, after, and between BEGIN/END blocks
    CLEAN_START_CERTS="-----BEGIN CERTIFICATE-----${NEW_CERT_BUNDLE#*-----BEGIN CERTIFICATE-----}"
    CLEAN_AROUND_CERTS="${CLEAN_START_CERTS%-----END CERTIFICATE-----*}-----END CERTIFICATE-----"

    # echo "$CLEAN_AROUND_CERTS"

    LOOP_CHAIN=
    LOOP_CERT=
    PREV_CERT=
    BEFORE_CERTS="$NEW_CERT_BUNDLE"

    while true ; do
        LOOP_CERT="-----BEGIN CERTIFICATE-----${BEFORE_CERTS##*-----BEGIN CERTIFICATE-----}"
        DIRTY_BEFORE_CERTS="${BEFORE_CERTS%-----BEGIN CERTIFICATE-----*}"
        BEFORE_CERTS="${DIRTY_BEFORE_CERTS%-----END CERTIFICATE-----*}-----END CERTIFICATE-----"

        CERT_SUBJ="$(echo "$LOOP_CERT" | openssl x509 -noout -subject | tr -d ' ')"
        CN="${CERT_SUBJ#*CN=}"

        # https://stackoverflow.com/questions/63827480/openssl-error-20-at-0-depth-lookupunable-to-get-local-issuer-certificate
        # openssl x509 -subject -subject_hash -noout -in rootca.crt
        # openssl x509 -issuer -issuer_hash -noout -in intermediateca.crt

        if [ -z "$LOOP_CHAIN" ] ; then
            # VERIFY=$(echo "${LOOP_CERT}" | openssl verify -verbose -CApath /no-such-dir -x509_strict 2>&1)
            LOOP_CHAIN="$LOOP_CERT"
        else
            VERIFY=$(echo "${LOOP_CERT}" | openssl verify -verbose -CAfile <(echo -e "$LOOP_CHAIN") -CApath /no-such-dir -x509_strict 2>&1)
            LOOP_CHAIN="$LOOP_CERT$LOOP_CHAIN"

            # openssl verify won't work on my mac, so I'm doing manual certificate validation

            SUBJECT_CN_STR=$(echo "$PREV_CERT" | openssl x509 -noout -subject)
            SUBJECT_CN="${SUBJECT_CN_STR#subject=}"
            SUBJECT_HASH=$(echo "$PREV_CERT" | openssl x509 -noout -subject_hash)
            ISSUER_CN_STR=$(echo "$LOOP_CERT" | openssl x509 -noout -issuer)
            ISSUER_CN="${ISSUER_CN_STR#issuer=}"
            ISSUER_HASH=$(echo "$LOOP_CERT" | openssl x509 -noout -issuer_hash)

            # if [[ -n "$VERBOSE" ]] ; then
            #     echo "ISSUER:  $ISSUER_HASH $ISSUER_CN"
            #     echo "SUBJECT: $SUBJECT_HASH $SUBJECT_CN"
            # fi

            if [[ "$ISSUER_HASH" != "$SUBJECT_HASH" ]] ; then
                echo "Error: certificate chain incorrect, previous certificate subject hash"
                echo "is not equal to the current certificate issuer hash"
                echo "Cannot continue."
                exit 4
            fi

            if [[ "$ISSUER_CN" != "$SUBJECT_CN" ]] ; then
                echo "Error: certificate chain incorrect, previous certificate subject CN = $SUBJECT_CN"
                echo "is not equal to the current certificate issuer CN = $ISSUER_CN"
                echo "Cannot continue."
                exit 4
            fi

        fi

        if [ "$BEFORE_CERTS" == "-----END CERTIFICATE-----" ] ; then
            break;
        fi

        PREV_CERT="$LOOP_CERT"

        # echo "$CN >>> $VERIFY"

        # echo "$LOOP_CHAIN"
    done

    ########################################

    # 4. check if remote cert is newer than existing local certificate

    REMOTE_CERT_DATE=$(openssl x509 -enddate -noout -in <(echo -e "$NEW_CERT") | cut -d= -f 2)

    LOCAL_CERT_DATE=$(openssl x509 -enddate -noout -in "$CERT_FILENAME" | cut -d= -f 2)

    DATES_DIFF=$(date_difference "$REMOTE_CERT_DATE" "$LOCAL_CERT_DATE")

    if (( DATES_DIFF <= 0 )) ; then
        echo "Note: local certificate ($LOCAL_CERT_DATE) is newer or same than remote ($REMOTE_CERT_DATE), no need to update"

        exit 5
    fi

}

update_cert_etc () {

    set -u
    set -e

    local CERT_FILENAME="$1"
    local HOSTNAME="${2:-${CERT_FILENAME##*/}}"
    local PORTNUM=${3:-443}
    local NEW_CERT_BUNDLE="${4:-}"

    local CERT_DATE_SUFFIX=

    if [[ ! -f "$CERT_FILENAME" ]] && [[ -f "$ETC_CERT_DIR/$CERT_FILENAME" ]] ; then
        CERT_FILENAME="$ETC_CERT_DIR/$CERT_FILENAME"
    fi

    if [[ ! -f "$CERT_FILENAME" ]] ; then
        usage "verify" "Error: No certificate file" 1;
    fi
    
    if [[ ! -L "$CERT_FILENAME" ]] ; then
        local LOCAL_CERT="$(<"$CERT_FILENAME")"
        CERT_DATE_SUFFIX="$(get_cert_enddate "$LOCAL_CERT")"
        cp "$CERT_FILENAME" "$CERT_FILENAME.$CERT_DATE_SUFFIX"
        ln -fs "${CERT_FILENAME##*/}.$CERT_DATE_SUFFIX" "$CERT_FILENAME"
        CERT_DATE_SUFFIX=
    fi

    if [[ -z "$NEW_CERT_BUNDLE" ]] ; then
        NEW_CERT_BUNDLE="$(download_cert "$HOSTNAME" "$PORTNUM")"
    fi

    local NEW_CERT=
    NEW_CERT="$(strip_chain "$NEW_CERT_BUNDLE")"

    #local NEW_CERT_CHAIN=
    #NEW_CERT_CHAIN="$(get_chain "$NEW_CERT_BUNDLE")"

    echo "Validating update"

    # why it not works?
    # validate_update "$CERT_FILENAME" "$HOSTNAME" "$PORTNUM" "$NEW_CERT_BUNDLE"
    VALIDATION_ERR="$(validate_update "$CERT_FILENAME" "$HOSTNAME" "$PORTNUM" "$NEW_CERT_BUNDLE")"
    VALIDATION_EXIT_CODE=$?
    if [ $VALIDATION_EXIT_CODE -ne 0 ]; then
        echo "$VALIDATION_ERR"
        exit "$VALIDATION_EXIT_CODE"
    fi

    echo "Validation ok"

    CERT_DATE_SUFFIX="$(get_cert_enddate "$NEW_CERT_BUNDLE")"
    echo "$NEW_CERT_BUNDLE" >"$CERT_FILENAME.bundle.$CERT_DATE_SUFFIX"
    ln -fs "$(basename "$CERT_FILENAME").bundle.$CERT_DATE_SUFFIX" "$CERT_FILENAME.bundle"

    echo "$NEW_CERT" >"$CERT_FILENAME.$CERT_DATE_SUFFIX"
    ln -fs "$(basename "$CERT_FILENAME").$CERT_DATE_SUFFIX" "$CERT_FILENAME"

    set +e
    set +u

    exit 1

    update_cert "$CERT_FILENAME" "$HOSTNAME" "$PORTNUM"
}

get_cert_enddate () {
    local CERT="$1"
    local CERT_DATE=
    local CERT_DATE_SUFFIX=

    CERT_DATE="$(openssl x509 -enddate -noout -in <(echo -e "$CERT") | cut -d= -f 2)"
    CERT_DATE_SUFFIX="$(date_format "$CERT_DATE" "+%Y-%m-%d.%H:%M:%S")"
    echo "$CERT_DATE_SUFFIX"
}

fix_cert_filename () {
    local CERT_FILENAME="$1"
    if [ ! -L "$CERT_FILENAME" ] ; then
        CERT="$(strip_chain "$NEW_CERT_BUNDLE")"

        CERT_DATE_SUFFIX="$(get_cert_enddate "$CERT")"
        # echo "$CERT_DATE_SUFFIX"

        echo "$NEW_CERT_BUNDLE" >"$CERT_FILENAME.$CERT_DATE_SUFFIX"
        ln -fs "$CERT_FILENAME.$CERT_DATE_SUFFIX" "$CERT_FILENAME"
    fi
}

update_cert () {
    # check if key exists
    # validate cert against the key

    CERT_FILENAME="$1"
    HOSTNAME="$2"
    PORTNUM=${3:-443}

    # download
    NEW_CERT_BUNDLE=$(cert_download "$HOSTNAME" "$PORTNUM")

    # TODO: assert
    if [[ ! -f "$CERT_FILENAME" ]] ;     then usage "update" "Error: No certificate file" 1;  exit 1 ; fi
    if [[ -z "$HOSTNAME" ]] ;            then usage "update" "Error: No hostname provided" 1; exit 1 ; fi
    
    # validate
    cert_verify "$CERT_FILENAME" "$HOSTNAME" "$PORTNUM" "$NEW_CERT_BUNDLE"

    CERT=$(strip_chain "$NEW_CERT_BUNDLE")

    CERT_DATE_SUFFIX="$(get_cert_enddate "$CERT")"
    # echo "$CERT_DATE_SUFFIX"

    echo "$NEW_CERT_BUNDLE" >"$CERT_FILENAME.$CERT_DATE_SUFFIX"
    ln -fs "$CERT_FILENAME.$CERT_DATE_SUFFIX" "$CERT_FILENAME"
    # echo "$NEW_CERT_BUNDLE" >"$CERT_FILENAME"

    # sudo cp ${HOSTNAME}.full.pem /etc/ssl/private/${HOSTNAME}
    # sudo cp ${HOSTNAME}.pem /etc/ipsec.d/certs/${HOSTNAME}

    # sudo systemctl restart nginx
    # sudo systemctl restart haproxygw

    # sudo ipsec restart

    exit;
}

METHOD=$1
ELEVATED=$([ "${CMD%%-elevated}" = "$CMD" ] && echo "NO" || echo "ELEVATED")



if [[ $METHOD == "download" ]] ; then
    cert_download "$2" "$3"
elif [[ $METHOD == "validate_update" ]] ; then
    validate_update "$2" "$3" "$4"
else
    # if [[ "$ELEVATED" == "ELEVATED" ]] ; then
        if [[ $METHOD == "update_etc" ]] ; then
            update_cert_etc "$2" "$3" "$4" "$5"
        elif [[ $METHOD == "update" ]] ; then
            cert_update "$2" "$3" "$4"
        fi
    #else
    #    exit 1
    #fi
fi
