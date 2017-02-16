#!/bin/bash
# Usage: ./share.sh file encryption_key

E_BADARGS=65

TRANSFER_SH_URL="https://transfer.sh"
MAX_DOWNLOADS=1
DAYS_BEFORE_EXPIRATION=1
TMP_FILE="/tmp/$(basename $0).$$.tmp"

# Will be set to 1 if a file is to be downloaded instead of uploaded.
RETRIEVE_MODE=0

###############################################################################

function usage()
{
    echo "`basename $0` is a simple script which facilitates secure file transfers."
    echo
    echo "Upload a file:"
    echo " `basename $0` [-m max_downloads] [-d days_before_expiration] file encryption_key"
    echo " Example: `basename $0` -m 1 -d 5 ~/secrets.txt \"The!Encryption!Key\""
    echo
    echo "Retrieve a file:"
    echo " `basename $0` -r file encryption_key URL"
}

###############################################################################

# Checks for torify, curl and wget presence.
function detect_capabilities()
{
    TORIFY_PRESENT=0
    CURL_PRESENT=1
    WGET_PRESENT=1

    # Check which commands are available on the system.
    command -v torify >/dev/null 2>&1 || TORIFY_PRESENT=0
    command -v curl >/dev/null 2>&1   || CURL_PRESENT=0
    command -v wget >/dev/null 2>&1   || WGET_PRESENT=0

    # Default to the onion URL if torify is present on the system.
    if [ ${TORIFY_PRESENT} -eq 1 ] ; then
            PROXY_COMMAND="torify"
    else
            PROXY_COMMAND=""
    fi

    if [ ${CURL_PRESENT} -eq 0 ] && [ ${WGET_PRESENT} -eq 0 ] ; then
        echo "Error: neither curl nor wget could be found!"
        exit 1
    fi
}

###############################################################################

# Uploads the target file to transfer.sh. Uses either wget or curl depending on
# what is available on the system.
function upload()
{
    # Compress and encrypt the target file.
    gzip -c $1 | openssl enc -aes-256-cbc -k $2 -out ${TMP_FILE}

    # Upload the file.
    if [ ${CURL_PRESENT} -eq 1 ] ; then
        URL=`${PROXY_COMMAND} curl -s -H "Max-Downloads: ${MAX_DOWNLOADS}" -H "Max-Days: ${DAYS_BEFORE_EXPIRATION}" --upload-file ${TMP_FILE} ${TRANSFER_SH_URL}/$$`
    elif [ ${WGET_PRESENT} -eq 1 ] ; then
        URL=`${PROXY_COMMAND} wget -qO- --header="Max-Downloads: ${MAX_DOWNLOADS}" --header="Max-Days: ${DAYS_BEFORE_EXPIRATION}" --method=PUT --body-file=${TMP_FILE} ${TRANSFER_SH_URL}/$$`
    fi

    # Verify that the file was uploaded successfully.
    if [ ! $? -eq 0 ] ; then
        echo "Error uploading $1."
        rm ${TMP_FILE}
        exit 1
    fi

    rm ${TMP_FILE}
    echo -e "Success! Retrieval command: $0 -r $(basename $1) \"$2\" ${URL}"
    exit 0
}

###############################################################################

# Downloads, decrypts and decompresses the file pointed by a URL.
# Usage: download destination_file decryption_key url
function download()
{
    # This function has lackluster error handling.
    if [ ${CURL_PRESENT} -eq 1 ] ; then
        ${PROXY_COMMAND} curl -s $3 | openssl enc -d -aes-256-cbc -k $2 | gunzip > $1
    elif [ ${WGET_PRESENT} -eq 1 ] ; then
        ${PROXY_COMMAND} wget -qO- $3 | openssl enc -d -aes-256-cbc -k $2 | gunzip > $1
    fi

    if [ $? -eq 0 ] ; then
        echo "File retrieved successfully!"
    else
        rm $1 # Delete the empty or corrupted file which was created.
    fi
}

###############################################################################

# Assert that there are enough arguments or print usage.
if [ $# -lt 2 ] ; then
  usage
  exit ${E_BADARGS}
fi

while getopts ":rd:m:h" opt; do
    case "$opt" in
        r)
            RETRIEVE_MODE=1
            ;;
        h)
            usage
            exit 0
            ;;
        m)
            MAX_DOWNLOADS=${OPTARG}
            ;;
        d)
            DAYS_BEFORE_EXPIRATION=${OPTARG}
            ;;
        \?)
            echo "Invalid option: -${OPTARG}. Use -h for help." >&2
            exit ${E_BADARGS}
            ;;
    esac
done

# Upload mode: verify that the target file exists.
if [ ! -e ${@:$OPTIND:1} ] && [ ${RETRIEVE_MODE} -eq 0 ] ; then
    echo "${@:$OPTIND:1} not found."
    exit ${E_BADARGS}
fi

# Retrieve mode: assert that the target file doesn't already exist.
if [ -e ${@:$OPTIND:1} ] && [ ${RETRIEVE_MODE} -eq 1 ] ; then
    echo "Error: ${@:$OPTIND:1} already exists and would be overwritten."
    exit ${E_BADARGS}
fi

detect_capabilities

# Launch download or upload.
if [ ${RETRIEVE_MODE} -eq 0 ] ; then
    upload ${@:$OPTIND:2}
else
    download ${@:$OPTIND:3}
fi