#!/bin/bash
#
# FENRIR
# Simple Bash IOC Checker
# Florian Roth

VERSION="0.5.2"

# Settings ------------------------------------------------------------

SYSTEM_NAME=$(uname -n | tr -d "\n")

# IOCs
HASH_IOC_FILE="./hash-iocs.txt"
STRING_IOCS="./string-iocs.txt"
FILENAME_IOCS="./filename-iocs.txt"
C2_IOCS="./c2-iocs.txt"

# Log
LOG_FILE="./fenrir_$SYSTEM_NAME.log"
LOG_TO_FILE=1
LOG_TO_SYSLOG=0 # Log to syslog is set to 'off' by default > false positives
LOG_TO_CMDLINE=1
SYSLOG_FACILITY=local4

# Disable Checks
DO_C2_CHECK=1

# Exclusions
MAX_FILE_SIZE=2000 # max file size to check in kilobyte, default 2 MB
CHECK_ONLY_RELEVANT_EXTENSIONS=1
declare -a RELEVANT_EXTENSIONS=('exe' 'jsp' 'dll' 'txt' 'js' 'vbs' 'bat' 'tmp' 'dat' 'sys' 'php' 'jspx' 'pl' 'war' 'sh'); # use lower-case
# files in these directories will be checked with string grep
# regradless of their size and extension
declare -a EXCLUDED_DIRS=('/proc/' '/initctl/' '/dev/' '/media/');
# Force Checks
declare -a FORCED_STRING_MATCH_DIRS=('/var/log/' '/etc/hosts');
# Exclude all output lines that contain these strings
declare -a EXCLUDE_STRINGS=('iocs.txt' 'fenrir');

# Hot Time Frame Check
MIN_HOT_EPOCH=1444163570 # minimum Unix epoch for hot time frame e.g. 1444160522
MAX_HOT_EPOCH=1444163590 # maximum Unix epoch for hot time frame e.g. 1444160619
CHECK_FOR_HOT_TIMEFRAME=0

# Debug
DEBUG=0

# Code ----------------------------------------------------------------

# Global vars
declare -a hash_iocs
declare -a hash_ioc_description
declare -a string_iocs
declare -a filename_iocs
declare -a c2_iocs
# declare grep_strings

function scan_dirs
{
    # Scan Dir
    scandir=$1

    # Debug Output --------------------------------------------
    if [ $DEBUG -eq 1 ]; then
        log debug "Scanning $scandir ..."
    fi

    # Cleanup trailing "/" in the most compatible way
    if [ "${scandir: -1}" == "/" ] && [ "${#scandir}" -gt 1 ]; then
        scandir="${scandir:0:${#scandir}-1}"
    fi

    # Loop through files
    for file_path in $(find "$scandir" -type f 2> /dev/null)
    do
        if [ -f "${file_path}" ]; then

            # Debug Output --------------------------------------------
            if [ $DEBUG -eq 1 ]; then
                log debug "Scanning $file_path ..."
            fi

            # Marker --------------------------------------------------
            DO_STRING_CHECK=1
            DO_HASH_CHECK=1
            DO_DATE_CHECK=1
            DO_FILENAME_CHECK=1

            # Evaluations ---------------------------------------------
            file_name=$(basename "$file_path")
            extension="${file_name##*.}"

            # Checks to disable modules -------------------------------

            # Excluded Directories
            result=$(check_dir "$file_path")
            if [ "${result}" -eq 1 ]; then
                if [ $DEBUG -eq 1 ]; then
                    log debug "Skipping $file_path due to exclusion ..."
                fi
                DO_STRING_CHECK=0
                DO_HASH_CHECK=0
                DO_DATE_CHECK=0
                DO_FILENAME_CHECK=0
            fi

            # Exclude Extensions
            if [ $CHECK_ONLY_RELEVANT_EXTENSIONS -eq 1 ]; then
                result=$(check_extension "$extension")
                if [ "${result}" -ne 1 ]; then
                    if [ $DEBUG -eq 1 ]; then
                        log debug "Deactivating some checks on $file_path due to irrelevant extension ..."
                    fi
                DO_STRING_CHECK=0
                DO_HASH_CHECK=0
                fi
            fi

            # Check Size
            filesize=$(du -k "$file_path" | cut -f1)
            if [ "${filesize}" -gt $MAX_FILE_SIZE ]; then
                if [ $DEBUG -eq 1 ]; then
                    log debug "Deactivating some checks on $file_path due to size"
                fi
                DO_STRING_CHECK=0
                DO_HASH_CHECK=0
            fi

            # Checks to include modules -------------------------------

            # Forced string check directory
            for fsm_dir in "${FORCED_STRING_MATCH_DIRS[@]}";
            do
                # echo "Checking if $ex_dir is in $dir"
                if [ "${file_path/$fsm_dir}" != "$file_path" ]; then
                    DO_STRING_CHECK=1
                    if [ $DEBUG -eq 1 ]; then
                        log debug "Activating string check on $file_name"
                    fi
                fi
            done

            # Checks --------------------------------------------------

            # File Name Check
            if [ $DO_FILENAME_CHECK -eq 1 ]; then
                check_filename "$file_path"
            fi

            # String Check
            if [ $DO_STRING_CHECK -eq 1 ]; then
                check_string "$file_path" "$extension"
            fi

            # Hash Check
            if [ $DO_HASH_CHECK -eq 1 ]; then
                md5=$(md5sum "$file_path" 2> /dev/null | cut -f1 -d' ')
                sha1=$(sha1sum "$file_path" 2> /dev/null | cut -f1 -d' ')
                sha256=$(shasum -a 256 "$file_path" 2> /dev/null | cut -f1 -d' ')
                check_hashes "$md5" "$sha1" "$sha256" "$file_path"
            fi

            # Date Check
            if [ $CHECK_FOR_HOT_TIMEFRAME -eq 1 ] && [ $DO_DATE_CHECK -eq 1 ]; then
                check_date "$file_path"
            fi
        fi


    done
    IFS=$oldIFS
}

# Check Functions -----------------------------------------------------

function check_hashes
{
    local index=0
    local md5=$1
    local sha1=$2
    local sha256=$3
    local filepath=$4
    for hash in "${hash_iocs[@]}";
    do
        # echo "Comparing $hash with $md5"
        if [ "$md5" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            log warning "[!] Hash match found FILE: $filepath HASH: $hash DESCRIPTION: $description"
        fi
        if [ "$sha1" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            log warning "[!] Hash match found FILE: $filepath HASH: $hash DESCRIPTION: $description"
        fi
        if [ "$sha256" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            log warning "[!] Hash match found FILE: $filepath HASH: $hash DESCRIPTION: $description"
        fi
        index=$((index+1))
    done
}

function check_string
{
    local filepath=$1
    local extension=$2
    local varlog="/var/log"

    # Decide which strings to look for
    check_strings=$(
        for string in "${string_iocs[@]}";
        do
            echo "$string"
        done

        if [ "${filepath/$varlog}" != "$filepath" ]; then
            # Add C2 iocs if directory is log directory
            for string in "${c2_iocs[@]}";
            do
                echo "$string"
            done
        fi
    )


    # echo "Greping $string in $1"
    match=$(grep -F "$check_strings" "$filepath" 2> /dev/null)
    if [ "$match" != "" ]; then
        match_extract=$(echo $match |cut -c1-100)
        size_of_match=${#match}
        if [ "$size_of_match" -gt 100 ]; then
            match_extract="$match_extract ... (truncated)"
        fi
        log warning "[!] String match found FILE: $filepath STRING: $string TYPE: plain MATCH: $match_extract"
    fi
    # Try zgrep on gz files below /var/log
    if [ "$extension" == "gz" ] || [ "$extension" == "Z" ] || [ "$extension" == "zip" ]; then
        if [ "${filepath/$varlog}" != "$filepath" ]; then
            match=$(zgrep -F "$check_strings" "$filepath" 2> /dev/null)
            if [ "$match" != "" ]; then
                match_extract=$(echo $match |cut -c1-100)
                size_of_match=${#match}
                if [ "$size_of_match" -gt 100 ]; then
                    match_extract="$match_extract ... (truncated)"
                fi
                log warning "[!] String match found FILE: $filepath STRING: $string TYPE: gzip MATCH: $match_extract"
            fi
        fi
    fi
    # Try bzgrep on bz files below /var/log
    if [ "$extension" == "bz" ] || [ "$extension" == "bz2" ]; then
        if [ "${filepath/$varlog}" != "$filepath" ]; then
            match=$(bzgrep -F "$check_strings" "$filepath" 2> /dev/null)
            if [ "$match" != "" ]; then
                match_extract=$(echo $match |cut -c1-100)
                size_of_match=${#match}
                if [ "$size_of_match" -gt 100 ]; then
                    match_extract="$match_extract ... (truncated)"
                fi
                log warning "[!] String match found FILE: $filepath STRING: $string TYPE: bzip2 MATCH: $match_extract"
            fi
        fi
    fi
}

function check_filename
{
    for filename in "${filename_iocs[@]}";
    do
        if [ "${1/$filename}" != "$1" ]; then
            log warning "[!] Filename match found FILE: $1 INDICATOR: $filename"
        fi
    done
}

function check_extension
{
    extension=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    result=0
    for ext in "${RELEVANT_EXTENSIONS[@]}";
    do
        # echo "Comparing $extension with $ext"
        if [ "$extension" == "$ext" ]; then
            result=1
        fi
    done
    echo "$result"
}

function check_date
{
    local filepath="$1"
    local file_epoch=123 # dummy value
    if [ "$stat_mode" -eq 1 ]; then
        file_epoch=$(stat -c '%Z' "$filepath")
    else
        local st_ctime="$file_epoch"
        eval "$(stat -s "$filepath")"
        file_epoch="$st_ctime"
    fi
    # echo "$file_epoch"
    if [ "$file_epoch" -gt "$MIN_HOT_EPOCH" ] && [ "$file_epoch" -lt "$MAX_HOT_EPOCH" ]; then
        log warning "[!] File changed/created in hot time frame FILE: $filepath EPOCH: $file_epoch"
    fi
}

function check_dir
{
    dir=$1
    result=0
    for ex_dir in "${EXCLUDED_DIRS[@]}";
    do
        # echo "Checking if $ex_dir is in $dir"
        if [ "${dir/$ex_dir}" != "$dir" ]; then
            result=1
        fi
    done
    echo $result
}

# Analysis

function scan_c2
{
    oldIFS=$IFS
    IFS=$'\n'
    lsof_output=$(lsof -i)
    for lsof_line in ${lsof_output}; do
        for c2 in "${c2_iocs[@]}"; do
            if [ "${lsof_line/$c2}" != "$lsof_line" ]; then
                log warning "[!] C2 server found in lsof output SERVER: $c2 LSOF_LINE: $lsof_line"
            fi
        done
    done
    lsof_output=$(lsof -i -n)
    for lsof_line in ${lsof_output}; do
        for c2 in "${c2_iocs[@]}"; do
            # echo "$lsof_line - $c2"
            if [ "${lsof_line/$c2}" != "$lsof_line" ]; then
                log warning "[!] C2 server found in lsof output SERVER: $c2 LSOF_LINE: $lsof_line"
            fi
        done
    done
    IFS=$oldIFS
}

# Helpers -------------------------------------------------------------

function evaluate_stat_mode
{
    # Check if Linux mode works
    local result
    result=$(stat -c '%Z' "$0" 2>&1)
    local marker="illegal option"
    if [ "${result/$marker}" != "$result" ]; then
        log info "[+] Setting stat mode to Unix / OS X"
        stat_mode=2
    else
        log info "[+] Setting stat mode to Linux"
        stat_mode=1
    fi
}

function timestamp {
  echo $(date +%F_%T)
}

function log {
    local type="$1"
    local message="$2"
    local ts=$(timestamp)

    # Exclude certain strings (false psotives)
    for ex_string in "${EXCLUDE_STRINGS[@]}";
    do
        # echo "Checking if $ex_string is in $message"
        if [ "${message/$ex_string}" != "$message" ]; then
            return 0
        fi
    done

    # Remove prefix (e.g. [+])
    if [[ "${message:0:1}" == "[" ]]; then
        message_cleaned="${message:4:${#message}}"
    else
        message_cleaned="$message"
    fi

    # Log to file
    if [[ $LOG_TO_FILE -eq 1 ]]; then
        echo "$ts $type $message_cleaned" >> "$LOG_FILE"
    fi
    # Log to syslog
    if [[ $LOG_TO_SYSLOG -eq 1 ]]; then
        logger -p "$SYSLOG_FACILITY.$type" "$(basename $0): $message_cleaned"
    fi
    # Log to command line
    if [[ $LOG_TO_CMDLINE -eq 1 ]]; then
        echo "$message"
    fi
}

# READ IOCS -----------------------------------------------------------

function read_hashes_iocs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    local index=0
    while read -r line ; do
        hash=$(echo "$line" | cut -f1 -d';')
        description=$(echo "$line" | cut -f2 -d';')
        hash_iocs[$index]="$hash"
        hash_ioc_description[$index]="$description"
        # echo "$hash $description"
        index=$((index+1))
    done < $HASH_IOC_FILE
    IFS=$oldIFS
}

function read_string_iocs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    local index=0
    while read -r line ; do
        string_iocs[$index]="$line"
        # echo "$line"
        index=$((index+1))
    done < $STRING_IOCS
    # Prepare grep strings - tried to concatenate a complete string, failed - todo
    # grep_strings=$(prepare_grep_strings)
    # echo $grep_strings
    IFS=$oldIFS
}

function read_filename_iocs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    local index=0
    while read -r line ; do
        filename_iocs[$index]="$line"
        # echo "$line"
        index=$((index+1))
    done < $FILENAME_IOCS
    IFS=$oldIFS
}

function read_c2_iocs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    local index=0
    while read -r line ; do
        c2_iocs[$index]="$line"
        # echo "$line"
        index=$((index+1))
    done < $C2_IOCS
    IFS=$oldIFS
}

# Program -------------------------------------------------------------

echo "##############################################################"
echo " FENRIR"
echo " v$VERSION"
echo " "
echo " Simple Bash IOC Checker"
echo " Florian Roth"
echo " August 2016"
echo "##############################################################"

if [ "$#" -ne 1 ]; then
    echo " "
    echo "[E] Error - not enough parameters"
    echo "    Usage: $0 DIRECTORY" >&2
    echo " "
    echo "    DIRECTORY - Start point of the recursive scan"
    echo " "
    exit 1
fi

# Non-static global variables
declare stat_mode=1

log info "Started FENRIR Scan - version $VERSION"
log info "HOSTNAME: $SYSTEM_NAME"

IP_ADDRESS=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | tr '\n' ' ')
OS_RELEASE=$(cat /etc/*release | sort -u | tr "\n" ";")
OS_ISSUE=$(cat /etc/issue)
OS_KERNEL=$(uname -a)

log info "IP: $IP_ADDRESS"
log info "OS: $OS_RELEASE"
log info "ISSUE: $OS_ISSUE"
log info "KERNEL: $OS_KERNEL"

# Evaluate which stat mode to use
evaluate_stat_mode

# Read all IOCs
log info "[+] Reading Hash IOCs ..."
read_hashes_iocs
log info "[+] Reading String IOCs ..."
read_string_iocs
log info "[+] Reading Filename IOCs ..."
read_filename_iocs
log info "[+] Reading C2 IOCs ..."
read_c2_iocs

# Now scan the given first parameter
if [ $DO_C2_CHECK -eq 1 ]; then
    log info "[+] Scanning for C2 servers in 'lsof' output ..."
    scan_c2
fi
log info "[+] Scanning path $1 ..."
scan_dirs "$1"
log info "Finished FENRIR Scan"
