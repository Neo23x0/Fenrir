#!/bin/bash
#
# FENRIR
# Simple Bash IOC Checker
# Florian Roth

VERSION="0.9.0-log4shell"

# Settings ------------------------------------------------------------
SYSTEM_NAME=$(uname -n | tr -d "\n")
TS_CONDENSED=$(date +%Y%m%d)

# IOCs
HASH_IOC_FILE="./hash-iocs.txt"
STRING_IOCS="./string-iocs.txt"
FILENAME_IOCS="./filename-iocs.txt"
C2_IOCS="./c2-iocs.txt"

# Log
LOGFILE="./FENRIR_${SYSTEM_NAME}_${TS_CONDENSED}.log"
LOG_TO_FILE=1
LOG_TO_SYSLOG=0 # Log to syslog is set to 'off' by default > false positives
LOG_TO_CMDLINE=1
SYSLOG_FACILITY=local4

# Enable / Disable Checks
ENABLE_C2_CHECK=1
ENABLE_TYPE_CHECK=1
ENABLE_HASH_CHECK=1

# Exclusions
MAX_FILE_SIZE=8000 # max file size to check in kilobyte, default 2 MB
CHECK_ONLY_RELEVANT_EXTENSIONS=1 # ELF binaries get always checked
declare -a RELEVANT_EXTENSIONS=('jsp' 'jspx' 'txt' 'tmp' 'pl' 'war' 'sh' 'log' 'jar'); # use lower-case
# files in these directories will be checked with string grep
# regradless of their size and extension
declare -a EXCLUDED_DIRS=('/proc/' '/initctl/' '/dev/' '/media/');
# Force Checks
declare -a FORCED_STRING_MATCH_DIRS=('/var/log/' '/etc/hosts' '/etc/crontab');
# Exclude all output lines that contain these strings
declare -a EXCLUDE_STRINGS=('iocs.txt' 'fenrir');

# global var for passing pseudo hash
declare -i pseudo_h

# Hot Time Frame Check
MIN_HOT_EPOCH=1444163570 # minimum Unix epoch for hot time frame e.g. 1444160522
MAX_HOT_EPOCH=1444163590 # maximum Unix epoch for hot time frame e.g. 1444160619
CHECK_FOR_HOT_TIMEFRAME=0

# Debug
DEBUG=0

# Code ----------------------------------------------------------------

# Global vars
declare -a hash_iocs
declare -a pseudo_hash_iocs
declare -a hash_ioc_description
declare -a string_iocs
declare -a check_strings
declare -a filename_iocs
declare -a c2_iocs
# declare grep_strings

function scan_dirs
{
    # Scan Dir
    scandir=$1

    # Debug Output --------------------------------------------
    log debug "Scanning $scandir ..."

    # Cleanup trailing "/" in the most compatible way
    if [ "${scandir: -1}" == "/" ] && [ "${#scandir}" -gt 1 ]; then
        scandir="${scandir:0:${#scandir}-1}"
    fi

    # Loop through files
    find "$scandir" -type f 2> /dev/null | while read -r file_path
    do
        if [ -f "${file_path}" ]; then

            # Debug Output --------------------------------------------
            log debug "Scanning $file_path ..."

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
                log debug "Skipping $file_path due to exclusion ..."
                DO_STRING_CHECK=0
                DO_HASH_CHECK=0
                DO_DATE_CHECK=0
                DO_FILENAME_CHECK=0
            fi
            
            # Check if relevant type
            if [ $ENABLE_TYPE_CHECK -eq 1 ]; then
                relevant_type=$(file "$file_path" | grep -F "ELF")
            fi

            # Exclude Extensions
            if [ $CHECK_ONLY_RELEVANT_EXTENSIONS -eq 1 ] && [ "$relevant_type" == "" ]; then
                result=$(check_extension "$extension")
                if [ "${result}" -ne 1 ]; then
                    log debug "Deactivating some checks on $file_path due to irrelevant extension ..."
                    DO_STRING_CHECK=0
                    DO_HASH_CHECK=0
                fi
            fi

            # Check Size
            filesize=$(du -k "$file_path" | cut -f1)
            if [ "${filesize}" -gt $MAX_FILE_SIZE ]; then
                log debug "Deactivating some checks on $file_path due to size"
                DO_STRING_CHECK=0
                DO_HASH_CHECK=0
            fi

            # Checks to include modules -------------------------------

            # Forced string check directory
            for fsm_dir in "${FORCED_STRING_MATCH_DIRS[@]}";
            do
                # echo "Checking if $ex_dir is in $dir"
                # The following check matches when $fsm_dir is ANYWHERE in the
                # $file_path, not only at the beginning. As we're just doing
                # more checks in that case, we don't care
                if [ "${file_path/$fsm_dir}" != "$file_path" ]; then
                    DO_STRING_CHECK=1
                    log debug "Activating string check on $file_name"
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
            if [ $DO_HASH_CHECK -eq 1 ] && [ $ENABLE_HASH_CHECK -eq 1 ]; then
                md5=$(md5sum "$file_path" 2> /dev/null | cut -f1 -d' ')
                #md5tmp=$(md5sum "$file_path" 2> /dev/null)
                #md5=${md5tmp%% *}
                sha1=$(sha1sum "$file_path" 2> /dev/null | cut -f1 -d' ')
                sha256=$(sha256sum "$file_path" 2> /dev/null | cut -f1 -d' ')
                log debug "Checking hashes of file $file_path : $md5"
                check_pseudo_hashes "$md5" "$sha1" "$sha256" "$file_path"
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

function check_pseudo_hashes
{
    local md5=$1
    local sha1=$2
    local sha256=$3
    local filepath=$4

    hashes=(${md5} ${sha1} ${sha256})
    for hash in "${hashes[@]}";
        do
        pseudo_hash "$hash"
        if [ -n "${pseudo_hash_iocs[$pseudo_h]}" ]; then
            # TODO change to "log debug"
            log debug "[+] Pseudo hash match on $file_path pseudo hash: $pseudo_h real hash will be checked now: $hash"

            check_hashes "$hash" "$file_path"
        fi
    done
}

function check_hashes
{
    local index=0
	local check_hash=$1
    #local md5=$1
    #local sha1=$2
    #local sha256=$3
    local filepath=$2

    for hash in "${hash_iocs[@]}";
    do
        #echo "Comparing $hash with $md5"
        if [ "$check_hash" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            log warning "[!] Hash match found FILE: $filepath HASH: $hash DESCRIPTION: $description"
        fi
        #if [ "$sha1" == "$hash" ]; then
            #description=${hash_ioc_description[$index]}
            #log warning "[!] Hash match found FILE: $filepath HASH: $hash DESCRIPTION: $description"
        #fi
        #if [ "$sha256" == "$hash" ]; then
            #description=${hash_ioc_description[$index]}
            #log warning "[!] Hash match found FILE: $filepath HASH: $hash DESCRIPTION: $description"
        #fi
        index=$((index+1))
    done
}

function check_string
{
    local filepath=$1
    local extension=$2
    local varlog="/var/log"

    # echo "Greping $string in $1"
    match=$(grep -F "$check_strings" "$filepath" 2> /dev/null)
    # Cut big matches (fixes buges in super long web shell lines without line breaks)
    match=$(echo "$match" |cut -c1-100)

    # if [[ ! -z "${match// }" ]] ; then
    if [ "$match" != "" ]; then
        string=$(determine_stringmatch "$match")
        log warning "[!] String match found FILE: $filepath STRING: $string TYPE: plain MATCH: $match"
    fi
    # Try zgrep on gz files below /var/log
    if [ "$extension" == "gz" ] || [ "$extension" == "Z" ] || [ "$extension" == "zip" ]; then
        if [ "${filepath/$varlog}" != "$filepath" ]; then
            match=$(zgrep -F "$check_strings" "$filepath" 2> /dev/null)
            if [ "$match" != "" ]; then
                string=$(determine_stringmatch "$match")
                match_extract=$(echo "$match" |cut -c1-100)
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
                string=$(determine_stringmatch "$match")
                match_extract=$(echo "$match" |cut -c1-100)
                size_of_match=${#match}
                if [ "$size_of_match" -gt 100 ]; then
                    match_extract="$match_extract ... (truncated)"
                fi
                log warning "[!] String match found FILE: $filepath STRING: $string TYPE: bzip2 MATCH: $match_extract"
            fi
        fi
    fi
}

function determine_stringmatch
{
    for string in "${string_iocs[@]}";
    do
        if [ "${1/$string}" != "$1" ]; then
            echo "$string"
            return 0
        fi
    done
    for string in "${c2_iocs[@]}";
    do
        if [ "${1/$string}" != "$1" ]; then
            echo "$string"
            return 0
        fi
    done
    echo "(binary match)"
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
            if [ "${dir/#$ex_dir}" = "$dir" ];then
                log debug "Skipping $dir due to WRONG exclusion bc/ $ex_dir in the middle of the path..."
            fi
            result=1
        fi
    done
    echo $result
}

# Analysis --------------------------------------------------------------------
function scan_c2
{
    oldIFS=$IFS
    IFS=$'\n'
    # Don't resolve names
    lsof_output=$(lsof -i -n)
    for lsof_line in ${lsof_output}; do
        for c2 in "${c2_iocs[@]}"; do
            # C2 check
            if [ "${lsof_line/$c2}" != "$lsof_line" ]; then
                log warning "[!] C2 server found in lsof output SERVER: $c2 LSOF_LINE: $lsof_line"
            fi
        done
        # Shell Check 
        if [ "${lsof_line:0:5}" == "bash " ] || [ "${lsof_line:0:3}" == "sh " ]; then
            if [ "${lsof_line/127.0.0.1}" == "$lsof_line" ]; then
                log notice "[!] Shell found in lsof output - could be a back connect shell LSOF_LINE: $lsof_line"
            fi
        fi
    done
    # Resolve names
    lsof_output=$(lsof -i)
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
  date +%F_%T
}

function log {
    local type="$1"
    local message="$2"
    local ts
    ts=$(timestamp)

    # Only report debug messages if mode is enabled
    if [ "$type" == "debug" ] && [ $DEBUG -ne 1 ]; then
        return 0
    fi

    # Exclude certain strings (false positives)
    for ex_string in "${EXCLUDE_STRINGS[@]}";
    do
        # echo "Checking if $ex_string is in $message"
        if [ "${message/$ex_string}" != "$message" ]; then
            return 0
        fi
    done

    # Remove line breaks
    message=$(echo "$message" | tr -d '\r' | tr '\n' ' ') 

    # Remove prefix (e.g. [+])
    if [[ "${message:0:1}" == "[" ]]; then
        message_cleaned="${message:4:${#message}}"
    else
        message_cleaned="$message"
    fi

    # Log to file
    if [[ $LOG_TO_FILE -eq 1 ]]; then
        echo "$ts $type $message_cleaned" >> "$LOGFILE"
    fi
    # Log to syslog
    if [[ $LOG_TO_SYSLOG -eq 1 ]]; then
        logger -p "$SYSLOG_FACILITY.$type" "$(basename "$0"): $message_cleaned"
    fi
    # Log to command line
    if [[ $LOG_TO_CMDLINE -eq 1 ]]; then
        echo "$message" >&2
    fi
}

# READ IOCS -----------------------------------------------------------

function pseudo_hash {
    local hash=$1
    #echo hash: $hash

    short_hash="0x${hash:0:8}"
    let pseudo_h=$(($short_hash))

    # use global var to save the fork of /bin/echo
    #echo $pseudo_h
}		


function read_hashes_iocs
{
    # Save field separator
    oldIFS="$IFS"
    IFS=$'\n'
    local index=0
    while read -r line ; do
        #hash=$(echo "$line" | cut -f1 -d';')
        #description=$(echo "$line" | cut -f2 -d';')
        hash=${line%;*}
        if [[ -z "${hash// }" ]] ; then
            continue
        fi

        # Skip comments
        if [[ $line == \#* ]] ; then
            continue
        fi
        description=${line#*;}

        hash_iocs[$index]="$hash"
        hash_ioc_description[$index]="$description"

        # changes global var $pseudo_h
        pseudo_hash "$hash"
        # assigning the real hash value to the pseudo hash array. beware: there might be collisions so only the last one is in there!
        #echo $pseudo_h
        pseudo_hash_iocs[$pseudo_h]=$hash

        # echo "$hash $description"
        index=$((index+1))
    done < $HASH_IOC_FILE
    IFS=$oldIFS
}

function read_string_iocs
{
    # Save field separator
    oldIFS="$IFS"
    IFS=$'\n'
    local index=0
    while read -r line ; do
        # Skip empty values
        if [[ -z "${line// }" ]] ; then
            continue
        fi
        # Skip comments
        if [[ $line == \#* ]] ; then
            continue
        fi
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
    oldIFS="$IFS"
    IFS=$'\n'
    local index=0
    while read -r line ; do
        if [[ -z "${line// }" ]] ; then
            continue
        fi
        filename_iocs[$index]="$line"
        # echo "$line"
        index=$((index+1))
    done < $FILENAME_IOCS
    IFS=$oldIFS
}

function read_c2_iocs
{
    # Save field separator
    oldIFS="$IFS"
    IFS=$'\n'
    local index=0
    while read -r line ; do
        if [[ -z "${line// }" ]] ; then
            continue
        fi
        c2_iocs[$index]="$line"
        # echo "$line"
        index=$((index+1))
    done < $C2_IOCS
    IFS=$oldIFS
}

function prepare_check_stings
{
    # New method - create a string with values divided by new line for use in 'grep -F' 
    check_strings=$(
        for string in "${string_iocs[@]}";
        do
            echo "$string"
        done

        # Add C2 iocs if directory is log directory
        for string in "${c2_iocs[@]}";
        do
            echo "$string"
        done
    )
}

function check_req 
{
    log info "Checking the required utilities ..."
    file_avail=$(command -v file)
    if [[ -z $file_avail ]]; then 
        log error "The 'file' command can't be found (disabling file type checks)"
        ENABLE_TYPE_CHECK=0
    fi
    lsof_avail=$(command -v lsof)
    if [[ -z $lsof_avail ]]; then 
        log error "The 'lsof' command can't be found (disabling C2 checks)"
        ENABLE_C2_CHECK=0
    fi
    md5sum_avail=$(command -v md5sum)
    if [[ -z $md5sum_avail ]]; then 
        log error "The 'md5sum' command can't be found (disabling hash checks)"
        ENABLE_HASH_CHECK=0
    fi
}


# Program -------------------------------------------------------------

echo "##############################################################"
echo "    ____             _     "
echo "   / __/__ ___  ____(_)___ "
echo "  / _// -_) _ \/ __/ / __/ "
echo " /_/  \__/_//_/_/ /_/_/    "
echo " v$VERSION"
echo " "
echo " Simple Bash IOC Checker"
echo " Florian Roth, Dec 2021"
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
log info "Writing logfile to ${LOGFILE}"
log info "HOSTNAME: ${SYSTEM_NAME}"

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

# Check requirements
check_req

# Read all IOCs
log info "[+] Reading Hash IOCs ..."
read_hashes_iocs
log info "[+] Reading String IOCs ..."
read_string_iocs
prepare_check_stings
log info "[+] Reading Filename IOCs ..."
read_filename_iocs
log info "[+] Reading C2 IOCs ..."
read_c2_iocs

# Now scan the given first parameter
if [ $ENABLE_C2_CHECK -eq 1 ]; then
    log info "[+] Scanning for C2 servers in 'lsof' output ..."
    scan_c2
fi
log info "[+] Scanning path $1 ..."
scan_dirs "$1"
log info "Finished FENRIR Scan"
