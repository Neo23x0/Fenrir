#!/bin/bash
#
# FENRIR
# Simple Bash IOC Checker
# Florian Roth
# October 2015

VERSION="0.2.0b"

# Settings
HASH_IOC_FILE=hash-iocs.txt
STRING_IOCS=string-iocs.txt
FILENAME_IOCS=filename-iocs.txt
MAX_FILE_SIZE=2000 # max file size to check in kilobyte, default 2 MB
CHECK_ONLY_RELEVANT_EXTENSIONS=1
declare -a RELEVANT_EXTENSIONS=('exe' 'jsp' 'asp' 'dll' 'txt' 'js' 'vbs' 'bat' 'tmp' 'dat' 'sys'); # lower-case
declare -a EXCLUDED_DIRS=('/proc/' '/initctl/' '/dev/' '/mnt/' '/media/');
MIN_HOT_EPOCH=1444160000 # minimum Unix epoch for hot time frame e.g. 1444160522
MAX_HOT_EPOCH=1444160400 # maximum Unix epoch for hot time frame e.g. 1444160619
CHECK_FOR_HOT_TIMEFRAME=0
DEBUG=1

# Code
declare -a hash_iocs
declare -a hash_ioc_description
declare -a string_iocs
declare -a filename_iocs
declare grep_strings
$
function scan_dirs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    # Loop through files
    for file_name in "$@"
    do
        if [[ -f "${file_name}" ]]; then

            # Skip (-f filename didn't work for '.' on one machine)
            if [[ "$file_name" == "." ]]; then
                continue
            fi

            # Evaluations
            current_dir=`pwd`
            file_path="$current_dir/$file_name"
            extension="${file_name##*.}"

            # Excluded Directories
            result=$(check_dir "$file_path")
            if [ $result -eq 1 ]; then
                if [ $DEBUG -eq 1 ]; then
                    echo "Skipping $file_path due to exclusion ..."
                fi
                continue
            fi

            # Extension Check
            if [ $CHECK_ONLY_RELEVANT_EXTENSIONS -eq 1 ]; then
                result=$(check_extension "$extension")
                if [ $result -ne 1 ]; then
                    if [ $DEBUG -eq 1 ]; then
                        echo "Skipping $file_path due to irrelevant extension ..."
                    fi
                    continue
                fi
            fi

            # File Name Check
            if [ $DEBUG -eq 1 ]; then
                echo "Scanning $file_path ..."
            fi
            check_filename "$file_path"

            # Check Size
            filesize=$(du -k "$file_name" | cut -f1)
            # echo "$filesize $f"

            if [ $filesize -gt $MAX_FILE_SIZE ]; then
                if [ $DEBUG -eq 1 ]; then
                    echo "Skipping file $file_name due to size"
                fi
                continue
            fi

            # Check for malicious strings in file
            check_string "$file_name"

            # Check for malicious hashes
            md5=$(md5sum "$file_name" 2> /dev/null | cut -f1 -d' ')
            sha1=$(sha1sum "$file_name" 2> /dev/null | cut -f1 -d' ')
            sha256=$(shasum -a 256 "$file_name" 2> /dev/null | cut -f1 -d' ')
            #check_hash "$md5" "$file_path"
            #check_hash "$sha1" "$file_path"
            #check_hash "$sha256" "$file_path"
            check_hashes "$md5" "$sha1" "$sha256" "$file_path"

            # Check Date
            if [ $CHECK_FOR_HOT_TIMEFRAME -eq 1 ]; then
                check_date "$file_name" "$file_path"
            fi
        fi
        if [[ -d "${file_name}" ]]; then
            cd "${file_name}"
            scan_dirs $(ls -1 ".")
            cd ..
        fi
    done
    IFS=$oldIFS
}

# Check Functions -----------------------------------------------------

function check_hash
{
    index=0
    filehash=$1
    filename=$2
    for hash in ${hash_iocs[@]};
    do
        # echo "Comparing $hash with $1"
        if [ "$filehash" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            echo "[!] Hash match found FILE: $filename HASH: $hash DESCRIPTION: $description"
        fi
        index=$(($index+1))
    done
}

function check_hashes
{
    local index=0
    local md5=$1
    local sha1=$2
    local sha256=$3
    local filename=$4
    for hash in ${hash_iocs[@]};
    do
        # echo "Comparing $hash with $md5"
        if [ "$md5" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            echo "[!] Hash match found FILE: $filename HASH: $hash DESCRIPTION: $description"
        fi
        if [ "$sha1" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            echo "[!] Hash match found FILE: $filename HASH: $hash DESCRIPTION: $description"
        fi
        if [ "$sha256" == "$hash" ]; then
            description=${hash_ioc_description[$index]}
            echo "[!] Hash match found FILE: $filename HASH: $hash DESCRIPTION: $description"
        fi
        index=$(($index+1))
    done
}

function check_string
{
    for string in ${string_iocs[@]};
    do
        # echo "Greping $string in $1"
        match=$(grep "$string" "$1")
        if [ "$match" != "" ]; then
            echo "[!] String match found FILE: $1 STRING: $string"
        fi
    done
}

function check_filename
{
    for filename in ${filename_iocs[@]};
    do
        if [ "${1/$filename}" != "$1" ]; then
            echo "[!] Filename match found FILE: $1 INDICATOR: $filename"
        fi
    done
}

function check_extension
{
    local extension=$(echo $1 | tr '[:upper:]' '[:lower:]')
    result=0
    for ext in ${RELEVANT_EXTENSIONS[@]};
    do
        # echo "Comparing $extension with $ext"
        if [ "$extension" == "$ext" ]; then
            result=1
        fi
    done
    echo $result
}

function check_date
{
    local filename="$1"
    local filepath="$2"
    local file_epoch=123 # dummy value
    if [ $stat_mode -eq 1 ]; then
        file_epoch=$(stat -c '%Z' "$1")
    else
        local st_ctime="$file_epoch"
        eval $(stat -s "$1")
        file_epoch="$st_ctime"
    fi
    if [ $file_epoch -gt $MIN_HOT_EPOCH -a $file_epoch -lt $MAX_HOT_EPOCH ]; then
        echo "[!] File changed/created in hot time frame FILE: $filepath EPOCH: $file_epoch"
    fi
}

function check_dir
{
    dir=$1
    result=0
    for ex_dir in ${EXCLUDED_DIRS[@]};
    do
        # echo "Checking if $ex_dir is in $dir"
        if [ "${dir/$ex_dir}" != "$dir" ]; then
            result=1
        fi
    done
    echo $result
}

# Helpers -------------------------------------------------------------

function evaluate_stat_mode
{
    # Check if Linux mode works
    local result=$(stat -c '%Z' "$0" 2>&1)
    local marker="illegal option"
    if [ "${result/$marker}" != "$result" ]; then
        echo "[+] Setting stat mode to Unix / OS X"
        stat_mode=2
    else
        echo "[+] Setting stat mode to Linux"
        stat_mode=1
    fi
}

# READ IOCS -----------------------------------------------------------

function read_hashes_iocs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    index=0
    while read line ; do
        hash=$(echo "$line" | cut -f1 -d';')
        description=$(echo "$line" | cut -f2 -d';')
        hash_iocs[$index]="$hash"
        hash_ioc_description[$index]="$description"
        # echo "$hash $description"
        index=$(($index+1))
    done < $HASH_IOC_FILE
    IFS=$oldIFS
}

function read_string_iocs
{
    # Save field separator
    oldIFS=$IFS
    IFS=$'\n'
    index=0
    while read line ; do
        string_iocs[$index]="$line"
        # echo "$line"
        index=$(($index+1))
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
    index=0
    while read line ; do
        filename_iocs[$index]="$line"
        # echo "$line"
        index=$(($index+1))
    done < $FILENAME_IOCS
    IFS=$oldIFS
}

# Program -------------------------------------------------------------

echo "##############################################################"
echo " FENRIR"
echo " v$VERSION"
echo " "
echo " Simple Bash IOC Checker"
echo " Florian Roth"
echo " October 2015"
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
stat_mode=1

# Evaluate which stat mode to use
evaluate_stat_mode

# Read all IOCs
echo "[+] Reading Hash IOCs ..."
read_hashes_iocs
echo "[+] Reading String IOCs ..."
read_string_iocs
echo "[+] Reading Filename IOCs ..."
read_filename_iocs

# Now scan the given first parameter
echo "[+] Scanning path ..."
scan_dirs $1
