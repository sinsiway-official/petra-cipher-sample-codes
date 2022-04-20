whichEnvironment() {
    # Outputs the path to the destination file.
    # Blank is output when no value is present.
    # Returns 0 on success. Returns 1 on failure.
    #
    ## ex)
    ## path=$(whichEnvironment libpcapi.so LD_LIBRARY_PATH)
    ## [ $? -ne "0" ] && exit
    ## echo $path
    #

    [ $# -lt "1" ] && exit 1
    fileName=${1}
    environmentName=${2:-PATH}
    includesFileName=${3:-false}

    elementList=$(env | awk -F "=" '{ if ($1=="'"${environmentName}"'") print $2}' | tr ':' '\n')

    hasElement=false
    for element in ${elementList}; do
        count=$(find ${element} -name ${fileName} | wc -l)
        if $includesFileName; then
            if [ "${fileName}" == "$(basename ${element})" ]; then
                hasElement=true
                hasElementPath=${element}
                break
            fi
        else
            if [ ${count} -ne "0" ]; then
                hasElement=true
                hasElementPath=${element}
                break
            fi
        fi

    done

    # return string
    echo "${hasElementPath}"

    # return code 0:success, 1:failed
    if $hasElement; then
        return 0
    else
        return 1
    fi
}

checkLibrary() {
    [ $# -lt "1" ] && exit 1
    libraryName=${1:-libpcapi.so}
    environmentName=${2:-LD_LIBRARY_PATH}

    libraryPath=$(whichEnvironment ${libraryName} ${environmentName})

    if [ $? -eq "1" ]; then
        echo "[failed] not found '${libraryName}' library in ${environmentName}"
        return 1
    else
        echo "[OK] Use [ ${libraryName} ] in path [ ${libraryPath} ]"
    fi

    return 0
}

checkCipherConfig() {

    return 0
}
