# libraryPathList=$(echo $LD_LIBRARY_PATH | tr ':' '\n')
log=petraCipherJava.log

initialize() {
    currentDir=$(pwd)
    echo "[info] Add the '${currentDir}' and '.' to the [ LD_LIBRARY_PATH ] path.."
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${currentDir}:.

    echo "[info] Add the '${currentDir}/PetraCipherAPI.jar' and '.' to the [ CLASSPATH ]"
    echo ""
    export CLASSPATH=${CLASSPATH}:${currentDir}/PetraCipherAPI.jar:.
}

getPathToFile() {
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

libraryCheck() {
    libraryName=libpcjapi.so
    environmentName=LD_LIBRARY_PATH

    libraryPath=$(getPathToFile ${libraryName} ${environmentName})

    if [ $? -eq "1" ]; then
        echo "[failed] not found '${libraryName}' library in ${environmentName}"
        return 1
    else
        echo "[OK] Use [ ${libraryName} ] in path [ ${libraryPath} ]"
    fi

    return 0
}

javaclassCheck() {
    javaclassName=PetraCipherAPI.jar
    makeScript=make_jar.sh
    environmentName=CLASSPATH

    # Create PetraCipherAPI.jar file if it does not exist.
    if [ ! -f "${javaclassName}" ]; then
        sh ${makeScript}
    fi

    # Terminate script if PetraCipherAPI.jar file creation fails
    if [ $? -ne "0" ]; then
        echo "[failed] [ ${javaclassName} ] file generate failed"
        return 1
    fi

    #Verify that the PetraCipherAPI.jar file is declared in CLASSPATH
    hasClass=false
    classPath=$(getPathToFile ${javaclassName} ${environmentName} true)
    if [ $? -eq "1" ]; then
        echo "[failed] not found [ ${javaclassName} ] in [ ${environmentName} ]"
        echo ""
        return 1
    else
        echo "[OK] Use [ ${javaclassName} ] in path [ ${classPath} ]"
    fi

    return 0
}

main() {
    initialize

    libraryCheck
    [ $? -ne "0" ] && exit 0

    javaclassCheck
    [ $? -ne "0" ] && exit 0

}

main
