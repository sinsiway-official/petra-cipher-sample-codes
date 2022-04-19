libraryPathList=$(echo $LD_LIBRARY_PATH | tr ':' '\n')

getPathToFile() {
    [ $# -lt "1" ] && exit 1
    fileName=${1}
    environmentName=${2:-PATH}

    pathList=$(env | awk -F "=" '{ if ($1=="'"${environmentName}"'") print $2}' | tr ':' '\n')

    hasLibrary=false
    for _path in ${pathList}; do
        count=$(find ${_path} -name ${fileName} | wc -l)
        if [ ${count} -ne "0" ]; then
            hasLibrary=true
            libraryPath=${_path}
            break
        fi
    done

    # return string
    echo "${libraryPath}"

    # return code 0:success, 1:failed
    if $hasLibrary; then
        return 0
    else
        return 1
    fi
}

libraryCheck() {
    libraryName=libpcjapi.so
    hasLibrary=false
    libraryPath=$(getPathToFile ${libraryName} LD_LIBRARY_PATH)

    if [ $? -eq "1" ]; then
        echo "not found 'libpcjapi.so' library in LD_LIBRARY_PATH [failed]"
        return 1
    else
        echo "Found library '${libraryName}' in path '${libraryPath}' [Done]"
    fi

    return 0
}

javaclassCheck() {
    javaclassName=PetraCipherAPI.jar
    makeScript=make_jar.sh

    # Create PetraCipherAPI.jar file if it does not exist.
    if [ ! -f "${javaclassName}" ]; then
        echo "Failed to find file '${javaclassName}'."
        echo "Runs file generation."
        sh ${makeScript}
    fi

    # Terminate script if PetraCipherAPI.jar file creation fails
    if [ $? -ne "0" ]; then
        echo "'${javaclassName}' file generate failed"
        return 1
    fi

    #Verify that the PetraCipherAPI.jar file is declared in CLASSPATH
    hasClass=false
    classPathList=$(env | awk -F "=" '{ if ($1=="CLASSPATH") print $2}' | tr ':' '\n')
    for _classPath in ${classPathList}; do
        if [ "${javaclassName}" == "$(basename ${_classPath})" ]; then
            hasClass=true
            break
        fi
    done

    # Add if not in CLASSPATH
    if ! $hasClass; then
        export CLASSPATH=./${javaclassName}:.:$CLASSPATH
    else
        echo "Found classfile '${javaclassName}' in path '${libraryPath}' [Done]"
        return 0
    fi

    # Secondary Search
    hasClass=false
    classPathList=$(env | awk -F "=" '{ if ($1=="CLASSPATH") print $2}' | tr ':' '\n')
    for _classPath in ${classPathList}; do
        if [ "${javaclassName}" == "$(basename ${_classPath})" ]; then
            hasClass=true
            break
        fi
    done

    if ! $hasClass; then
        echo "test faield"
        exit 1
    fi

    echo "Found classfile '${javaclassName}' in path '${libraryPath}' [Done]"
    return 0
}

main() {
    # path=$(getPathToFile test)

    # echo "? : ${?}"
    # echo $path
    # [ !${?} ] && echo "is null"

    libraryCheck
    [ $? -ne "0" ] && exit 0

    javaclassCheck
    [ $? -ne "0" ] && exit 0

}

main
