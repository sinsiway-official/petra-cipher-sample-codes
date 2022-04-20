source tools.sh
log=petraCipherJava.log

initialize() {
    currentDir=$(pwd)
    echo "[info] Add the '${currentDir}' and '.' to the [ LD_LIBRARY_PATH ] path.."
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${currentDir}:.

    echo "[info] Add the '${currentDir}/PetraCipherAPI.jar' and '.' to the [ CLASSPATH ]"
    echo ""
    export CLASSPATH=${CLASSPATH}:${currentDir}/PetraCipherAPI.jar:.
}

checkJavaclass() {
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
    classPath=$(whichEnvironment ${javaclassName} ${environmentName} true)
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

    checkLibrary libpcjapi.so
    [ $? -ne "0" ] && exit 0

    checkJavaclass
    [ $? -ne "0" ] && exit 0

    checkCipherConfig
    [ $? -ne "0" ] && exit 0

}

main
