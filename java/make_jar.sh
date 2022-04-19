#/bin/sh

if [ -f "PetraCipherAPI.jar" ]; then
    echo "aleady PetraCipherAPI.jar. [Done]"
    exit
fi

javac_bin=$(which javac)

if [ -z "${javac_bin}" ]; then
    echo "Failed to find 'javac' binary."
    echo "Install 'jdk' first"
    exit 1
else
    echo "Check for jdk installation. [OK]"
fi

if [ ! -f "sinsiway/PcaSession.java" ]; then
    echo "There is no 'PcaSession.java' file in the 'sinsiway' folder. [failed]"
    exit 1
fi

if [ ! -f "sinsiway/PcaSessionPool.java" ]; then
    echo "There is no 'PcaSessionPool.java' file in the 'sinsiway' folder. [failed]"
    exit 1
fi

if [ ! -f "sinsiway/PcaException.java" ]; then
    echo "There is no 'PcaException.java' file in the 'sinsiway' folder. [failed]"
    exit 1
fi

javac -Xlint:unchecked sinsiway/*.java

if [ ! -f "sinsiway/PcaSession.class" ]; then
    echo "Failed to compile file 'PcaSession.class'. [failed]"
    exit 1
fi

if [ ! -f "sinsiway/PcaSessionPool.class" ]; then
    echo "Failed to compile file 'PcaSessionPool.class'. [failed]"
    exit 1
fi

if [ ! -f "sinsiway/PcaException.class" ]; then
    echo "Failed to compile file 'PcaException.class'. [failed]"
    exit 1
fi

echo "Compiling Petra cipher classes. [Ok]"

jar -cvf0 PetraCipherAPI.jar ./sinsiway/*.class

if [ -f "sinsiway/PcaSession.class" ]; then
    rm "sinsiway/PcaSession.class"
fi

if [ -f "sinsiway/PcaSessionPool.class" ]; then
    rm "sinsiway/PcaSessionPool.class"
fi

if [ -f "sinsiway/PcaException.class" ]; then
    rm "sinsiway/PcaException.class"
fi
echo "remove class files. [Done]"

if [ ! -f "PetraCipherAPI.jar" ]; then
    echo "Failed to create PetraCipherAPI.jar file. [failed]"
    exit 1
fi

echo "create PetraCipherAPI.jar [Ok]"

exit
