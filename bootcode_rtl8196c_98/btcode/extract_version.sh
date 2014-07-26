#!/bin/sh
HISTORY_FILE_PATH=../history.txt
P_VERSION=Unknow
O_VERSION=Unknow

Get_PTAG_OTAG()
{
        if [ -e $HISTORY_FILE_PATH ] ; then
                exec < ${HISTORY_FILE_PATH}

                #Get PTAG process
                read line
                PTAG_S=`echo $line | sed 's/Project TAG: TAG_\(.*\)/\1/'`
                if [ "$PTAG_S" != "$line" ] ; then
                        P_VERSION=${PTAG_S//_/.}
                fi

                #Get OTAG process
                read line
                OTAG_S=`echo $line | sed 's/Official TAG: OTAG_\(.*\)/\1/'`
                if [ "$OTAG_S" != "$line" ] ; then
                        O_VERSION=${OTAG_S//_/.}
                fi

        else
                echo "The $HISTORY_FILE_PATH doesn't exist!"
                exit
        fi
}

Get_PTAG_OTAG
echo $P_VERSION
