#!/bin/sh
VERSION_FILE_PATH=../../romfs/etc/FwVersion
if [ -e $HISTORY_FILE_PATH ] ; then
	exec < ${VERSION_FILE_PATH}
	read VER
	IFS="."
	set -- $VER
	echo $1.$2.$3.$4
else
	echo "Unknown"
fi
