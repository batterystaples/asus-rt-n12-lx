#!/bin/sh
dir_romfs=../../romfs
dir_romfs_web=../../romfs/web
dir_web=../../users/www/
www_path=web
comp_path=compress_web
tmp_list=/tmp/list.txt
cgi=0

filelist=$(cd $www_path && find -type f -name "*" | egrep --regexp '(js|css)$')
cgilist=(./state.js ./util_gw.js ./general.js)

chmod -R 777 $dir_romfs

# for JS and CSS compress
for filename in $filelist
do
   for ((i=0; i<${#cgilist[@]}; i++))
    do
        if [ $filename == ${cgilist[$i]} ]; then	
		cgi=1
		break
	else
		cgi=0
	fi 
     done
	if [ $cgi -eq 0 ]; then
		if [ ! -d "$comp_path" ]; then
			mkdir -p $comp_path/qis
		else
			rm -rf $comp_path
			mkdir -p $comp_path/qis
		fi
		
		./yuicompressor-2.4.2.jar $www_path/$filename -o $comp_path/$filename
		cp -r $comp_path/* $dir_romfs_web
		echo "YUI Downsizing:" $filename
	fi
done


# for htm, asp, jsp(including CGI)
find $dir_romfs_web -type f -name "*" | egrep --regexp '(asp|htm)$' > $tmp_list

	for ((i=0; i<${#cgilist[@]}; i++))
    	do
      	   find $dir_romfs_web -type f -name "*" | grep ${cgilist[$i]} >> $tmp_list
    	done

./web_downsize -f $tmp_list



