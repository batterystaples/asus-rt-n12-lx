Memory_Threshold=550
Free_Memory=`cat /proc/meminfo | grep 'MemFree:' | sed 's/^.*MemFree://g'  | sed 's/kB*$//g'`

if [ $Free_Memory -le $Memory_Threshold ]; then
   sync;echo 3 > /proc/sys/vm/drop_caches
   echo "====clear memory cache===="
fi



