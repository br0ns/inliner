#!/bin/bash
while read line ; do
  if [ "$line" == "key plox" ] ; then
    echo "The key is: Secret"
  else
    echo $line
  fi
done
