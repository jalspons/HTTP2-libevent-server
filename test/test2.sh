#!/bin/bash
#echo 'Conntect_time | Time_pretransfer | Time Starttransfer | Total_time' > $1 
#echo '--------------------------' >> $1

#for i in {1..100}; do
#    curl -w '%{time_connect},\t%{time_pretransfer},\t%{time_starttransfer},\t%{time_total}\n' -o /dev/null -k https://localhost:8080/index.html >> $1
#done

#rm -f $1

#reqTemplate=$(printf "%10000s")
    
#curl $2 -w '%{time_connect}\t%{time_pretransfer}\t%{time_starttransfer}\t%{time_total}\n' -k ${reqTemplate// /https://localhost:8080/index.html -o /dev/null } >> $1

resource=index.html

server() {
    cmd=`nghttpd $1 8080 host.key host.crt &`
    echo "$cmd"
}

test_push() {
    echo "Testing for server push"
    Tmpl_push=$(printf "%98s")     
    push_resource=${Tmpl_push// /$resource,}$resource
    push="--push=index.html=$push_resource"
    
    echo "Server running with 99 pushes" 
    echo "$push"
    server $push &
    sleep 0.1

    if [ -e "./client_push" ]; then
        rm -f client_push
    fi
    make client_push

    ./client_push https://localhost:8080/index.html
    
    killall nghttpd
}

test_multiplexing() {
    echo "Testing multiplexing"
    
    for i in 1 2 5 10 20 50 100 1000; do
        logfile=log/test_multiplexing_$i.csv
        rm -f $logfile
        
        # N = 10 000 
        cmd="-m$i"

        echo "### $i streams #"
        server $cmd &
        sleep 0.1

        client=`h2load --requests=$1 -m100 --log-file=$logfile https://localhost:8080/index.html`
        echo "$client" |grep "finished"

        killall -v nghttpd
    done
}

echo "$($1 $2)"



#nghttpd --push=${reqTemplate// /



#h2load -n10000 -m$2 --log-file=$1 ${reqTemplate// /https://localhost:8080/index.html }
