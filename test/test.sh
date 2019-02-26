#!/bin/bash


# Examples for usage:
# 1) 

server() {
    cd ..

    cmd=`nghttpd $1 8080 host.key host.crt &`
    echo "$cmd"

    cd test
}


reqTemplate=$(printf "%100s")

test_push_with_curl() {
    push_resources="index.html,css/styles.css"
    push="-m1 --push=index.html=$push_resources"

    req_resources=${reqTemplate// /https://localhost:8080/index.html -o /dev/null \
        https://localhost:8080/index.html -o /dev/null \
        https://localhost:8080/css/styles.css -o /dev/null }
    
    echo "Server running with $1 pushes"
    echo $req_resources
    server $push &
    sleep 0.1

    curl \
        -w '%{time_connect}\t%{time_pretransfer}\t%{time_starttransfer}\t%{time_total}\n' \
        -k \
        $req_resources

    killall -v nghttpd
}

resource=css/styles.css




test_push_with_dummy_files() {
    echo "Testing for server push"
    push_resources=""
    req_resources=""

    ./make_dummy_files.sh $1

    for i in $(seq 1 $1); do
        push_resources="$push_resources, test/testfile-$i.js"
        req_resources="$req_resources /test/testfile-$i.js"
    done

    rm -f ../log/test_server_push_$i.log
        
    push="-m1 --push=index.html=$push_resources"
    
    echo "Server running with $i pushes" 
    server $push &
    sleep 0.1

    client=`h2load -v -n$((100 - (100 % $1)))  -m100 --log-file=../log/test_server_push_$i.csv https://localhost:8080/index.html $req_resources` 
    echo "$client"

    rm -f testfile-*

    killall -v nghttpd
}

echo "$($1 $2)"
