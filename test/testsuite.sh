#!/bin/bash

# This is the latest test script for the program. It does not require any 
# arguments.

cd ..

# Create log folders
[ ! -d log ] && mkdir log

for i in 1 2 5 10 25 50 100 200; do
    
    make clean

    echo -e "#ifndef TEST_H_\n"                     \
            "#define TEST_H_\n"                     \
            "\n"                                    \
            "#define SAMPLE_SIZE $i\n"              \
            "#define SAMPLE_CONNECTIONS 100\n"      \
            '#define TEST_RESOURCE "/index.html"\n'  \
            "\n"                                    \
            "#endif"    >  test.h

    make client_no_push client_push server_no_push server_push

    # Start test servers as background processes
    ./server_no_push 8080 host.key host.crt &
    ./server_push 8081 host.key host.crt &
    sleep 0.1

    # Run tests and log them accordingly to log -folder
    ./client_no_push https://localhost:8080/index.html 1> log/no_push_$i.log
    ./client_push https://localhost:8081/index.html 1> log/push_$i.log
    sleep 0.1

    killall server_no_push
    killall server_push

    sleep 0.1

done

make clean
