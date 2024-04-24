#!/bin/bash
#docker run --rm -ti -v ~/storage.001:/usr/local/src/container_dir -v ~/container.pfx:/usr/local/src/container.pfx privkey2012 ${pfx_password}

if [ -d "container_dir" ]; then
    ./privkey2012 'container_dir'
fi

if [ -e "container.pfx" ]; then
    password=$1
    if [ -z "$password" ]; then
        echo "password pfx not found"
        exit 1
    fi
    openssl pkcs12 -in container.pfx -clcerts -password pass:"$password" -nokeys -out cert.pem
    cat cert.pem
fi

exit