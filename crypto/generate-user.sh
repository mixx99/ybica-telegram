openssl genrsa -out user.key 2048
openssl req -new -key user.key -out user.csr
