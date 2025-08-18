# ybica-telegram

This is an implementation of a simple messenger on a local network

## Functionality

- We can send messages to everyone using the UDP broadcast protocol.
- We can send private messages using the TCP protocol, as well as encryption using the OpenSSL library and certificates.
- We can send and receive files using encrypted messages of any size.
- If the connection is disconnected, we can resume downloading the file from the same location.
- The functionality of detecting new users has been implemented.
- The clients in the network have the same rights and priorities.
- All messages are saved.
- It is possible to send messages to a group of users
- Connecting/disconnecting to a general chat

<img width="484" height="357" alt="image" src="https://github.com/user-attachments/assets/4ed9dd7a-d0e6-44f8-a3fe-3bc2eec0f7c8" />

### User functions:

```
/help - for help message.
/pm <name> <text> - for private message.
/members - print list of current members.
/trust <user> - Trust the user. He will be able to send you files.
/untrust <user> - Stop trust user. He won't be able to send you files.
/trusted - List of your trusted users.
/sendfile <user> <path-to-file> - Send a file to user. Need to be a trusted user.
/general - Enable/Disable general chat.
/history <username> - Prints the history with user.
/sendg <Number-of-users> <Users> <Text> - Sends a message to group of users.
```

### Building

#### Linux:

```bash
make # Default
#####
make OUT_O_DIR=debug CC=clang CFLAGS="-g -O0" # Debug
#####
make test # Run tests
#####
# Coverage of tests using lcov.
make coverage
lcov --capture --directory build --output-file coverage.info
lcov --remove coverage.info 'thirdparty/*' --output-file coverage.info
genhtml coverage.info --output-directory coverage-report
firefox coverage-report/index.html
```
