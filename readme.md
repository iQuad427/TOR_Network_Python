# TOR Network 

This project was conducted for the Communication Network course at the EPB (École Polytechnique de Bruxelles). 
It aims at implementing our own 
[TOR Network](https://en.wikipedia.org/wiki/Tor_(network)) 
(cf. [onion routing](https://en.wikipedia.org/wiki/Onion_routing))
which is a network allowing its users to access the internet anonymously.

> Note : all packages required to run the project are listed in the requirements.txt file

## Start up

### 1. Launch a local TOR network 

(by launching the kernel nodes from the network)
```
python3 launch.py
```

### 2. Run the authentication server

```
python3 auth_server.py
```


### 3. Run the script

This script is mimicking a use case of the Network to allow for authentication
through a challenge-response process to the server launched at step 2.
```
python3 main.py
```
>note: for each new node and to ensure the scalability it is recommended that
> each node update its phonebook regularly by asking other nodes so that the
> kernel node are not overused.
## Troubleshooting

### Address already in use

When you want to initialize a node on an already used address some troubles
appear, its is therefore recommended to check if the ip address is available.
If some port are already used you can directly change them in "the main.py" file 
or even change the kernel node in the "node.py" file.

It is also recommended when a launching error occur to wait a bit so that the
socket have the time to shut down.

> Note : on MACOS you have to first allow the connection on your different local
> ip address 
