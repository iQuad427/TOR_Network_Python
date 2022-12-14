# TOR Network 

This project was conducted for the Communication Network course at the EPB (École Polytechnique de Bruxelles). 
It aims at implementing our own 
[TOR Network](https://en.wikipedia.org/wiki/Tor_(network)) 
(cf. [onion routing](https://en.wikipedia.org/wiki/Onion_routing))
which is a network allowing its users to access the internet anonymously.

> Note : all packages required to run the project are listed in the requirements.txt file

## Start up

In 3 different command line tools

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

Before running it, make sure that both server started previously have launched successfully

```
python3 main.py
```
> Note: for each new node and to ensure the scalability it is recommended that
> each node update its phonebook regularly by asking other nodes so that the
> kernel node are not overused.

## Troubleshooting

### Address already in use

When you want to initialize a node on an already used address some troubles
appear, its is therefore recommended checking if the IP address is available.
If some ports are already used you can directly change them in the "main.py" file 
or even change the kernel node ones in the "node.py" file.

It is also recommended when a launching error occur to wait a bit so that the
socket have the time to shut down by themselves.

> Note : on MACOS you have to first allow the connection on your different local
> IP address by using the following command ```sudo ifconfig lo0 alias 127.0.0.X up```
