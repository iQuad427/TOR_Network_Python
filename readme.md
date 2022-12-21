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
python3 authentication_server.py
```


### 3. Run the script

This script is mimicking a use case of the Network to allow for authentication
through a challenge-response process to the server launched at step 2.
```
python3 main.py
```


## Troubleshooting

### Address already in use

