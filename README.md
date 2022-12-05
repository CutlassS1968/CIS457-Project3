# Encrypted Chat Server  

### Authors
* __Bryan Vandyke:__ ([GitHub](https://github.com/bryanvandyke), vandybry@mail.gvsu.edu, bryan.vandyke@gmail.com)

* __Evan Johns:__ ([GitHub](https://github.com/CutlassS1968), johnsev@mail.gvsu.edu, evanlloydjohns@gmail.com)

### Details
* Project 3 - Encrypted Chat Server
* CIS 457 -  _Data Communications_, Section 03  
* Grand Valley State University, Fall 2022



  

## Building

Building is relatively simple with the included MakeFile.

First need to generate the initial or new public and private keys for the server.
```ssh
make keys
```
Then compile the code into the client and server executables.
```ssh
make
``` 
  
## Running

To run the server, execute the following line:
```ssh  
./server
```
  > _Note: server currently has port hardcoded to 9999_  


And execute this line to run the client:
```ssh
./client <ip_address> 9999 <username>
```
> _Note: Where `<ip_address>` is the server's IP address, and `<username>` is the username that will be used when chatting over the server_

Use the `!help` command to view a list of commands. `!help` will also display a list of exclusive commands for Admins when the connected client is an Admin.
