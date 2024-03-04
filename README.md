# gotcpreply
Copy Tcp Traffic and reply to other service

## Function

1. Cap Input stream and reply to target address.
2. Create a forwarding connection for each input stream. 
3. If there is a problem with the connection, try to reestablish the connection and write the bit to the header of a request before forwarding.

## Usage

example:

`./gotcpreply -level debug -device lo -filter "tcp dst port 6379" -target 127.0.0.1:6380`

```
Usage of ./gotcpreply:
  -device string
        net device (default "lo0")
  -filter string
        cap filter (default "tcp dst port 6379")
  -header string
        filter header regexp (default "^\\*\\d+\\r\\n\\$")
  -level string
        log level, use: debug info warn error (default "info")
  -sendmsg string
        sed the message to each target conn (default "*3\r\n$6\r\nclient\r\n$5\r\nreply\r\n$3\r\noff\r\n")
  -target string
        transfer target address
```
