#### restmbmaster

restmbmaster is a simple daemon that allows user to access Modbus slaves
over Rest API. The slaves could be either connected over
serial line (Modbus RTU protocol), or over TCP (Modbus TCP protocol).

#### Examples

To run connecting to Modbus TCP:

```
$ restmbmaster -c tcp://test.abc:1000 -p 8080
```

To run connecting to Modbus RTU:


```
$ restmbmaster -c rtu:/dev/ttyS0?baud=9600 -p 8080
```

To run according to the configuration from file:

```
$ restmbmaster -f myconfig.conf
```

When restmbmaster is running, one can use for example curl to communicate with Modbus slaves.
In the following example, slave with address 55 is queried for the value of input register with address 10:

```
$ curl http://127.0.0.1:8080/slaves/55/input-registers/10
34
```

It is possible to query multiple registers (in sequence) at once:

```
$ curl http://127.0.0.1:8080/slaves/55/input-registers/10?count=4
34 78 234 2
```

To write new value (434) to holding register 20 the "PUT" method has to be used:

```
$ curl http://127.0.0.1:8080/slaves/55/holding-registers/20 -d "434" -H "Content-Type: text/plain" -X PUT
```

It is also possible to write to a sequence of registers (20-26):

```
$ curl http://127.0.0.1:8080/slaves/55/holding-registers/20 -d "434 48 32 92 1 0 3" -H "Content-Type: text/plain" -X PUT
```

#### Running with systemd

restmbmaster is prepared to be run in multiple parallel instances to allow to access multiple buses. One just have to prepare a configuration file for each bus and ask systemd to spawn the instance.

```
$ sudo mkdir /etc/restmbmaster/
$ sudo cp /usr/share/doc/restmbmaster/example_configs/sample_tcp.conf /etc/restmbmaster/mytcpmodbus1.conf
$ sudo systemctl start restmbmaster@mytcpmodbus1
$ sudo systemctl status restmbmaster@mytcpmodbus1
● restmbmaster@mytcpmodbus1.service - Rest API Modbus master mytcpmodbus1
   Loaded: loaded (/usr/lib/systemd/system/restmbmaster@.service; static; vendor preset: disabled)
   Active: active (running) since Sat 2019-12-28 18:36:54 CET; 1s ago
 Main PID: 8337 (restmbmaster)
    Tasks: 1 (limit: 4915)
   Memory: 588.0K
   CGroup: /system.slice/system-restmbmaster.slice/restmbmaster@mytcpmodbus1.service
           └─8337 /usr/bin/restmbmaster -f /etc/restmbmaster/mytcpmodbus1.conf

Dec 28 18:36:54 nanopsycho systemd[1]: Started Rest API Modbus master mytcpmodbus1.
```

