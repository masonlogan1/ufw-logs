# ufw-python
Python module for easy interaction with the Ubuntu default firewall (Uncomplicated Firewall)

To Do List:

- [x] ability to parse a ufw log file into an object
- [x] ability to search log file object 
- [x] ability to turn each line of the ufw log into an object with all known
attributes for a single entry
- [ ] ability to serialize ufw log entry into json format
- [ ] ability to use something like `UFWLogFile(<filename>)[DPT=='25565']` to
get everything where DPT == 25565, where DPT is an object imported from
ufw
- [ ] ability to chain searches together using `&`, `^`, and `|` operators
- [ ] ability to search using `^` and `!^` operators for similarity/dissimilarity
- [ ] ability to search using `in` and `not in` operators to check that an
attribute is not in a collection

The end goal is to be able to do something like this:

```Python
from ufw import UFWLogFile, DPT, SRC
filename = '/var/log/ufw.log'
log = UFWLogFile(filename)
desired = log[(DPT=='25565') & (SRC is not '192.168.')]
```

and receive a list of all entries that have attempted to access port 25565
from outside the local network