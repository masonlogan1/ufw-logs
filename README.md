# ufw-python
Python module for easy interaction with the Ubuntu default firewall (Uncomplicated Firewall)

### Version 0.1
Basic functionality (parsing files, searching for entries)

#### Checklist:

- [x] ability to parse a ufw log file into an object
- [x] ability to search log file object 
- [x] ability to turn each line of the ufw log into an object with all known
attributes for a single entry
- [x] ability to serialize ufw log entry into json format
- [x] ability to use something like `UFWLogFile(<filename>)[DPT=='25565']` to
get everything where DPT == 25565, where DPT is an object imported from
ufw
- [x] ability to chain searches together using `&`, `^`, and `|` operators
- [x] ability to search using `%` and `!%` operators for similarity/dissimilarity
attribute is not in a collection
- [x] ability to use `+` and `-` operators in filtering

### Version 0.2
Database persistence, improved file handling

#### Checklist:
- [ ] ability to persist log data into a SQLite database
- [ ] default log object to use lazy-parsing that only parses the file when it
is necessary
- [ ] ability to use a lazy evaluation for a log file to iterate over logs 
without storing the row data in the object when they are iterated over
- [ ] ability to use existing search tools to query entries from the database:
  - [ ] greater-than, less-than, equal-to
  - [ ] logical and, or, not
  - [ ] regex searching

### Version 0.3
Split file parser into separate class (`UFWFileParser`)

#### Checklist:
- [ ] `UFWFileParser` class is split away from `UFWLogFile` class to separate
parsing functionality from data representation
- [ ] `UFWFileParser` class creates overridable methods for extracting,
cleaning, and storing the data into objects, allowing for easier extension
- [ ] `UFWSQLite` class that extends `UFWFileParser` but stores data from files
directly into a SQLite database

### Future Goals
- [ ] Classes that allow for easy transformation of UFW data into various
SQL/NoSQL databases
- [ ] Tools for searching data in a web interface (potential breakaway project)