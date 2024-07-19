# EPICS IOC process chain trace (PASJ2024)

This is the archive of BCC codes for PASJ2024.
The test codes to trace the record process chain.

## Requirements

- BCC: Refer to the [install manual](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
- Zipkin Server running outside the eBPF program

## Usage

```bash
$ sudo python3 ./proctrace.py -p <path to libdbCore library>
start
```
