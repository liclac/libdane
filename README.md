libdane
=======

This is a C++ implementation of the **DANE** (DNS-Based Authentication of Named Entities) specification detailed in [RFC6698](https://tools.ietf.org/html/rfc6698).

It consists of two parts:

* **libdane** - a library for working with DANE records
* **danetool** - a commandline tool for inspecting domains' DANE records

Right now, the project is very much a work in progress - it's partially implemented, and biased towards SMTP. This will *not* be the case in the finished library.
