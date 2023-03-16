
# Implementation of BLAKE Hash Function in C
### ECS412(BS Project) - April 2022

This project studies the working principles and methods of the [MD5](https://github.com/ajaycc17/md5-hash-function) and BLAKE hash functions. MD5 hash
function is not cryptographically secure now, it has already been broken and is used only for local integrity
checks and other simple tasks, but it is a great example to understand the concept of hash functions; it
introduces message compression using a naive method and then with the help of some non-linear functions
on the message, the hash for the message is generated. The BLAKE hash function is similar to the MD5 hash
function for a few initial steps. MD5 produces a 128-bit hash value with the compression of the message by
adding some extra bits and applying some non-linear functions. But in BLAKE, a core function uses 16
different states to process the content of the message and generates a 256-bit hash value. The working
method of both the hash functions is explained, and the hash functions are implemented in the C
programming language for simple string values.


## Author

- [@ajaycc17](https://www.github.com/ajaycc17)(Ajay Choudhury)



## Under Guidance of:
Dr. Shashank Singh [(IISER Bhopal)](https://sites.google.com/view/shashank).