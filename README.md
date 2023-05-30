# Password-Cracker
Simple password cracker in Rust using multithreading. This was done with the purpose of exploring threads in Rust and explore cryptographic methods. It is based on the MD5 algorithm.

The program asks the user for a password in plain text and gives back password's MD5 hash. It then loops over password lengths from 1 until it finds a matching hash and returns the password, time spent to crack and which thread that found it.

NOTE: This is not a useful password cracker in itself, as you hand it the password in plain text. The purpose is to be able to easily test and verify that it works.

Example password times with 8 threads (i7 12700f processor):
* Password 'a': 441.80µs
* Password 'ab': 5.28ms
* Password 'gash': 24.13s
