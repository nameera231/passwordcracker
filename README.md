# passwordcracker

A password cracker is a program that recovers users’ passwords from a database of hashed passwords. 
In operating systems and web applications it is standard practice to not store users’ passwords in the database of user accounts. 
Instead, the application typically runs each user’s password through a hash function and stores the result. 
A hash function must be consistent—every time I run my password through a given hash function I should get the same output—but these functions are meant to work only one way. 
I can easily convert passwords to hashed passwords, but it is very difficult to go from hashed passwords back to passwords.
However, sometimes it is possible to recover passwords from hashes; a password cracker performs this feat by searching over the entire space of possible passwords, hashing each one and comparing it to the list of known password hashes. Any time there is a match we now know the users’ original password.

Searching over password hashes is quite difficult for secure hash functions, but luckily there are some insecure hash functions that are still widely used. One of these hash functions is MD5, which is no longer recommended for cryptographic uses.My program will receive a list of usernames and MD5-hashed passwords (all must have 6 lowercase alphabet characters) . It will then search over all possible passwords, hashing each one, until it finds a match for each user’s password. 

 To complete the search in a reasonable amount of time, I will use POSIX threads to perform the search in parallel. 
