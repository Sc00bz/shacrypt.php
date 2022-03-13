# shacrypt.php
Create shacrypt hashes in preparation for deprecation and removal of crypt() from PHP.

## Warning - Do not use shacrypt hashes
Instead of using this, please use bcrypt with PHP's functions `password_hash()` and `password_verify()`.

bcrypt cost 9 is much faster as a defender while being much slower for an attacker vs my default rounds of 330000 for sha256crypt and 190000 for sha512crypt.
