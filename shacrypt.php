<?php

/*
	shacrypt.php - Create and verify bad legacy password hashing algorithms: sha256crypt and sha512crypt

	Written in 2022 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
	rights to this software to the public domain worldwide. This software is distributed without any warranty.

	You should have received a copy of the CC0 Public Domain Dedication along with this software.
	If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
*/

// ####################################################
// ####################################################
// ###                                              ###
// ###   Instead of using this, please use bcrypt   ###
// ###  with password_hash() and password_verify()  ###
// ###                                              ###
// ###  bcrypt cost 9 is much faster as a defender  ###
// ###   while being much slower for an attacker    ###
// ###  vs the default rounds of 330000 and 190000  ###
// ###                                              ###
// ####################################################
// ####################################################

/**
 * Creates a sha256crypt hash.
 *
 * @param string $password
 * @param integer $rounds
 * @return string on success, otherwise false
 */
function sha256crypt_create($password, $rounds = 330000)
{
	return _shacrypt_create($password, $rounds, true);
}

/**
 * Creates a sha512crypt hash.
 *
 * @param string $password
 * @param integer $rounds
 * @return string on success, otherwise false
 */
function sha512crypt_create($password, $rounds = 190000)
{
	return _shacrypt_create($password, $rounds, false);
}

/**
 * Verifies a shacrypt hash.
 *
 * @param string $password
 * @param string $hash
 * @return bool
 */
function shacrypt_verify($password, $hash)
{
	// Prevent CVE-2016-20013
	$pwLen = strlen($password);
	if ($pwLen > 1024)
	{
		return false;
	}

	return password_verify($password, $hash);
}

/**
 * Creates a shacrypt hash.
 *
 * @param string $password
 * @param integer $rounds
 * @param bool $isSha256
 * @return string on success, otherwise false
 */
function _shacrypt_create($pw, $rounds, $isSha256)
{
	// Prevent CVE-2016-20013
	$pwLen = strlen($pw);
	if ($pwLen > 1024)
	{
		return false;
	}

	// Version
	if ($isSha256)
	{
		// RTX 3080 10GB benchmark for $minRounds
		// Update as better GPUs come out (MSRP of ~$700 in 2015 USD)
		// This should be 330000 for <10 kH/s/GPU but this algorithm is slow for defenders
		// $minRounds = 653.4 kH/s * 5000 rounds / 25 kH/s
		// https://gist.github.com/Chick3nman/bb22b28ec4ddec0cb5f59df97c994db4
		$minRounds = 140000; // <25 kH/s/GPU
		$hashName = 'sha256';
		$hashRepeats = ($pwLen + 31) >> 5;
	}
	else
	{
		// RTX 3080 10GB benchmark for $minRounds
		// Update as better GPUs come out (MSRP of ~$700 in 2015 USD)
		// This should be 190000 for <10 kH/s/GPU but this algorithm is slow for defenders
		// $minRounds = 373.2 kH/s * 5000 rounds / 25 kH/s
		// https://gist.github.com/Chick3nman/bb22b28ec4ddec0cb5f59df97c994db4
		$minRounds = 75000; // <25 kH/s/GPU
		$hashName = 'sha512';
		$hashRepeats = ($pwLen + 63) >> 6;
	}

	// Generate 96 bit $salt
	$salt = str_replace('+', '.', base64_encode(random_bytes(12)));

	// Min rounds
	$rounds = intval($rounds);
	if ($rounds < $minRounds)
	{
		$rounds = $minRounds;
	}
	else if ($rounds > 999999999)
	{
		$rounds = 999999999;
	}

	// Do some dumb stuff
	$hash = hash($hashName, $pw . $salt . $pw, true);

	// Do some dumber stuff
	$ctx = hash_init($hashName);
	hash_update($ctx, $pw . $salt);
	hash_update($ctx, substr(str_repeat($hash, $hashRepeats), 0, $pwLen));
	for ($i = $pwLen; $i > 0; $i >>= 1)
	{
		if (($i & 1) != 0)
		{
			hash_update($ctx, $hash);
		}
		else
		{
			hash_update($ctx, $pw);
		}
	}
	$hash = hash_final($ctx, true);

	// Do the dumbest stuff
	// Create DoS hash O(pwLen^2)
	$ctx = hash_init($hashName);
	if ($pwLen > 0)
	{
		// 1 <= $count <= $pwLen
		// strlen($tmp) <= max(2048, $pwLen)
		$count = max(1, min((int) floor(2048 / $pwLen), $pwLen));
		$tmp = str_repeat($pw, $count);
		for ($i = $pwLen; $i >= $count; $i -= $count)
		{
			hash_update($ctx, $tmp);
		}
		if ($i > 0)
		{
			hash_update($ctx, str_repeat($pw, $i));
		}
	}
	$dosHash = hash_final($ctx, true);

	// Do pointless stuff
	$pHash = substr(str_repeat($dosHash, $hashRepeats), 0, $pwLen);
	$sHash = substr(hash($hashName, str_repeat($salt, ord($hash[0]) + 16), true), 0, 16);

	// Do more pointless stuff that ends up being a DoS.
	// BUT there's a larger DoS with $dosHash... So *shrug*.
	$pp  = $pHash . $pHash;
	$ps  = $pHash . $sHash;
	$sp  = $sHash . $pHash;
	$psp = $ps . $pHash;
	$spp = $sp . $pHash;
	for ($i = 42; $i < $rounds; $i += 42)
	{
		$hash = hash($hashName, $hash  . $pHash, true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $pp    . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $pp,    true);
		$hash = hash($hashName, $ps    . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $pp    . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $pp,    true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $sp,    true);
		$hash = hash($hashName, $pp    . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $pp,    true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $pHash . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $pp,    true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $pp    . $hash,  true);
		$hash = hash($hashName, $hash  . $sp,    true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $pp,    true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $pp    . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $ps    . $hash,  true);
		$hash = hash($hashName, $hash  . $pp,    true);
		$hash = hash($hashName, $psp   . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $pp    . $hash,  true);
		$hash = hash($hashName, $hash  . $spp,   true);
		$hash = hash($hashName, $psp   . $hash,  true);
	}
	for ($i -= 42; $i < $rounds; $i++)
	{
		$ctx = hash_init($hashName);
		if (($i & 1) != 0) { hash_update($ctx, $pHash); } else { hash_update($ctx, $hash); }
		if ( $i % 3  != 0) { hash_update($ctx, $sHash); }
		if ( $i % 7  != 0) { hash_update($ctx, $pHash); }
		if (($i & 1) != 0) { hash_update($ctx, $hash);  } else { hash_update($ctx, $pHash); }
		$hash = hash_final($ctx, true);
	}

	// OH WOW... This is the dumbest most misguided thing.
	//
	// I get trying "let's do stupid stuff because it's harder for attackers to optimized".
	// Even though that's stupid and doesn't work. Note attackers will base64 decode and
	// undo this whole mess and have the final hash.
	//
	// Why didn't they just use PBKDF2 with 16 to 32 bytes of output encoded as hex?
	// Did you know that PBKDF2 is almost a decade older than shacrypt?
	if ($isSha256)
	{
		$magic = '$5$';
		$pad = "\0";
		$stupid = [31, 30,
			9, 19, 29, 18, 28,  8, 27,  7, 17,
			6, 16, 26, 15, 25,  5, 24,  4, 14,
			3, 13, 23, 12, 22,  2, 21,  1, 11,
			0, 10, 20];
	}
	else
	{
		$magic = '$6$';
		$pad = "\0\0";
		$stupid = [63,
			62, 20, 41, 40, 61, 19, 18, 39, 60,
			59, 17, 38, 37, 58, 16, 15, 36, 57,
			56, 14, 35, 34, 55, 13, 12, 33, 54,
			53, 11, 32, 31, 52, 10,  9, 30, 51,
			50,  8, 29, 28, 49,  7,  6, 27, 48,
			47,  5, 26, 25, 46,  4,  3, 24, 45,
			44,  2, 23, 22, 43,  1,  0, 21, 42];
	}
	$tmp = $hash;
	for ($i = 0; $i < count($stupid); $i++)
	{
		$tmp[$i] = $hash[$stupid[$i]];
	}
	$encodedHash = strrev(substr(strtr(base64_encode($pad . $tmp),
		'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
		'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'), strlen($pad)));
	return $magic . 'rounds=' . $rounds . '$' . $salt . '$' . $encodedHash;
}
