<?php

// PPP in PHP (November 2, 2007)
// An implementation of the PPP CryptoSystem designed by Steve Gibson of GRC
// Full details and spec can be found at http://www.grc.com/ppp

// Implementation in PHP by Bob Somers (www.bobsomers.com)
// Tested on PHP version 5.2.3

// REQUIREMENTS:
// + PHP5, preferably 5.2.3 or higher (that's what I tested with)
// + The hash() function must support the SHA256 hash. You can check this with the hash_algos() function.
// + The bcmath extension for dealing with numbers of arbitrary size.
// + The mcrypt extension (built against libmcrypt > 2.4.x) for 128-bit Rijndael.

// define the passcode alphabet
$PC_ALPHABET = "23456789!@#%+=:?abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ";

// generates a 256-bit sequence key by hashing the passed string with SHA256
// it isn't recommended to use this method, rather, you should generate a random
// key with GenerateRandomSequenceKey() instead
// returns the sequence key as a hex string
function GenerateSequenceKeyFromString($passphrase)
{
	return hash('sha256', $passphrase);
}

// generates a random 256-bit sequence key
// returns the sequence key as a hex string
function GenerateRandomSequenceKey()
{
	$randomness = get_loaded_extensions();
	$randomness[] = php_uname();
	$randomness[] = memory_get_usage();
	$randomness = implode(microtime(), $randomness);
	return hash('sha256', $randomness);
}

// returns an array of $count passcodes starting with the passcode number $first,
// generated using the passed sequence key
// the $first and $count variables should be passed as arbitrary-length decimal strings (see the bcmath functions)
// the $sequence_key should be passed as a hex string
function RetrievePasscodes($first, $count, $sequence_key)
{
	global $PC_ALPHABET; // bring in the passcode alphabet

	$passcodes = array();
	
	// pack our hex string sequence key into a binary string
	$sk = pack("H*", $sequence_key);
	
	// because we need to handle these as aribitrary position numbers, we need to write a for loop using
	// bcmath functions (as a while loop), which is why this looks bizarre
	$i = $first;
	$limit = bcadd($first, $count);
	while (bccomp($i, $limit) < 0)
	{
		$pc_start = bcmul($i, '24'); // how many bits into the sequence does the passcode start?
		$n = bcdiv($pc_start, '128', 0); // what 128-bit block does that start in? (in other words, what's the value of our counter?)
		$offset = bcmod($pc_start, '128'); // how many bits into the n'th 128-bit block does the passcode start?
		
		if (bccomp(bcsub('128', $offset), '24') < 0)
		{
			// we don't have enough bits left in a single cipher, we're going to need to calculate two
			$ciphers = array();
			for ($j = 0; $j < 2; $j++)
			{
				$n_bits = pack("V*", bcadd($n, $j));
				error_reporting(error_reporting() & ~E_WARNING); // mcrypt complains that we aren't using an initialization vector
				$enc_bits = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $sk, $n_bits, MCRYPT_MODE_ECB);
				error_reporting(error_reporting() | E_WARNING); // we still want to get warnings, though
				$enc_hex = unpack("H*", $enc_bits);
				$ciphers[$j] = $enc_hex[1];
			}
			
			// grab the chunks we need from each cipher and combine them
			// note that $offset will always be less than 128, so we don't need to use bcmath functions here
			$first_chunk = substr($ciphers[0], $offset / 4, (128 - $offset) / 4);
			$second_chunk = substr($ciphers[1], 0, (24 - (128 - $offset)) / 4);
			$pc_hex = $first_chunk . $second_chunk;
		}
		else
		{
			// a single cipher will do the trick
			$n_bits = pack("V*", $n);
			error_reporting(error_reporting() & ~E_WARNING); // mcrypt complains that we aren't using an initialization vector
			$enc_bits = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $sk, $n_bits, MCRYPT_MODE_ECB);
			error_reporting(error_reporting() | E_WARNING); // we still want to get warnings, though
			$enc_hex = unpack("H*", $enc_bits);
			$enc_hex = $enc_hex[1];
			
			// grab the chunk which represents our passcode
			$pc_hex = substr($enc_hex, $offset / 4, 6);
		}
		
		// reverse byte order, regroup into 6-bit chunks, and translate to the passcode alphabet
		$pc_bin = str_pad(decbin(hexdec($pc_hex)), 24, "0", STR_PAD_LEFT);
		$pc_chars = array();
		for ($j = 0; $j < 3; $j++)
		{
			$pc_chars[$j] = substr($pc_bin, -8 * ($j + 1), 8);
		}
		$pc_bin = implode("", $pc_chars);
		$pc_chars = array();
		for ($j = 0; $j < 4; $j++)
		{
			$pc_chars[$j] = $PC_ALPHABET[bindec(substr($pc_bin, $j * 6, 6))];
		}
		$passcode = implode("", array_reverse($pc_chars));
		
		// add this passcode to our list of passcodes to return
		$passcodes[] = $passcode;
		
		// increment our "for" loop
		$i = bcadd($i, '1');
	}
	
	return $passcodes;
}

var_dump(GenerateSequenceKeyFromString('zombie'));

var_dump(RetrievePasscodes(0, 9, GenerateSequenceKeyFromString('zombie')));
?>