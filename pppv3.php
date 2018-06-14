<?php // PPPv3 Implementation in PHP
// Library provided by DNH Computing - http://www.dnh.net.nz/

// Author: Daniel Hodder, Nicholas Hinds
// Date: November 2007

// For configuration please skip to the like "Start Configuration"

// IMPORTENT PLEASE READ - LICENCE:
// You may distribute this code and mocify it as you please as long as you keep the origonal authors names and the name DNH Computing in a header similar to this
// An example of this would be a file confaining this phrase: "This code was based off the PPPv3 Library provided by DNH Computing - http://www.dnh.net.nz/"

// Now on with the actual code

abstract class ppp3 {
	// Start Configuration
	const checkKey = false; // Whether to check for a key that has less repeats than other keys. NOTE: This is very cpu intensive
	const checkKey_keys = 100; // The number of keys to check to find the best out of
	const checkKey_codes = 200000; // The number of passcodes to generate for EACH key
	
	const storeKey = true; // Store the key inside the class so you don't have to remember it. NOTE: this will remember the last generated key only.
	// End Configuration
	
	const cpy_aes128 = MCRYPT_RIJNDAEL_128; // Easy way of identiying the Rijndael-128 cypher
	const cpy_aes256 = MCRYPT_RIJNDAEL_256; // Easy way of identiying the Rijndael-256 cypher
	const mod_ecb = MCRYPT_MODE_ECB; // Easy way of addressing MCRYPT's ECB mode
	const chr_null = "\0"; // This is a null charictor
	const chr_nl = "\n"; // This is a new line
	const chr_rnl = "\r\n"; // This is a return charictor and then a new line
	
	private static $alphabet = '23456789!@#%+=:?abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ'; // This is the string version of the alphabet that is being used
	private static $alphabat_array = array('2','3','4','5','6','7','8','9','!','@','#','%','+','=',':','?','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','J','K','L','M','N','P','R','S','T','U','V','W','X','Y','Z'); // This is the array version of the alphabet that is being used
	
	public static function genKeyFromPass($pass, $seed=null) { // Generate a sequance key from a string. DO NOT USE IN PRODUCTION ENVIROMENTS AS THE ENTROPY IS FAR TO LOW
		trigger_error('Using a low entripy key generated from a pass-phrase', E_USER_WARNING);
		return (!is_null($seed)?hash_hmac('sha256', $pass, $seed):hash('sha256', $pass)); // Hash the passphrase
	}
	
	private static function genKey($seed=null) { // This generates high qaulity random sequance keys
		self::seedRand();
		
		$randomness = get_loaded_extensions(); // get an array of the loaded extentions
		$randomness[] = php_uname(); // Get the UNAME of this php install
		$randomness[] = memory_get_usage(); // get the mem usage
		$randomness = implode(rand(), $randomness); // Implode the array with a random integer
		
		$random_key = (!is_null($seed)?hash_hmac('sha256', $randomness, $seed):hash('sha256', $randomness)); // Make a realy, highly entropic key
		
		$seq_key = mcrypt_encrypt( // Generate the Sequance key
			self::cpy_aes256, // Using RIJNDAEL_256
			substr($random_key, 0, mcrypt_get_key_size(self::cpy_aes256, self::mod_ecb)), // Trim the key to fit
			microtime(), // Feed in microtime()
			self::mod_ecb, // Useing ECB mode
			self::genNullIV(self::cpy_aes256, self::mod_ecb) // Give it a null IV
		);
		
		return bin2hex($seq_key); // convert the binary expression to hexidecimal and then return it
	}
	
	private static function genRandomKey($seed=null) { // This makes a realy random key
		$keys = array(); // array of keys that will be picked
		$len = 0; // the legnth of the key
		$final = ''; // The final string that will be assembilled
		
		for ($i=0; $i<10; ++$i) // Loop through and assign 10 keys
			$keys[$i] = self::genKey($seed);
		
		$len = strlen($keys[0]); // Determine the legnth of the key
		
		for ($i=0; $i<$len; ++$i) // Loop through the keys
			$final .= $keys[rand(0, 9)][$i]; // Select a charictor from a random key and append it to the return string
		
		return $final; // Return it
	}
	
	public static function seedRand() { // Seed the random number generator with microtime
		srand((int)((($m=microtime(true))-((int)$m))*pow(10,(int)log10(PHP_INT_MAX))));  
	}
	
	private static function genNullIV($cypher, $mode) { // Generate a string of nulls that can be used for an IV to make mcrypt stop complaining 
		$size = mcrypt_get_iv_size($cypher, $mode); // Find how big the IV needs to be
		$return = ''; // Initilize the return string
		
		for ($i=0; $i<$size; ++$i) // Create the string of the appropreate legnth
			$return .= self::chr_null; // Append a null
		
		return $return; // Return the string of nulls
	}
	
	public static function newKey($seed=null) {
		if (self::checkKey) {
			
		} else return self::genRandomKey($seed);
	}
}
?>