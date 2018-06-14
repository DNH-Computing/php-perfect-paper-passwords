<?php //  DNH Computing PPP Library
// Writen by: DNH Computing. http://www.dnh.net.nz/
// Author: Daniel Hodder, and Nicholas Hinds
// Date: 11 November 2007

// This code was based off the code created by Bob Somers from http://www.bobsomers.com/

// This code is open source and you may use it for whatever you like. Please feal free to modify this code at will.

// REQUIRMENTS:
// PHP5 (This was tested on PHP 5.2.3) 
// hash() that supports sha256
// bcmath extention for dealing with numbers of arbitory size
// mcrypt extention (built from libmcrypt > 2.4.x). Must include MCRYPT_RIJNDAEL_128

abstract class ppp {
	public static $alphabet = '23456789!@#%+=:?abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ'; // The PPP alphabet
	public static $alphabet_array = array('2','3','4','5','6','7','8','9','!','@','#','%','+','=',':','?','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','J','K','L','M','N','P','R','S','T','U','V','W','X','Y','Z');
	const check = false; // Generate a given number of keys and find which one repeats least. NOTE THIS IS VERY COMPUTATIONALY INTENSIVE
	const window = 100; // The number of codes to compare
	const max = 1; // The maximum number of keys to create (0 for infinate)
	const store=true; // Whether to store the key in a varable so you don't
	
	const nl = "\n";
	const rnl = "\r\n";
	const null = "\0";
	
	public static $key=null; // Stores the key currently being used
	
	public static function genKeyFromPass($pass, $seed=null) { // Generate a sequance key from a string. DO NOT USE IN PRODUCTION ENVIROMENTS AS THE ENTROPY IS FAR TO LOW
		return (!is_null($seed)?hash_hmac('sha256', $pass, $seed):hash('sha256', $pass)); // Hash the passphrase
	}
	
	private static function genKey($seed=null) { // This generates high qaulity random sequance keys
		$randomness = get_loaded_extensions(); // get an array of the loaded extentions
		$randomness[] = php_uname(); // Get the UNAME of this php install
		$randomness[] = memory_get_usage(); // get the mem usage
		$randomness = implode(rand(), $randomness); // Implode the array with a random integer
		
		$random_key = (!is_null($seed)?hash_hmac('sha256', $randomness, $seed):hash('sha256', $randomness)); // Make a realy, highly entropic key
		
		$seq_key = mcrypt_encrypt( // Generate the Sequance key
			MCRYPT_RIJNDAEL_256, // Using RIJNDAEL_256
			substr($random_key, 0, mcrypt_get_key_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB)), // Trim the key to fit
			microtime(), // Feed in microtime()
			MCRYPT_MODE_ECB, self::genNullIV(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB) // Give it a null IV
			);
		
		return bin2hex($seq_key); // convert the binary expression to hexidecimal and then return it
	}
	
	private static function genRandomKey($seed=null) {
		$keys = array();
		$len = 0;
		$final = '';
		
		for ($i=0; $i<10; ++$i) 
			$keys[$i] = self::genKey($seed);
		
		$len = strlen($keys[0]);
		
		for ($i=0; $i<$len; ++$i)
			$final .= $keys[rand(0, 9)][$i];
		
		return $final;
	}
	
	public static function newKey($seed=null) {
		if (self::check) { // Check the key for repeated codes from the keys
			$keys = array(); // This is where all the keys are going to be stored
			for ($key=0; $key<self::max; ++$key) // generate a lot of keys
				array_push($keys, self::genRandomKey($seed));
			
			$key = self::checkKeys($keys); // Check all the keys and give us the best one
			if (self::store) self::$key = $key; // If you want it stored, store it
			return $key; // return in
		} else { // You obviosly are silly not checking the entriopy of the key and all
			$key = self::genRandomKey($seed); // Generate the key
			if (self::store) self::$key = $key; // Store it
			return $key; // Not checking and just taking the first thing out of the generator.
		}
	}
	
	public static function checkKeys($keys) { // Check the key
		$diffs = array(); // Array of the repeting numbers for all the different keys
		foreach ($keys as $key) // loop through the keys and put them into the array
			$diffs[$key]=self::checkKey($key); // whilst checking their entropy
		
		$highest=0; // Counter type thing
		foreach ($diffs as $diff) // loop through all the keys again
			if ($diff > $highest) $highest=$diff; // Find the key with highest repeting value
		
		return array_search($highest, $diffs); // return the best key
	}
	
	public static function checkKey($key) { // Check a single key
		$codes = self::getStream(0, self::window); // get piles of passcodes
		$repeat = self::window; // value of the repats
		
		foreach ($codes as $index => $code) { // Loop throught all the passcodes
			$repeats = array_keys($codes, $code); // Find all times this key repeats in the array
			foreach ($repeats as $v) { // loop through all the repeats
				if (($v!=$index)&&($v<$repeat)) // not the one we are looking at, and closer than the value in memery
					$repeat=($v<$index?($index-$v):($v-$index)); // update the counter with the correct value
			}
		}

		return $repeat;
	}
	
	public static function array2string($array) {
		$out = '';
		foreach ($array as $v) $out .= $v;
		return $out;
	}
	
	public static function code2ref($code) { // be aware this returns an array of referances. NOT A STRING
		$output=array(); // Initilize the touput
		$code_len=strlen($code); // How long is the code (It sould be 4)
		for ($i=0; $i<$code_len; ++$i) // Loop through the string's charictors
			$output[] =& self::$alphabet_array[array_search($code[$i], self::$alphabet_array)];
			// Create referances to the array alphabet to save on memery

		return $output; // return the array of referances
	}
	
	public static function ref2code($ref) { // This takes a specific array as input.
		$code=''; // INitiluze the output string
		foreach ($ref as $char) // loop through the array
			$code .= $char; // append the charictor to the string
		
		return $code; // Return the code
	}
	
	public function getCard($cards, $key=null) {
		self::getKeyIfNull($key);
		
		if (is_array($cards)) { // Are we trying to get multiple cards
			$out = array();
			foreach ($cards as $v) $out[$v] = self::getCard($key, $v); // Recurce and get each card into an array
			return $out; // Return an array of cards
		} else {		
			$codeID_beginning = ($card*70)+1; // Beginning number for this card
			$codeID_end = ($card*70)+70+8; // Ending number for this card
			
			$list = array(); // List of codes in this card
			
			for ($i=$codeID_beginning; $i <= $codeID_end; ++$i) // generate all the codes we need for this card
				array_push($list, self::getIDCode($i, $key)); // Push them onto the array
			
			$card = array();
			for ($i=0; $i<10; ++$i) { // Loop through and create the rows
				$card[$i+1]=array(); // Create the array for holding the rows data
				for ($j=0; $j<7; ++$j) $card[$i+1][chr(65+$j)]=$list[$i*7+$j]; // assign the collums into the rows
			}
			
			return $card; //return the card
		}
	}
	
	public static function getCode($card=0, $row=0, $col=0, $key=null) { // BEWARE SCARY MATHS
		self::getKeyIfNull($key);
		
		if (is_numeric($col)) $codeID = ($card*70)+(($row-1)*7)+($col+1); // the collum has been given as an integer
		else $codeID = ($card*70)+(($row-1)*7)+((ord($col)-65)+1); // The colum has been given as a charictor
		
		return self::getIDCode($codeID, $key); // Get the code and return it
	}
	
	public static function getStream($start=0, $end=1, $key=null, $ref=false) {
		self::getKeyIfNull($key);
		
		$codes=array();
		for ($id=$start; $id <= $end; ++$id) { // Get the required number of passcodes and push them into an array
			if ($ref) array_push($codes, self::code2ref(self::getIDCode($id, $key)));
			else array_push($codes, self::getIDCode($id, $key)); 
		}
		return $codes;
	}
	
	// NOTE: If you don't like brain bending maths do not real below here
	
	private static function getIDCode($id, $key=null) { // This section if mainly from Bob Somers' origonal library
		self::getKeyIfNull($key);
		//var_dump($key); exit;
		
		$packed_key = pack('H*', $key);
		
		$pc_start = bcmul($id, '24'); // how many bits into the sequence does the passcode start?
		$n = bcdiv($pc_start, '128', 0); // what 128-bit block does that start in? (in other words, what's the value of our counter?)
		$offset = bcmod($pc_start, '128'); // how many bits into the n'th 128-bit block does the passcode start?
		$iv = self::genNullIV(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
		
		if (bccomp(bcsub('128', $offset), '24') < 0) {
			// we don't have enough bits left in a single cipher, we're going to need to calculate two
			$ciphers = array();
			for ($j = 0; $j < 2; $j++)
			{
				$n_bits = pack("V*", bcadd($n, $j));
				error_reporting(error_reporting() & ~E_WARNING); // mcrypt complains that we aren't using an initialization vector
				$enc_bits = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $sk, $n_bits, MCRYPT_MODE_ECB, $iv);
				error_reporting(error_reporting() | E_WARNING); // we still want to get warnings, though
				$enc_hex = unpack("H*", $enc_bits);
				$ciphers[$j] = $enc_hex[1];
			}
			
			// grab the chunks we need from each cipher and combine them
			// note that $offset will always be less than 128, so we don't need to use bcmath functions here
			$first_chunk = substr($ciphers[0], $offset / 4, (128 - $offset) / 4);
			$second_chunk = substr($ciphers[1], 0, (24 - (128 - $offset)) / 4);
			$pc_hex = $first_chunk . $second_chunk;
		} else {
			// a single cipher will do the trick
			$n_bits = pack("V*", $n);
			error_reporting(error_reporting() & ~E_WARNING); // mcrypt complains that we aren't using an initialization vector
			$enc_bits = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $packed_key, $n_bits, MCRYPT_MODE_ECB, $iv);
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
			$pc_chars[$j] = substr($pc_bin, -8 * ($j + 1), 8);
		
		$pc_bin = implode("", $pc_chars);
		$pc_chars = array();
		for ($j = 0; $j < 4; $j++)
			$pc_chars[$j] = self::$alphabet[bindec(substr($pc_bin, $j * 6, 6))];
		
		//var_dump($pc_chars);
		return implode("", array_reverse($pc_chars));
	}
	
	private static function genNullIV($cypher, $mode) {
		$size = mcrypt_get_iv_size($cypher, $mode);
		$return = '';
		
		for ($i=0; $i<$size; ++$i) 
			$return .= self::null;
		
		return $return;
	}
	
	private static function getKeyIfNull(&$key) { // Assign the key if it is not set
		if (is_null($key)) $key = self::$key; // Cool referance assign crap
	}
	
	public static function test() { // Inboult tester
		$output = array('hash'=>false, 'bcmath'=>false, 'mcrypt'=>false, 'mcrypt-rijndael'=>false, 'passphrase'=>false); // Default values. (All Fail)
		
		if (in_array('sha256', hash_algos())) $output['hash']=true; // Can we use sha256
		if ((extension_loaded('bcmath'))&&(function_exists('bcadd'))) $output['bcmath']=true; // is bcmath loaded
		if ((extension_loaded('mcrypt'))&&(function_exists('mcrypt_encrypt'))) {
			$output['mcrypt']=true; // is mcrypt loaded
			if (in_array('rijndael-128', mcrypt_list_algorithms())) $output['mcrypt-rijndael']=true; // Can mcrypt use RIJNDAEL-128
		}
		
		if (self::getIDCode(0, self::genKeyFromPass('zombie'))=='8N=3') $output['passphrase']=true; // We can generate the correct inital code from the passcode
		
		return $output; // return the array
	}
	
	public static function guiTest() {
		$tests = self::test();
		$all=true; foreach ($tests as $v) { if (!$v) $all=false; }
		
		if ($all) echo '<h1 style="color: #00FF00;">System passed</h1>'."\n";
		else echo '<h1 style="color: #FF0000;">System failed</h1>'."\n";
		
		echo '<ul>';
			if ($tests['hash']) echo '<li style="color: #00FF00;">Can use SHA256</li>';
			else echo '<li style="color: #FF0000;">Can not use SHA256</li>';
			
			if ($tests['bcmath']) echo '<li style="color: #00FF00;">Can use BCMATH</li>';
			else echo '<li style="color: #FF0000;">Can not use BCMATH</li>';
			
			if ($tests['mcrypt']) echo '<li style="color: #00FF00;">Can use MCRYPT</li>';
			else echo '<li style="color: #FF0000;">Can not use MCRYPT</li>';
			
			if ($tests['mcrypt-rijndael']) echo '<li style="color: #00FF00;">Can use MCRYPT_RIJNDAEL128</li>';
			else echo '<li style="color: #FF0000;">Can not use MCRYPT_RIJNDAEL128</li>';
			
			if ($tests['passphrase']) echo '<li style="color: #00FF00;">Can generate passcodes properly</li>';
			else echo '<li style="color: #FF0000;">Can not generate passcodes properly</li>';
		echo '</ul>';
		echo '<br />';
		echo '<h2>Sample passcard from random seed</h1>';
		echo '<pre>';
		
		$key = self::newKey();
		$card = self::getCard($key, 1);
		
		foreach ($card as $rows) {
			foreach ($rows as $value) echo $value.'    ';
			echo "\n";
		}
		
		echo '</pre>';
	}
}

?>