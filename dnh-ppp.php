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
// mcrypt extention (built from libmcrypt > 2.4.x). Must include MCRYPT_RIJNDAEL_256

abstract class ppp {
	public static $alphabet = '23456789!@#%+=:?abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ'; // The PPP alphabet
	public static $alphabet_array = array('2','3','4','5','6','7','8','9','!','@','#','%','+','=',':','?','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','J','K','L','M','N','P','R','S','T','U','V','W','X','Y','Z');
	const check = true; // Generate a given number of keys and find which one repeats least. NOTE THIS IS VERY COMPUTATIONALY INTENSIVE
	const window = 100; // The number of codes to compare
	const max = 1; // The maximum number of keys to create (0 for infinate)
	const store=true; // Whether to store the key in a varable so you don't
	
	public static $key=null;	
	
	private static function genKeyFromPass($pass, $seed=null) {
		return (!is_null($seed)?hash_hmac('sha256', $pass, $seed):hash('sha256', $pass)); // Hash the passphrase
	}
	
	private static function genKey($seed=null) {
		$randomness = get_loaded_extensions(); // get an array of the loaded extentions
		$randomness[] = php_uname(); // Get the UNAME of this php install
		$randomness[] = memory_get_usage(); // get the mem usage
		$randomness = implode(microtime(), $randomness); // Make a realy long string
		//return crypt::digest($randomness, $seed, 'sha256'); // Hash the string down
		return (!is_null($seed)?hash_hmac('sha256', $randomness, $seed):hash('sha256', $randomness)); // Hash the string down
	}
	
	public static function newKey($seed=null) {
		if (self::check) { // Check the key for repeated codes from the keys
			$keys = array();
			for ($key=0; $key<self::max; ++$key)
				array_push($keys, self::genKey($seed));
			
			$key = self::checkKeys($keys);
			if (self::store) self::$key = $key;
			return $key;
		} else {
			$key = self::genKey($seed);
			if (self::store) self::$key = $key;
			return $key; // Not checking and just taking the first thing out of the generator.
		}
	}
	
	public static function checkKeys($keys) {
		$diffs = array();
		foreach ($keys as $key) 
			$diffs[$key]=self::checkKey($key);
		
		$highest=0;
		foreach ($diffs as $diff) {
			if ($diff > $highest) $highest=$diff;
		}
		
		return array_search($highest, $diffs);
	}
	
	public static function checkKey($key) {
		$codes = self::getStream(0, self::window);
		$repeat = self::window;
		
		foreach ($codes as $index => $code) {
			$repeats = array_keys($codes, $code);
			foreach ($repeats as $v) {
				if (($v!=$index)&&($v<$repeat)) {
					$repeat=($v<$index?($index-$v):($v-$index));
				}
			}
		}

		return $repeat;
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
		$n = bcdiv($pc_start, '256', 0); // what 256-bit block does that start in? (in other words, what's the value of our counter?)
		$offset = bcmod($pc_start, '256'); // how many bits into the n'th 256-bit block does the passcode start?
		
		if (bccomp(bcsub('256', $offset), '24') < 0) {
			// we don't have enough bits left in a single cipher, we're going to need to calculate two
			$ciphers = array();
			for ($j = 0; $j < 2; $j++)
			{
				$n_bits = pack("V*", bcadd($n, $j));
				error_reporting(error_reporting() & ~E_WARNING); // mcrypt complains that we aren't using an initialization vector
				$enc_bits = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $packed_key, $n_bits, MCRYPT_MODE_ECB);
				error_reporting(error_reporting() | E_WARNING); // we still want to get warnings, though
				$enc_hex = unpack("H*", $enc_bits);
				$ciphers[$j] = $enc_hex[1];
			}
			
			// grab the chunks we need from each cipher and combine them
			// note that $offset will always be less than 128, so we don't need to use bcmath functions here
			$first_chunk = substr($ciphers[0], $offset / 4, (256 - $offset) / 4);
			$second_chunk = substr($ciphers[1], 0, (24 - (256 - $offset)) / 4);
			$pc_hex = $first_chunk . $second_chunk;
		} else {
			// a single cipher will do the trick
			$n_bits = pack("V*", $n);
			error_reporting(error_reporting() & ~E_WARNING); // mcrypt complains that we aren't using an initialization vector
			$enc_bits = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $sk, $n_bits, MCRYPT_MODE_ECB);
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
	
	private static function getKeyIfNull(&$key) {
		if (is_null($key)) $key = self::$key;
	}
	
	public static function test() {
		$output = array('hash'=>false, 'bcmath'=>false, 'mcrypt'=>false, 'mcrypt-rijndael'=>false, 'passphrase'=>false);
		
		if (in_array('sha256', hash_algos())) $output['hash']=true; // Can we use sha256
		if ((extension_loaded('bcmath'))&&(function_exists('bcadd'))) $output['bcmath']=true; // is bcmath loaded
		if ((extension_loaded('mcrypt'))&&(function_exists('mcrypt_encrypt'))) {
			$output['mcrypt']=true; // is mcrypt loaded
			if (in_array('rijndael-256', mcrypt_list_algorithms())) $output['mcrypt-rijndael']=true; // Can mcrypt use RIJNDAEL-256
		}
		
		var_dump(self::getIDCode(0, self::genKeyFromPass('zombie')));
		if (self::getIDCode(0, self::genKeyFromPass('zombie'))=='8N=3') $output['passphrase']=true; // Card: 1, Row: 3, Column: F; should be B8=W
		
		return $output;
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
			
			if ($tests['mcrypt-rijndael']) echo '<li style="color: #00FF00;">Can use MCRYPT_RIJNDAEL256</li>';
			else echo '<li style="color: #FF0000;">Can not use MCRYPT_RIJNDAEL256</li>';
			
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