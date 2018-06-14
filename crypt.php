<?php // Crypto Class
// Version 1.0 (Modified from DNH Computing's Pager)
// Author: Daniel Hodder
// Date: 16 September 2007

abstract class crypt {
	// All the algerithms that this class can use
	const aes128 = 'rijndael-128';
	const aes192 = 'rijndael-192';
	const aes256 = 'rijndael-256';
	const cast128	= 'cast-128';
	const cast256 = 'cast-256';
	const gost = 'gost';
	const loki97 = 'loki97';
	const saferplus = 'saferplus';
	const blowfish = 'blowfish';
	const des = 'des';
	const serpent = 'serpent';
	const xtea = 'xtea';
	const rc2 = 'rc2';
	const twofish = 'twofish';
	
	/**
	 * Array of all possible algerithms and their key legnths
	 *
	 * @var Array
	 */
	private static $keylen=array(
		'rijndael-192'=>192,
		'rijndael-128'=>128,
		'rijndael-256'=>256,
		'cast-128'=>256,
		'cast-256'=>256,
		'gost'=>256,
		'loki97'=>256,
		'saferplus'=>256,
		'des'=>64,
		'serpent'=>256,
		'xtea'=>128,
		'blowfish'=>448,
		'rc2'=>1024,
		'twofish'=>256
	);
	
	
	/**
	 * Encrypt data using the key provided with the supplied algerithm
	 *
	 * @param String $data
	 * @param String $key
	 * @param String $algerithm [OPTIONAL]
	 * @return Bytewise String (NULL on failiure)
	 */
	public static function encrypt($data, $key, $algerithm=self::aes256){
		if (!self::ck_algol($algerithm)) return; // If the algerithm is not supported return NULL
		$key = self::genkey($key, $algerithm); // Trim the key so that it fits the algerithm
		
		$mod = mcrypt_module_open($algerithm, '', 'ecb', ''); // Open the mcrypt module
		$iv_size = mcrypt_enc_get_iv_size($mod); // Calculate the size of the IV
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND); // Create the IV
		
		if (mcrypt_generic_init($mod, $key, $iv) != -1) { // Create the wrapper
			$cyphertext = mcrypt_generic($mod, $data); // Do the encryption
			mcrypt_generic_deinit($mod); // Deregister the wrapper
			return $cyphertext; // Return the bytewize string
		} else trigger_error('Failed to initilize encryption', E_USER_ERROR); // Error stuff
	}
	
	/**
	 * Decrypt data using key and the supplied angerithm
	 *
	 * @param Bytewize String $data
	 * @param String $key
	 * @param String $algerithm [OPTIONAL]
	 * @return Bytewize String
	 */
	public static function decrypt($data, $key, $algerithm=self::aes256) {
		if (!self::ck_algol($algerithm)) return; // If the algerithm is not supported return NULL
		$key = self::genkey($key, $algerithm); // Trim the key so that it fits the algerithm
		
		$td = mcrypt_module_open($algerithm, '', 'ecb', ''); // Open the mcrypt module
		$iv_size = mcrypt_enc_get_iv_size($td); // Calculate the size of the IV
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND); // Create the IV
		
		if (mcrypt_generic_init($td, $key, $iv) != -1) { // Create the wrapper
			$p_t = trim(rtrim(mdecrypt_generic($td, ($data)))); // Decrypt the data and remove the crap from the start and the end
			mcrypt_generic_deinit($td); // Deregister the wrapper
			return $p_t; // return the plaintext
		} else trigger_error('Failed to initilize encryption', E_USER_ERROR); // More error stuff
	}
	
	/**
	 * Check the algerithm is able to be used
	 *
	 * @param String $algol
	 * @return Boolean
	 */
	private static function ck_algol($algol) {
		if (array_key_exists($algol, self::$keylen)===false) { // search for the algerithm in the key list
			trigger_error('Algerithm not supported', E_USER_WARNING); 
			return false; 
		} else return true;
	}
	
	/**
	 * Generate an appropreate key for the algerithm
	 *
	 * @param String $key
	 * @param String $algol
	 * @return String
	 */
	public static function genkey($key, $algol) {
		if (!is_array($key)) return substr(hash('sha512', hash('sha384', $key)), 0, floor(self::$keylen[$algol]/8));
		else {
			if ((is_string($key[0]))&&(is_bool($key[1]))) {
				if ($key[1]) {
					if (strlen($key[0]) < (floor(self::$$keylen[$algol])/8)) trigger_error('Key to shor for algerithm: \''.$algol.'\'', E_USER_ERROR);
					
					return substr($key[0], 0, floor(self::$keylen[$algol])/8);
				} else return self::genkey($key[0], $algol);
			} else trigger_error('Invalid array form', E_USER_ERROR);
		}
	}
	
	/**
	 * Create a message Digest
	 *
	 * @param String $data
	 * 				Data to be digested
	 * @param String $key [OPTIONAL]
	 * 				An optional key to seed the hash
	 * @param String $algerithm [OPTIONAL]
	 * 				The algerigm used for hashing. Deafaults to sha512
	 * @return String
	 */
	public static function digest($data, $key=null, $algerithm='sha512') {
		if (!in_array($algerithm, hash_algos())) { trigger_error('Hash not supported', E_USER_WARNING); return; }
		return ($key?hash_hmac($algerithm, $data, hash('sha384', $key)):hash($algerithm, $data));
	}
	
	/**
	 * Create a signiture for a given string
	 *
	 * @param String $data
	 * @param String $key [OPTIONAL]
	 * @return String
	 */
	public static function sign($data, $key=null){
		return base64_encode(crypt::encrypt(self::digest($data, hash('sha384', $key), 'sha1'), hash('sha384', $key)));
	}
	/**
	 * Check the signiture for a given string and signiture
	 *
	 * @param String $data
	 * @param String $sig
	 * @param String $key [OPTIONAL]
	 * @return Boolean
	 */
	public static function ck_sig($data, $sig, $key=null) {
		return (self::digest($data, hash('sha384', $key), 'sha1')===self::decrypt(base64_decode($sig), hash('sha384', $key)));
	}
}
?>