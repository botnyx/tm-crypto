<?php 

namespace botnyx\crypto;


class hashing {
	
	/*
		https://github.com/strawbrary/php-blake2
		
		Usage:

		string blake2 ( string $str [, int $outputSize = 64, string $key, bool $rawOutput = false ] )

		$str: The string to hash
		$outputSize: The length of the output hash (can be between 1 and 64)
		$key: Turns the output into a keyed hash using the specified key
		$rawOutput: If set to true, then the hash is returned in raw binary format

		Return value: A hex string containing the BLAKE2 hash of the input string


		string blake2b ( string $str [, int $outputSize = 64, string $key, bool $rawOutput = false ] )
		is an alias to blake2

		string blake2s ( string $str [, int $outputSize = 32, string $key, bool $rawOutput = false ] )

		$str: The string to hash
		$outputSize: The length of the output hash (can be between 1 and 32)
		$key: Turns the output into a keyed hash using the specified key
		$rawOutput: If set to true, then the hash is returned in raw binary format

		Return value: A hex string containing the BLAKE2s hash of the input string

		Examples
		echo blake2('');
		786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce

		echo blake2('Hello world', 20);
		5ad31b81fc4dde5554e36af1e884d83ff5b24eb0

		echo blake2('Hello world', 20, 'foobar');
		5b4bbc84b59ab5d9146089b143fd52f38638dcac

		echo blake2s('');
		Outputs : 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9

		More Info
		https://blake2.net/
		
		
		
		blake2 comes in two flavors:
		
		blake2b (or just BLAKE2)is optimized for 64-bit platforms—including NEON-enabled ARMs—and produces digests of any size between 1 and 64 bytes
		blake2s is optimized for 8- to 32-bit platforms and produces digests of any size between 1 and 32 bytes
	
	*/
	
	var $outputSize = 64;
	var $rawOutput = false;
	var $key = 'our hashing salt';
	
	
	
	function __construct(){
		
		if( !function_exists( 'blake2' ) ){
			error_log('Blake2 is not available!');
			error_log('Please enable in your php.ini `extension=blake2` ');
			
			
			
			die("this system does not meet the security standards.");
			
			
			
		}
		
		
		error_log(__DIR__);
	}
	
	

	
	
	private function blake2($str){
		return  blake2 ( $str ,$this->outputSize, $this->key, $this->rawOutput);
	}
	
	
	
	
	
	public function hash($str,$password=false,$properties){
		
		if($password){
			return $this->getPasswordHash($str);
		}else{
			$this->outputSize = $properties['hash_size'];
			$this->key = $properties['hash_key'];
			return $this->blake2($str);
		}
	}
	
	public function verifyhash($original,$supplied,$password=false,$properties){
		if($password){
			return  $this->checkPasswordHash($original, $supplied);
		}else{
			$this->outputSize = $properties['hash_size'];
			$this->key = $properties['hash_key'];
			
			return  (bool)$this->blake2($supplied)==$original;	
		}
	}
	
	
	
	/* Libsodium hash validation */
	public function checkPasswordHash($dbhash, $plaintext)
    {     
		if (sodium_crypto_pwhash_str_verify($dbhash, $plaintext)) {
			// recommended: wipe the plaintext password from memory
			sodium_memzero($plaintext);
			// Password was valid
			return true;
		} else {
			// recommended: wipe the plaintext password from memory
			sodium_memzero($plaintext);
			// Password was invalid.
			return false;
		}
    }

    /* Libsodium hashing */
    public function getPasswordHash($password)
    {
        // hash the password and return an ASCII string suitable for storage
		$hash_pass = sodium_crypto_pwhash_str(
			$password,
			SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
			SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
		);
		// recommended: wipe the plaintext password from memory
		sodium_memzero($password);
		
		return $hash_pass;
    }
	
	
	
	
	
}
