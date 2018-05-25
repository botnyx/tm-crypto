<?php 

namespace botnyx\tm_encryption;
/*

	$c= new crypto();

	$c->encrypt("mytext","REGISTRATION");
	$c->encrypt("mytext","EMAIL");
	$c->encrypt("mytext","PROFILE");

	$c->decrypt("mytext","REGISTRATION");
	$c->decrypt("mytext","EMAIL");
	$c->decrypt("mytext","PROFILE");
	
	
	$c->hash("mytext",$password=true);
	$c->hash("mytext",$password=false,"EMAIL");
	

*/


/*
	$c = new \trustmaster\Crypto\crypto();
	$text = "Dit is een test.";


	echo '$text = "Dit is een test.";<br><br>';
	echo '$c = new \trustmaster\Crypto\crypto();<br>';
	echo '$result = $c->encrypt($text ,"REGISTRATION");<br>';
	echo "Message to be encrypted: ".$text."<br>";
	$result = $c->encrypt($text ,"REGISTRATION");
	echo "Encrypted result: ".$result."<br><br>";

	echo '$result = $c->decrypt($result ,"REGISTRATION");<br>';
	$result = $c->decrypt($result ,"REGISTRATION");
	echo "Decrypted result: ".$result."<br>";

	var_dump($text==$result);




	echo "<hr><h3>Static Hash</h3>";

	echo '$text = "Dit is een test.";<br>';
	echo '$result = $c->hash($text ,"REGISTRATION");<br>';
	$result = $c->hash($text ,"REGISTRATION");
	echo "Hashresult: ".$result."<br><br>";


	echo '$result = $c->verifyhash($text ,"REGISTRATION");<br><br>';
	$result = $c->verifyhash($text,$result ,"REGISTRATION");

	echo "verified: ";
	var_dump($result);




	echo "<br><hr><h3>Password Hash</h3>";
	$suppliedpassword="averysecretpassword";
	echo "suppliedpassword: ".$suppliedpassword."<br>";
	echo '$result1 = $c->pwhash(suppliedpassword);<br>';

	$result1 = $c->pwhash($suppliedpassword);

	echo "result1 :".$result1."<br><br>";

	echo "Lets hash the same password again<br>";
	echo '$result2 = $c->pwhash(suppliedpassword);<br>';

	$result2 = $c->pwhash($suppliedpassword);

	echo "result2 :".$result2."<br><br>";




	echo '$vresult = $c->verifypwhash($result1,$suppliedpassword);<br>';
	$vresult = $c->verifypwhash($result1,$suppliedpassword);
	var_dump($vresult);
	echo '<br>';
	echo '$vresult = $c->verifypwhash($result2,$suppliedpassword);<br>';
	$vresult = $c->verifypwhash($result2,$suppliedpassword);
	var_dump($vresult);
		

*/

class crypto {
	
	function __construct(){
		// $keys=false
		/* encryption/decryption keys */
		//if(!$keys){ 
		//	$this->keys = $this->EncryptionKeys(); 
		//}elseif(!is_array($keys)){
		//	throw new \Exception('No Encryption keys found.');
		//}
		#die();
		
		$this->cryptokeys = $this->readConfig();
		
		
		$this->e = new \botnyx\tm_encryption\encryption();
		$this->d = new \botnyx\tm_encryption\decryption();
		$this->h = new \botnyx\tm_encryption\hashing();
	}
	
	function readConfig(){
		$sf = __DIR__."/../settings.json";
		if(file_exists($sf)){
			$handle = fopen($sf, "r");
			$contents = fread($handle, filesize($sf));
			fclose($handle);
			$cs = json_decode($contents,true);
			
			switch (json_last_error()) {
				case JSON_ERROR_NONE:
					break;
				default:
					error_log("Cryptographic settings unreadable!");
					error_log("please check the Crypto settings.json");
					die("there is a problem with the security settings.");
			}
			return $cs;
			
			
		}else{
			error_log("Cryptographic settings missing!");
			error_log("please check the Crypto settings.json");
			die("this system does have the correct security settings.");
		}
		
	}
	
	
	
	/* Shows the sections we can encrypt/decrypt */
	public function help(){
		$list = array();foreach($this->getEncryptionKeys() as $k=>$v){$list[]=$k;}
		return "Supported Encryped sections: ". rtrim(implode(',', $list), ',');
	}
	
	/* Hashing methods */
	public function hash($value,$section=''){
		try{
			return $this->h->hash($value,$password=false, $this->EncryptionKeys(strtoupper($section))['h'] );
		}catch(Exception $e){
			throw new \Exception($e->getMessage());
		}
	}
	
	public function verifyhash($value,$hash,$section=''){
		
		
		try{
			return (bool)$hash==$this->hash($value,$section,$this->EncryptionKeys(strtoupper($section))['h']);
		}catch(Exception $e){
			throw new \Exception($e->getMessage());
		}
	}
	
	/* Password Hashing methods */
	public function pwhash($value){
		try{
			return $this->h->getPasswordHash($value);
		}catch(Exception $e){
			throw new \Exception($e->getMessage());
		}
	}
	
	public function verifypwhash($dbhash,$plaintext){
		try{
			return $this->h->checkPasswordHash($dbhash, $plaintext);
		}catch(Exception $e){
			throw new \Exception($e->getMessage());
		}
	}	
	
	/* Encryption method */
	public function encrypt($data,$type){
		
		//print_r($this->EncryptionKeys(strtoupper($type))['c'] );
		//['c'];
		
		try{
			return $this->e->encrypt($data,$this->EncryptionKeys(strtoupper($type))['c'] );		
		}catch(Exception $e){
			throw new \Exception($e->getMessage());
		}
	}
	
	/* Decryption method */
	public function decrypt($data,$type){
		try {
			return $this->d->decrypt($data,$this->EncryptionKeys(strtoupper($type))['c'] );	
		}catch(Exception $e){
			throw new \Exception($e->getMessage());
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/* Private methods. */
	private function EncryptionKeys($type){
		$keys = $this->getEncryptionKeys();
		if(!array_key_exists(strtoupper($type),$keys) ){
			throw new \Exception('Unknown Encryption section ['.strtoupper($type).']');
		}
		return $keys[strtoupper($type)];
	}
	
	
	/* the key section, this needs to come from some file/db/api? */
	private function getEncryptionKeys(){
		return $this->cryptokeys;
		/*
		return array('REGISTRATION'=> array(
										'h'=>array(
											'hash_size'=> 	64,
											'hash_key'=>	'mysecretkey' ),
										'c'=>array(	
											'nonce'=>		'f5de5a2935a8927268be7a358dbfe73334a7dc38d57f23df',
											'secretkey'=>	'8b49a72bb1addff71e630692e2a0c6a0f0cfa3657ff527642700b247364c19e8',
											'blocksize'=>	16 )
										),
					 'EMAIL'=> 	array(
										'h'=>array(
											'hash_size'=> 	32,
											'hash_key'=>	'mysecretkey' ),
										'c'=>array(	
											'nonce'=>		'f5de5a2935a8927268be7a358dbfe73334a7dc38d57f23df',
											'secretkey'=>	'8b49a72bb1addff71e630692e2a0c6a0f0cfa3657ff527642700b247364c19e8',
											'blocksize'=>	16 )
										),
					 'PROFILE'=> array(
										'h'=>array(
											'hash_size'=> 	64,
											'hash_key'=>	'mysecretkey' ),
										'c'=>array(	
											'nonce'=>		'f5de5a2935a8927268be7a358dbfe73334a7dc38d57f23df',
											'secretkey'=>	'8b49a72bb1addff71e630692e2a0c6a0f0cfa3657ff527642700b247364c19e8',
											'blocksize'=>	16 )
										)
					);
			*/
		
					 			
	}
	


	

	
}