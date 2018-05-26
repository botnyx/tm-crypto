<?php 

namespace botnyx\crypto;


class encryption {
	
	public function encrypt($data,$type){
		
		$_nonce		=hex2bin($type['nonce']);
		$_secret_key=hex2bin($type['secretkey']);
		$_block_size=(int)$type['blocksize'];

				
		$padded_message 	= sodium_pad($data, $_block_size);
		$encrypted_message 	= sodium_crypto_secretbox($padded_message, $_nonce, $_secret_key);
		return bin2hex($encrypted_message);		
	}
	

	
	public function genkeys(){
		// generate keys for the encryption
		$_nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$_secret_key = sodium_crypto_secretbox_keygen();
		$_block_size = 16;
		
		return array("_nonce"=>bin2hex($_nonce),"_secret_key"=>bin2hex($_secret_key),"_block_size"=>$_block_size);
	}
	
	
	
}
