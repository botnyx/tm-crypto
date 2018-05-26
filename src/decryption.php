<?php 

namespace botnyx\tmcrypto;

class decryption {
	
	
	public function decrypt( $encrypted_message, $type){
			
		if(is_string($encrypted_message)){ 
			$encrypted_message = hex2bin($encrypted_message);
		}
		
		
		$_nonce		=hex2bin($type['nonce']);
		$_secret_key=hex2bin($type['secretkey']);
		$_block_size=(int)$type['blocksize'];
		
		$decrypted_padded_message = sodium_crypto_secretbox_open($encrypted_message, $_nonce, $_secret_key);
		$decrypted_message = sodium_unpad($decrypted_padded_message, $_block_size);
		return $decrypted_message;//bin2hex($decrypted_message);		
	}
	
}

