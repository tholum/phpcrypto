<?php 
class hexstring {
	public $string;
	public $hex;
	 function hex2str($hex) {
		$str = '';
    		for($i=0;$i<strlen($hex);$i+=2)
    			$str .= chr(hexdec(substr($hex,$i,2)));

    		return $str;
  	}
	function to_hex(){
		return $this->hex;
	}
	function xorb( $b1 , $b2 ){
		$sum = (int)$b1 + (int)$b2;
		if( $sum == 0 || $sum == 2 ){
			return 0;
		}
		if( $sum ==1 ){
			return 1;
		}
	}
	function xornib( $nib1 , $nib2 ){
		$x = 0;
		$return = "";
		while( $x <= 3 ){
			$return .= $this->xorb( substr($nib1 , $x , 1 ) , substr( $nib2 , $x , 1)  );
			$x++;
		}
		return $return;
	}
	function binnib_to_hex( $nib ){
                switch( strtolower($nib) ){
                        case "0000":
                                $return = "0";
                        break;
                        case "0001":
                                $return = "1";
                        break;
                        case "0010":
                                $return = "2";
                        break;
                        case "0011":
                                $return = "3";
                        break;
                        case "0100":
                                $return = "4";
                        break;
                        case "0101":
                                $return = "5";
                        break;
                        case "0110":
                                $return = "6";
                        break;
                        case "0111":
                                $return = "7";
                        break;
                        case "1000":
                                $return = "8";
                        break;
                        case "1001":
                                $return = "9";
                        break;
                        case "1010":
                                $return = "a";
                        break;
                        case "1011":
                                $return = "b";
                        break;
                        case "1100":
                                $return = "c";
                        break;
                        case "1101":
                                $return = "d";
                        break;
                        case "1110":
                                $return = "e";
                        break;
                        case "1111":
                                $return = "f";
                        break;
                }
		return $return;

	}
	function hexnib_to_bin($char){
		switch( strtolower($char) ){
			case "0":
				$return = "0000";
			break;
			case "1":
				$return = "0001";
			break;
			case "2":
				$return = "0010";
			break;
			case "3":
				$return = "0011";
			break;
			case "4":
				$return = "0100";
			break;
			case "5":
				$return = "0101";
			break;
			case "6":
				$return = "0110";
			break;
			case "7":
				$return = "0111";
			break;
			case "8":
				$return = "1000";
			break;
			case "9":
				$return = "1001";
			break;
			case "a":
				$return = "1010";
			break;
			case "b":
				$return = "1011";
			break;
			case "c":
				$return = "1100";
			break;
			case "d":
				$return = "1101";
			break;
			case "e":
				$return = "1110";
			break;
			case "f":
				$return = "1111";
			break;
		}
		return $return;
	}
	function xor_hexstr( $string2 , $string1="" ){
		if( $string1 == '' ){
			$string1 = $this->string;
		}
		$len1 = strlen( $string2 );
		$len2 = strlen( $string1 );
		if( $len1 > $len2 ){
			$len = $len2;
		} else { 
			$len = $len1;
		}
		$x = 0;
		$return = "";
		while( $x < $len ){
			//echo "$x\n";
			$nib1 = $this->hexnib_to_bin(substr($string1,$x,1));
			$nib2 = $this->hexnib_to_bin(substr( $string2,$x,1));
			$xor_chr = $this->xornib( $nib1 , $nib2 );
			$return .= $this->binnib_to_hex( $xor_chr );
			$x++;
		}
		return $return;
	
	}
	function hex_to_bin($hexbyte="00"){
		$nibble_hxa = substr($hexbyte,0,1);
		$nibble_hxb = substr($hexbyte,1,1);
		//echo "$nibble_hxa:$nibble_hxb = " . $this->hexnib_to_bin($nibble_hxa) . " " . $this->hexnib_to_bin($nibble_hxb) . "\n";
		return $this->hexnib_to_bin($nibble_hxa) . $this->hexnib_to_bin($nibble_hxb) ;
	}
	function __construct($string){
		$this->string = $string;
		$this->string_to_hex();
	}
	function string_to_hex(){
		$lenght = strlen( $this->string );
		$x = 0;
		$this->hex = array();
		while( $x <= $lenght/2 ){
			$this->hex[] = substr( $this->string , $x*2, 2);
			$x++;	
		}
	}

}

$a = array();
$target = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904";
$a[] = "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e";
$a[] = "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f";
$a[] = "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb";
$a[] = "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa";
$a[] = "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070";
$a[] = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4";
$a[] = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce";
$a[] = "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3";
$a[] = "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027";
$a[] = "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83";

/*echo strlen( $target )."\n";
echo "\t". $target . "\n";
$t = array();
foreach( $a as $str ){
	echo "\t".substr( $str , 0 , strlen( $target ) ) . "\n";
	$t[] = substr( $str , 0 , strlen( $target ) );
}
$x = 0;
$r = array();
*/
$str1="32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904";
$str2="315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba50";
$str3="234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb741";
$str4="32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de812";
$str5="32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee41";
$str6="3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de812";
$str7="32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d";
$str8="32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af513";
$str9="315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e941";
$str10="271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f404";
$str11="466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d";
$ss = array($str1,$str2,$str3,$str4,$str5,$str6,$str7,$str8,$str9,$str10,$str11);

$hex1 = new hexstring($str1);
$hex2 = new hexstring( $str2 );
$hex3 = new hexstring( $str3);
$hex4 = new hexstring( $str4);
$hex5 = new hexstring( $str5 );
$hex6 = new hexstring( $str6 );
$hex7 = new hexstring( $str7 );
$hex8 = new hexstring( $str8 );
$hex9 = new hexstring( $str9 );
$hex10 = new hexstring( $str10 );
$hex11 = new hexstring( $str11 );
//var_dump( $hex1->hex ) ;

//echo $hex1->hex_to_bin("FF") . "\n";
//echo $hex1->hex_to_bin("00") . "\n";
//echo $hex1->hex_to_bin("9b") . "\n";
//echo "::".$hex1->xornib( "0110" , "1100" )."\n";


echo $hex1->xor_hexstr( "40" , "40" )."\n";
echo $hex1->xor_hexstr( "40404040404040404040" , "7a" )."\n";
echo $hex1->xor_hexstr( "20" , "40" )."\n";
echo $hex1->xor_hexstr( "20" , "7a" )."\n";

//$key = $hex1->xor_hexstr("54686520736563726574206d6573736167652069733a205768656e207573696e6720612073747265616d206369706865722c206e6576657220");
//$key = $hex1->xor_hexstr("54686520736563726574206d6573736167652069733a205768656e207573696e6720612073747265616d206369706865722c206e657665722075736520746865206b6579206d6f726520");

//$key = $hex2->xor_hexstr("57652063616e20666163746f7220746865206e756d6265722031352077697468207175616e74756d20636f6d7075746572732e2057652063616e20616c736f20666163746f7220746865206e756d62657220");
//$key = $hex3->xor_hexstr("45756c657220776f756c642070726f6261626c7920656e6a6f792074686174206e6f7720686973207468656f72");
//$key = $hex6->xor_hexstr("596f7520646f6e27742077616e7420746f20627579206120736574206f6620636172206b6579732066726f6d20612067757920");
//$key = $hex4->xor_hexstr("546865206e696365207468696e672061626f7574");
//$key = $hex9->xor_hexstr("57652063616e207365652074686520706f696e742077686572652074686520");
//$key = $hex5->xor_hexstr("54686520636970686572746578742070726f64756365642062792061207765616b20656e6372797074696f6e20616c676f726974686d206c6f6f6b7320617320676f6f6420617320636970686572");
//$key = $hex7->xor_hexstr("5468657265206172652074776f207479706573206f662063727970746f677261706879");

//$key = $hex8->xor_hexstr("5468657265206172652074776f207479706573206f6620637970746f6772617068793a206f6e65207468617420616c6c6f77732074686520476f7665726e6d656e74");
$key = $hex10->xor_hexstr("412028707269766174652d6b6579292020656e6372797074696f6e20736368656d6520737461746573203320616c676f726974686d732c206e616d656c7920612070726f63656475726520666f722067656e65726174696e67");
//$key = $hex11->xor_hexstr("2054686520436f6e63697365204f78666f726444696374696f6e61727920283230303629206465efac816e65732063727970746f2061732074686520");
$h = array();
foreach( $ss as $n => $t ){
	$h[] = new hexstring( $t );
	echo "\nSTR $n = \t" . $hex1->xor_hexstr( $key  , $t ) . "\n";
	echo "DEC: $n = " . $hex1->hex2str($hex1->xor_hexstr( $key , $t )) . "\n\n";
}
$answer = new hexstring( "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904");
$answ = $answer->xor_hexstr($key);

file_put_contents('key.txt',$key . "\n" . $answ);
/*
foreach( $h as $me => $hs ){
	foreach( $h as $me2 => $hs2 ){
		if( $me != $me2 ){
			echo "$me => $me2\t". $hs->xor_hexstr( $hs2->string ) . "\n";
		}
	}
}
echo $key . "\n\n";
echo $hex1->xor_hexstr($str2,$str1)."\n";
echo $hex1->xor_hexstr($str3,$str1)."\n";
echo $hex1->xor_hexstr($str4,$str1)."\n";
echo $hex1->xor_hexstr($str5,$str1)."\n";
echo $hex1->xor_hexstr($str6)."\n";
echo $hex1->xor_hexstr($str7)."\n";
echo $hex1->xor_hexstr($str8)."\n";
echo $hex1->xor_hexstr($str9)."\n";
echo $hex1->xor_hexstr($str10)."\n";

*/

//var_dump( base_convert( $str1 , 16 ,16 ) );



//var_dump( $t);
/*while( $x <= strlen( $target ) / 2 ){
	$tmparr = array();
	foreach( $t as $str ){
		echo $str."::\n";
		$hx = substr( $str , $x *2 , 2 );
		if( !array_key_exists( $tmparr , $hx )){
			$tmparr[$hx] = 0;
		} 
		$tmparr[$hx]++;
	}
	$r[] = $tmparr;
	$x++;
}*/
//var_dump( $r);


?>
