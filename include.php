<?php
$key1 = "140b41b22a29beb4061bda66b6747e14";
$enc1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
$iv1 = substr( $enc1, 0 , 32 );

echo strlen( $iv1 )."\n";
echo $iv1."\n";
?>
