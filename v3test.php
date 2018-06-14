<?php require('pppv3.php');
$start = microtime(true);
var_dump(ppp3::newKey());
var_dump(microtime(true)-$start);
?>