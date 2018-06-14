<?php require('dnh-ppp-new.php');
$key=ppp::newKey();
$card=ppp::getCard(1);

//ppp::guiTest();
var_dump($key);
//var_dump(ppp::checkKey($key));

//var_dump($key);
//var_dump($card);

//var_dump($card[5]['C']);
var_dump($code=ppp::getCode(0, 'C', 5));
var_dump($ref=ppp::code2ref($code));
var_dump($reconst=ppp::ref2code($ref));
//var_dump($code===$reconst);

//var_dump(ppp::test());

var_dump(ppp::getStream(0, 9, ppp::genKeyFromPass('zombie')));
//var_dump(ppp::getCode($key, 0, 2, 5));
?>