<?php

if ($_SERVER['PHP_AUTH_PW']) {
  echo '<pre>';
  echo 'User: ' . $_SERVER['PHP_AUTH_USER'] . "\n\n";
  echo 'Attributes: ';
  print_r(json_decode(gzinflate(base64_decode($_SERVER['PHP_AUTH_PW']))));
  echo '</pre>';
} else {
  echo "Not authenticated!";
}
