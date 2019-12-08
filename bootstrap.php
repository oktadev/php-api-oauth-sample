<?php
require 'vendor/autoload.php';
use Dotenv\Dotenv;

$dotenv = new DotEnv(__DIR__);
$dotenv->load();

// test that the variables are loaded:
echo getenv('OKTA_AUDIENCE');
