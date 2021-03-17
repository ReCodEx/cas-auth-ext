<?php

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../app/ConfigException.php';
require_once __DIR__ . '/../app/Config.php';
require_once __DIR__ . '/../app/TokenGenerator.php';
require_once __DIR__ . '/../app/Application.php';


App\Application::run();
