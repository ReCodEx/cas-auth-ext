<?php

namespace App;

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Latte\Engine as Latte;
use Latte\Loaders\FileLoader;
use phpCAS;
use Exception;
use DateTime;
use DateTimeInterface;

/**
 * Main class which acts only as a wrapper for static methods.
 * It would be overkill to do anything more elaborate.
 */
class Application
{
    private const COOKIE_NAME = 'cas-auth-ext-start';

    /**
     * Direct mappings between CAS attributes and properties for ReCodEx auth token.
     * @var array [ CAS attribute => recodex token property ]
     */
    private static $attributeMapping = [
        'cunipersonalid' => 'id',
        'mail' => 'mail',
        'givenname' => 'firstName',
        'sn' => 'lastName',
    ];

    /**
     * Internal instance of logging component.
     * @var Logger|null;
     */
    private static $log;

    /**
     * @var TokenGenerator|null
     */
    private static $tokenGenerator = null;

    /**
     * @var Latte|null
     */
    private static $latte = null;

    /**
     * Sets a cookie that marks the time of the authentication.
     * @param DateTIme|null $at the mark, null to remove the cookie
     */
    private static function setStartedCookie(DateTime $at = null): void
    {
        $value = $at === null ? '' : $at->getTimestamp();
        setcookie(self::COOKIE_NAME, $value, $at === null ? 1 : time() + 365 * 86400, '', '', true, true);
    }

    private static function getStartedCookie(): ?DateTime
    {
        if (empty($_COOKIE[self::COOKIE_NAME]) || !is_numeric($_COOKIE[self::COOKIE_NAME])) {
            return null;
        }

        $date = new DateTime();
        $date->setTimestamp((int)$_COOKIE[self::COOKIE_NAME]);
        return $date;
    }

    /**
     * Internal function that shows 500 errors.
     * @param string $message additional message to be displayed
     * @param int $httpCode response code (500 is default)
     */
    private static function internalError(string $message = '', int $httpCode = 500)
    {
        http_response_code($httpCode);
        echo "Internal error.";
        if ($message) {
            echo " $message";
        }
        exit;
    }

    /**
     * Use configuration to re-initialize internal logger component.
     * @param Config $logConfig config section for the log
     */
    private static function initializeLog(Config $logConfig): void
    {
        $logfile = __DIR__ . '/../' . $logConfig->logfile;
        $severity = @constant('\Monolog\Logger::' . $logConfig->severity);
        if ($severity === null) {
            throw new Exception("Invalid monoglog severity '$logConfig->severity' specified in configuration.");
        }
        $handler = new StreamHandler($logfile, $severity);

        self::$log->popHandler(); // remove bootstrap handler
        self::$log->pushHandler($handler);
    }

    /**
     * Initialize the PHP CAS client.
     * @param Config $casConfig CAS section from the config file
     */
    private static function initializeCAS(Config $casConfig): void
    {
        phpCAS::client(
            CAS_VERSION_3_0,
            $casConfig->server,
            $casConfig->safeGet('port', 443),
            $casConfig->safeGet('uri', '/cas'),
            $casConfig->client_base_url
        );

        $certificate = $casConfig->safeGet('certificate', null);
        if ($certificate) {
            self::$log->debug("Using $certificate PEM chain to verify CAS server.");
            $certificate = __DIR__ . '/../' . $certificate;
            if (!is_file($certificate) || !is_readable($certificate)) {
                throw new Exception("Given certificate path is either not a file or is not readable.");
            }
            phpCAS::setCasServerCACert($certificate, true);
        } else {
            phpCAS::setNoCasServerValidation();
            self::$log->info("CAS certificate chain is not validated.");
        }
    }

    /**
     * Load configuration and initialize Application class.
     * @param string $configFile path to config yaml file
     */
    private static function initialize(string $configFile): void
    {
        $config = Config::loadYaml($configFile);
        self::initializeLog($config->monolog);
        self::initializeCAS($config->CAS);
        self::$tokenGenerator = new TokenGenerator($config->ReCodEx, self::$log);

        self::$latte = new Latte();
        self::$latte->setTempDirectory(__DIR__ . '/../temp');
        self::$latte->setLoader(new FileLoader(__DIR__ . '/../templates'));
    }

    /**
     * Handles POST requests (actions).
     */
    private static function handlePostActions(): void
    {
        if (strtoupper($_SERVER['REQUEST_METHOD']) === 'POST') {
            $action = $_GET['action'] ?? '';
            if ($action === 'logout') {
                self::setStartedCookie(null);
                phpCAS::logout();
                exit;
            }

            // generic redirect for all POST requests
            header("Location: ?");
            exit;
        }
    }

    /**
     * Show template with error (some CAS attributes are missing or are invalid).
     */
    private static function showErrorTemplate(): void
    {
        $attributes = [];
        foreach (self::$tokenGenerator->getAttributes() as $name => $value) {
            if (!is_scalar($value)) {
                $value = json_encode($value, JSON_PRETTY_PRINT);
            }
            $attributes[$name] = (object)[
                'name' => $name,
                'value' => $value,
                'error' => false,
            ];
        }

        foreach (self::$tokenGenerator->getAttributeErrors() as $name) {
            if (!array_key_exists($name, $attributes)) {
                $attributes[$name] = (object)[
                    'name' => $name,
                    'value' => null,
                ];
            }
            $attributes[$name]->error = true;
        }

        ksort($attributes);

        $params = [
            'attributes' => array_values($attributes)
        ];
        self::$latte->render('error.latte', $params);
    }

    /**
     * Show the information about currently signed user with a choice to proceed or logout.
     */
    private static function showUserTemplate(): void
    {
        $params = [
            'id' => self::$tokenGenerator->getId(),
            'mail' => self::$tokenGenerator->getMail(),
            'firstName' => self::$tokenGenerator->getFirstName(),
            'lastName' => self::$tokenGenerator->getLastName(),
            'authenticatedAt' => self::getStartedCookie(),
            'affiliations' => self::$tokenGenerator->getAffiliations(),
            'recodexUrl' => self::$tokenGenerator->getRedirectUrl(),
        ];
        self::$latte->render('user.latte', $params);
    }

    /**
     * Application entry point.
     */
    public static function run(): void
    {
        // initialize log (boostrap phase)
        self::$log = new Logger('');
        self::$log->pushHandler(new StreamHandler(__DIR__ . '/../logs/bootstrap.log', Logger::WARNING));
        try {
            // load config and initialize the application
            self::initialize(__DIR__ . '/../config/config.yaml');

            // actions must be handled first (before we display anything)
            self::handlePostActions(); // in case of POST action, execution ends here

            // make sure the user is authenticated (redirects to CAS if not)
            phpCAS::forceAuthentication();

            if (!self::$tokenGenerator->load(phpCAS::getAttributes())) {
                self::showErrorTemplate();
            } else {
                $authenticatedAt = self::getStartedCookie();
                if (!$authenticatedAt) {
                    self::setStartedCookie(new DateTime());
                }

                $userLoggedSeconds = $authenticatedAt
                    ? (new DateTime())->getTimestamp() - $authenticatedAt->getTimestamp()
                    : 0;

                if ($userLoggedSeconds > 10) {
                    // the user has authenticated a while ago -> give him/her chance to logout (change account)
                    self::showUserTemplate();
                } else {
                    // the user has just autenticated -> let's not waste any time
                    header("Location: " . self::$tokenGenerator->getRedirectUrl());
                    exit;
                }
            }
        } catch (Exception $e) {
            self::$log->critical("Unhandled exception: " . $e->getMessage(), [ 'exception' => $e ]);
            self::internalError($e->getMessage());
        }
    }
}
