<?php

namespace App;

use Firebase\JWT\JWT;
use Monolog\Logger;
use DateTime;
use DateTimeInterface;

/**
 * Helper class that process CAS attributes and can generate ReCodEx tokens.
 */
class TokenGenerator
{
    /**
     * @param string key under which affiliation attributes are stored
     */
    private $affiliationKey = 'edupersonscopedaffiliation';

    /**
     * Direct mappings between CAS attributes and properties for ReCodEx auth token.
     * @var array [ CAS attribute => recodex token property ]
     */
    private $attributeMapping = [
        'cunipersonalid' => 'id',
        'mail' => 'mail',
        'givenname' => 'firstName',
        'sn' => 'lastName',
    ];

    /**
     * @var string|null CAS user identifier (UKCO) loaded from attributes using mapping
     */
    private $id = null;

    public function getId(): ?string
    {
        return $this->id;
    }

    /**
     * @var string|null LDAP login (second user identifier)
     */
    private $login = null;

    public function getLogin(): ?string
    {
        return $this->login;
    }

    /**
     * @var string|null user's email loaded from attributes using mapping
     */
    private $mail = null;

    public function getMail(): ?string
    {
        return $this->mail;
    }

    /**
     * @var string|null user's first name loaded from attributes using mapping
     */
    private $firstName = null;

    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    /**
     * @var string|null user's last name loaded from attributes using mapping
     */
    private $lastName = null;

    public function getLastName(): ?string
    {
        return $this->lastName;
    }

    /**
     * @var string URI for ReCodEx redirect
     */
    private $uri;

    /**
     * @var string|null optional ID that is added in token when present
     */
    private $instanceId = null;

    /**
     * @var string shared secret string used for signing the token
     */
    private $jwtSecret;

    /**
     * @var array rules used to determine the role for the user
     */
    private $roles = [];

    /**
     * @var array attributes loaded from CAS
     */
    private $attributes = [];

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * @var array list of invalid/missing attributes from last validation
     */
    private $attributeErrors = [];

    public function getAttributeErrors(): array
    {
        return $this->attributeErrors;
    }

    /**
     * @var Logger
     */
    private $logger = null;

    /**
     * Initialize this helper component using configuration data.
     * @param Config $recodexConfig the 'ReCodEx' section of yaml configuration
     */
    public function __construct(Config $recodexConfig, Logger $logger)
    {
        $this->uri = $recodexConfig->uri;
        $this->jwtSecret = $recodexConfig->jwtSecret;
        $this->instanceId = $recodexConfig->safeGet('instanceId', null);
        $this->roles = $recodexConfig->safeGet('roles', []);
        foreach ($this->roles as $role) {
            if (empty($role['role']) || !is_string($role['role'])) {
                throw new ConfigException("Invalid role identification.");
            }
            if (empty($role['affiliation']) || !is_array($role['affiliation'])) {
                throw new ConfigException("Invalid affiliations specified for role {$role['role']}.");
            }
            foreach ($role['affiliation'] as $affiliation) {
                if (empty($affiliation) || !is_string($affiliation)) {
                    throw new ConfigException("Invalid affiliations specified for role {$role['role']}.");
                }
            }
        }
        $this->logger = $logger;
    }

    /**
     * Validate CAS attributes. Errors are stored in $attributeErrors member variable.
     * @return @bool true if attributes are valid
     */
    private function validateAttributes(): bool
    {
        $this->logger->debug("Loaded attributes: " . json_encode($this->attributes));

        $errors = [];
        foreach ($this->attributeMapping as $attr => $prop) {
            if (!array_key_exists($attr, $this->attributes) || !$this->attributes[$attr]) {
                $errors[] = $attr;
            }
            $this->$prop = $this->attributes[$attr];
        }

        $this->mail = $this->attributes['mail'] ?? null;
        if (is_array($this->mail)) {
            $this->mail = reset($this->mail); // take the first mail if there are more
        }
        if ($this->mail && !filter_var($this->mail, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'mail';
        }

        if (!array_key_exists($this->affiliationKey, $this->attributes)) {
            $errors[] = $this->affiliationKey;
        }

        if ($errors) {
            $this->logger->warning("Attributes validation failed: " . join(', ', $errors));
        }

        if (!empty($this->attributes['uid']) && is_array($this->attributes['uid'])) {
            $logins = array_filter($this->attributes['uid'], function ($login) {
                return $login !== $this->id && preg_match('/^[a-z][a-z0-9]+$/', $login);
            });
            if (count($logins) === 1) {
                $this->login = reset($logins);
            }
        }

        $this->attributeErrors = $errors;
        return count($errors) === 0;
    }

    /**
     * Get affiliations from the attributes and try to determine the correct role.
     * Roles and associated affiliations are listed in configuration.
     * @return string|null role identifier of null if the role cannot be determined
     */
    private function determineRole(): ?string
    {
        $affiliations = $this->getAffiliations();
        if (!$affiliations) {
            $this->logger->warning("User $this->id has no affiliations.");
            return null; // short cut to save time
        }

        // let us build an index of existing affiliations, so we can test it in constant time
        $affIndex = [];
        foreach ($affiliations as $affiliation) {
            $affIndex[$affiliation] = true;
        }

        foreach ($this->roles as $role) {
            // first role that matches affiliations is on
            foreach ($role['affiliation'] as $affiliation) {
                // at least one of the affiliations should match...
                if (array_key_exists($affiliation, $affIndex)) {
                    return $role['role'];
                }
            }
        }

        $affStr = join(', ', $affiliations);
        $this->logger->warning("User $this->id affiliations ($affStr) do not map to any role.");
        return null;
    }

    /**
     * Load CAS data.
     * @param array attributes associated with signed user
     * @return bool whether the attributes are valid
     */
    public function load(array $attributes): bool
    {
        $this->attributes = $attributes;
        return $this->validateAttributes();
    }

    /**
     * Parse the attributes and return when the user actually perform the authentication.
     * @return DateTime|null if the attribute is missing or incorrect, null is returned
     */
    public function getAuthenticatedAt(): ?DateTime
    {
        $date = $this->attributes['authenticationDate'] ?? null;
        if ($date) {
            $date = DateTime::createFromFormat(DateTimeInterface::RFC3339_EXTENDED, $date);
        }
        return $date ? $date : null; // make sure any false-like value is casted to null
    }

    /**
     * Return raw affiliations as returned from CAS.
     * @return array
     */
    public function getAffiliations(): array
    {
        $affiliations = !empty($this->attributes[$this->affiliationKey])
            ? $this->attributes[$this->affiliationKey]
            : [];

        if (!is_array($affiliations)) {
            $affiliations = [$affiliations];
        }
        return $affiliations;
    }

    /**
     * Return URL refering back to ReCodEx (including the newly created JWT).
     * @return string complete URL
     */
    public function getRedirectUrl(): string
    {
        // prepare payload
        $payload = [
            'iat' => time(), // to make sure this token will not last forever
            'role' => $this->determineRole(),
        ];

        // add user identification properties
        foreach ($this->attributeMapping as $prop) {
            $payload[$prop] = $this->$prop;
        }

        if ($this->login) {
            // add login as extra ID for LDAP UK
            $payload['extId'] = ['ldap-uk' => $this->login];
        }

        if ($this->instanceId) {
            $payload['instanceId'] = $this->instanceId;
        }

        $token = JWT::encode($payload, $this->jwtSecret, "HS256");
        return $this->uri . '?token=' . urlencode($token);
    }
}
