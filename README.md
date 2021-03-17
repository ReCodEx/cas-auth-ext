# CAS Authentication Adapter for ReCodEx

External authentication component that connects ReCodEx to CAS. This is basically a standalone application that handles CAS authentication (using native PHP CAS library). When the user is authenticated, it creates a JWT token that is passed via redirect back to ReCodEx in URL. The token holds the following items in payload:

- `iat` - timestamp when the token was issued
- `id` - external (CAS) identification of the user (e.g., UKCO in case of cuni.cz CAS).
- `firstName`, `lastName` and `mail` address of the user
- `role` identifier based on user's affiliations (rules are defined in config)
- `instanceId` - if set in config (this is a simple mechanism that will allow ReCodEx to create the user on first sign-in)

The secret key used to sign the token must be shared with ReCodEx in configuration.
