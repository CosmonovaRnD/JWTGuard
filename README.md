# Symfony Guard JWT Authenticator

## Installing

- Install package using composer

> composer require cosmonova-rnd/jwt-guard

## Configuring

- Configure environment variables `JWT_PUBLIC_KEY` and `JWT_PASSPHRASE` with public key and passphrase

- Add to your firewall new authenticator

example: 
```yaml
security:
    main:
        anonymous: ~
        guard:
            authenticators:
                - CosmonovaRnD\JWTGuard\Security\JwtAuthenticator
```
## Usage

Use symfony UserInterface to get authenticated user 

  
@ Cosmonova | Research & Development
