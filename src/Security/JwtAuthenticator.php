<?php
declare(strict_types=1);

namespace CosmonovaRnD\JWTGuard\Security;

use CosmonovaRnD\JWT\Exception\NotSupportedAlgorithmException;
use CosmonovaRnD\JWT\Parser\Parser;
use CosmonovaRnD\JWT\Verifier\Verifier;
use DateTimeImmutable;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use function strpos;

/**
 * Class JwtAuthenticator
 *
 * @author  Aleksandr Besedin <bs@cosmonova.net>
 * @package CosmonovaRnD\JWTGuard\Security
 * Cosmonova | Research & Development
 */
class JwtAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var Parser
     */
    private $parser;
    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * JwtAuthenticator constructor.
     *
     * @param Parser   $parser
     * @param Verifier $verifier
     */
    public function __construct(Parser $parser, Verifier $verifier)
    {
        $this->parser   = $parser;
        $this->verifier = $verifier;
    }

    /**
     * @param Request                      $request
     * @param AuthenticationException|null $authException
     *
     * @return JsonResponse
     */
    public function start(Request $request, AuthenticationException $authException = null): JsonResponse
    {
        return new JsonResponse(['message' => $authException->getMessage()], Response::HTTP_UNAUTHORIZED);
    }

    /**
     * @param Request $request
     *
     * @return bool
     */
    public function supports(Request $request): bool
    {
        return $request->headers->has('Authorization');
    }

    /**
     * @param Request $request
     *
     * @return array
     * @throws AuthenticationCredentialsNotFoundException
     * @throws CredentialsExpiredException
     * @throws AuthenticationException
     * @throws NotSupportedAlgorithmException
     */
    public function getCredentials(Request $request): array
    {
        $authorizationHeader = $request->headers->get('Authorization');
        [$tokenType, $jwt] = explode(' ', $authorizationHeader);

        $token = $this->parser->parse($jwt);

        if (null === $token || !$this->verifier->verify($token)) {
            throw new AuthenticationException('JWT token not valid');
        }

        if ($token->expires() < new DateTimeImmutable()) {
            throw  new CredentialsExpiredException('JWT expired');
        }

        $username = $token->user();

        if (null === $username) {
            throw new AuthenticationCredentialsNotFoundException('Username not found');
        }

        $roles = $token->roles();

        return [
            'username' => $username,
            'roles'    => $this->prepareRoles($roles),
        ];
    }

    /**
     * @param mixed                                                       $credentials
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $userProvider
     *
     * @return UserInterface
     * @throws \InvalidArgumentException
     */
    public function getUser($credentials, UserProviderInterface $userProvider): UserInterface
    {
        return new User($credentials['username'], null, $credentials['roles']);
    }

    /**
     * @param mixed         $credentials
     * @param UserInterface $user
     *
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user): bool
    {
        return true;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): JsonResponse
    {
        return new JsonResponse(['message' => $exception->getMessage()], Response::HTTP_FORBIDDEN);
    }

    /**
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $providerKey
     *
     * @return null|Response
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
    {
        return null;
    }

    /**
     * @return bool
     */
    public function supportsRememberMe(): bool
    {
        return false;
    }

    /**
     * @param array $roles
     *
     * @return array
     */
    private function prepareRoles(array $roles): array
    {
        foreach ($roles as $k => $role) {
            if (strpos($role, 'ROLE_') !== 0) {
                $roles[$k] = "ROLE_$role";
            }
        }

        return $roles;
    }
}
