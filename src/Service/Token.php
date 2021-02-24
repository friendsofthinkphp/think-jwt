<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use DateTimeZone;
use DateTimeImmutable;
use think\App;
use xiaodi\JWTAuth\Config\Token as Config;
use xiaodi\JWTAuth\Handle\RequestToken;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token as JwtToken;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\Clock\SystemClock;

/**
 *
 * @method JwtToken make()
 * @method bool verify()
 */
class Token
{
    /**
     *
     * @var Config
     */
    protected $config;

    /**
     *
     * @var array
     */
    protected $claims;

    /**
     *
     * @var JwtToken
     */
    protected $token;

    /**
     * @var Configuration
     */
    private $jwtConfiguration;

    public function __construct(App $app)
    {
        $this->app = $app;
        $this->init();
    }

    protected function init()
    {
        $this->resolveConfig();
        $this->initJwtConfiguration();
    }

    protected function initJwtConfiguration()
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            $this->config->getSigner(),
            InMemory::base64Encoded($this->config->getSigningKey())
        );
    }

    protected function getStore()
    {
        return $this->app->get('jwt')->getStore();
    }

    protected function resolveConfig()
    {
        $store = $this->getStore();
        $options = $this->app->config->get("jwt.stores.{$store}.token", []);

        if (!empty($options)) {
            $this->config = new Config($options);
        } else {
            throw new JWTException($store . '应用 Token 配置未完整', 500);
        }
    }

    public function make($identifier, array $claims = []): JwtToken
    {
        $now   = new DateTimeImmutable();
        return $this->jwtConfiguration->builder()
            ->permittedFor($this->config->getAud())
            ->issuedBy($this->config->getIss())
            ->identifiedBy((string)$identifier)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime($now))
            ->relatedTo((string) $identifier)
            ->withClaim('scopes', json_encode($claims))
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }

    public function getExpiryDateTime($now): DateTimeImmutable
    {
        $ttl = (string)$this->config->getExpires();
        return $now->modify("+{$ttl} sec");
    }

    public function parseToken(string $token): JwtToken
    {
        $token = $this->jwtConfiguration->parser()->parse($token);
        return $token;
    }

    /**
     * 验证成功的Token
     *
     * @return JWTToken
     */
    public function getToken(): ?JwtToken
    {
        return $this->token;
    }

    public function verify(string $token): ?bool
    {
        $this->token = $this->parseToken($token);

        $this->jwtConfiguration->setValidationConstraints(
            new ValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get()))),
            new SignedWith($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey())
        );

        $constraints = $this->jwtConfiguration->validationConstraints();

        if (!$this->jwtConfiguration->validator()->validate($this->token, ...$constraints)) {
            throw new JWTException('效验失败', 401);
        }

        return true;
    }

    public function logout(?string $token): void
    {
        $token = $token ?: $this->getRequestToken();
        $token = $this->parseToken($token);

        $this->app->get('jwt.manager')->logout($token);
    }

    /**
     * 自动获取请求下的Token.
     *
     * @return string
     */
    public function getRequestToken(): string
    {
        $requestToken = new RequestToken($this->app);

        $token = $requestToken->get($this->config->getTokenType());

        return $token;
    }

    public function getType(): string
    {
        return $this->config->getTokenType();
    }
}
