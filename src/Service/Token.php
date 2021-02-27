<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use DateTimeZone;
use DateTimeImmutable;
use DateTimeInterface;
use think\App;
use xiaodi\JWTAuth\Config\Token as Config;
use xiaodi\JWTAuth\Handle\RequestToken;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token as JwtToken;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\Clock\SystemClock;
use xiaodi\JWTAuth\Exception\JWTException;

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

    public function initJwtConfiguration()
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

    public function getToken()
    {
        return $this->token;
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
        $builder = $this->jwtConfiguration->builder()
            ->permittedFor($this->config->getAud())
            ->issuedBy($this->config->getIss())
            ->identifiedBy((string)$identifier)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime($now))
            ->relatedTo((string) $identifier)
            ->withClaim('store', $this->getStore());

        foreach ($claims as $key => $value) {
            $builder->withClaim($key, $value);
        }

        return $builder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }

    public function getExpiryDateTime($now): DateTimeImmutable
    {
        $ttl = (string)$this->config->getExpires();
        return $now->modify("+{$ttl} sec");
    }

    /**
     *
     * @param string $token
     * @return JwtToken
     */
    public function parse(string $token): JwtToken
    {
        $this->token = $this->jwtConfiguration->parser()->parse($token);

        return $this->token;
    }

    /**
     * 效验 Token
     * @param string $token
     * @return boolean
     */
    public function validate(string $token)
    {
        $token = $this->parse($token);
        $this->jwtConfiguration->setValidationConstraints(
            new ValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get()))),
            new SignedWith($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey())
        );

        $constraints = $this->jwtConfiguration->validationConstraints();

        return $this->jwtConfiguration->validator()->validate($token, ...$constraints);
    }

    public function login(JwtToken $token)
    {
        $this->app->get('jwt.manange')->login($token);
    }

    public function logout(?string $token): void
    {
        $token = $token ?: $this->getRequestToken();
        $token = $this->parse($token);

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

        $token = $requestToken->get($this->config->getType());

        return $token;
    }

    public function isRefreshExpired(DateTimeInterface $now): bool
    {
        if (!$this->token->claims()->has('iat')) {
            return false;
        }

        $iat = $this->token->claims()->get('iat');
        $refresh_ttl = $this->config->getRefreshTTL();
        $refresh_exp = $iat->modify("+{$refresh_ttl} sec");
        return $now >= $refresh_exp;
    }

    /**
     * @var Config
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * Token 自动续期
     *
     * @param Token $token
     * @param int|string $ttl 秒数
     * @return void
     */
    public function automaticRenewalToken(JwtToken $token)
    {
        $claims = $token->claims()->all();

        $jti = $claims['jti'];
        unset($claims['aud']);
        unset($claims['iss']);
        unset($claims['jti']);
        unset($claims['iat']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['sub']);

        $token = $this->make($jti, $claims);
        $refreshAt = $this->config->getRefreshTTL();

        header('Access-Control-Expose-Headers:Automatic-Renewal-Token,Automatic-Renewal-Token-RefreshAt');
        header("Automatic-Renewal-Token:" . $token->toString());
        header("Automatic-Renewal-Token-RefreshAt:$refreshAt");

        return $token;
    }
}
