<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use think\App;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token as JwtToken;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Parser;
use xiaodi\JWTAuth\Config\Token as Config;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\Exception\JWTInvalidArgumentException;
use xiaodi\JWTAuth\Exception\TokenAlreadyEexpired;
use xiaodi\JWTAuth\Handle\RequestToken;

/**
 * Undocumented class
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

    public function __construct(App $app)
    {
        $this->app = $app;
        $this->init();
    }

    protected function init()
    {
        $options = $this->resolveConfig();

        $this->config = new Config($options);
    }

    protected function getStore()
    {
        return $this->app->get('jwt')->getStore();
    }

    protected function resolveConfig(): array
    {
        $store = $this->getStore();
        $options = $this->app->config->get("jwt.stores.{$store}.token", []);

        if (!empty($options)) {
            return $options;
        }

        throw new JWTException($store . '应用 Token 配置未完整', 500);
    }

    protected function makeId(array $claims)
    {
        $key = $this->config->getIdKey();
        if (!array_key_exists($key, $claims)) {
            throw new JWTException("claims {$key} requried", 500);
        }

        return $claims[$key];
    }

    public function make(array $claims): JwtToken
    {
        $unique_id = $this->makeId($claims);

        $now = time();
        $expires = $now + $this->config->getExpires();
        $refreshAt = $expires + $this->config->getRefreshTTL();
        $notBefore = $this->config->getNotBefore();
        $iss = $this->config->getIss();
        $aud = $this->config->getAud();

        $builder = new Builder();
        $builder->setIssuer($iss)
            ->setAudience($aud)
            ->setId($unique_id, true)
            ->setIssuedAt($now)
            ->setNotBefore($now + $notBefore)
            ->setExpiration($expires)
            ->set('refreshAt', $refreshAt);

        $builder->set('store', $this->getStore());

        foreach ($claims as $key => $claim) {
            $builder->set($key, $claim);
        }

        $token = $builder->getToken($this->config->getSigner(), $this->config->makeSignerKey());

        return $token;
    }

    /**
     * Token 自动续期
     *
     * @param Token $token
     * @param int|string $ttl 秒数
     * @return void
     */
    protected function automaticRenewalToken(JwtToken $token)
    {
        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);
        unset($claims['refreshAt']);

        $token = $this->make($claims);
        $claims = $token->getClaims();
        $refreshAt = $claims['refreshAt'];

        header('Access-Control-Expose-Headers:Automatic-Renewal-Token,Automatic-Renewal-Token-RefreshAt');
        header("Automatic-Renewal-Token:$token");
        header("Automatic-Renewal-Token-RefreshAt:$refreshAt");

        return $token;
    }

    protected function parseToken(string $token): JwtToken
    {
        try {
            $token = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new JWTInvalidArgumentException('此 Token 解析失败', 500);
        }

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

        if (false === $this->token->verify($this->config->getSigner(), $this->config->makeSignerKey())) {
            throw new JWTException('此 Token 与 密钥不匹配', $this->config->getReloginCode());
        }

        // Token 是否已可用
        $now = time();
        $exp = $this->token->getClaim('nbf');
        if ($now < $exp) {
            throw new JWTException('此 Token 暂未可用', 500);
        }

        // 是否已过期
        if (true === $this->token->isExpired()) {
            if ($now <= $this->token->getClaim('refreshAt')) {
                // 是否开启自动续签
                if ($this->config->getAutomaticRenewal()) {
                    $this->token = $this->automaticRenewalToken($this->token);
                } else {
                    throw new TokenAlreadyEexpired('Token 已过期，请重新刷新', $this->config->getRefreshCode());
                }
            } else {
                throw new TokenAlreadyEexpired('Token 刷新时间已过，请重新登录', $this->config->getReloginCode());
            }
        } else {
            // 是否存在黑名单
            if (true === $this->app->get('jwt.manager')->wasBan($this->token)) {
                throw new TokenAlreadyEexpired('Token 已被禁用，请重新登录', $this->config->getReloginCode());
            }
        }

        $data = new ValidationData();

        $jwt_id = $this->token->getHeader('jti');
        $data->setIssuer($this->config->getIss());
        $data->setAudience($this->config->getAud());
        $data->setId($jwt_id);

        if (!$this->token->validate($data)) {
            throw new JWTException('此 Token 效验不通过', $this->config->getReloginCode());
        }

        return true;
    }

    public function refresh(string $token = null): JwtToken
    {
        $token = $token ?: $this->getRequestToken();
        $token = $this->parseToken($token);

        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);

        $this->app->get('jwt.manager')->logout($token);

        return $this->make($claims);
    }

    public function logout(?string $token = null): void
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

    public function getRefreshTTL()
    {
        return $this->config->getRefreshTTL();
    }
}
