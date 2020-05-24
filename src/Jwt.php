<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use think\App;
use think\Model;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\Exception\JWTInvalidArgumentException;
use xiaodi\JWTAuth\Exception\TokenAlreadyEexpired;
use xiaodi\JWTAuth\Handle\RequestToken;

class Jwt
{
    use \xiaodi\JWTAuth\Traits\Jwt;

    private $config;

    private $store;

    private $user;

    private $token;

    public function __construct(App $app, $store = null)
    {
        $this->app = $app;
        
        if ($store === null) {
            $store = $this->getDefaultStore();
        }

        $this->store = $store;
        $this->make();
    }

    public function store(string $name = '')
    {
        $jwt = app('jwt', ['store' => $name], true);
        $this->app->bind('jwt',  $jwt);
        return $jwt;
    }

    protected function make()
    {
        $this->setStoreConfig();

        return $this;
    }

    public function getStore()
    {
        return $this->store;
    }

    /**
     * 获取默认 app
     *
     * @return void
     */
    public function getDefaultStore()
    {
        $store = $this->app->config->get("jwt.default", '');
        if (!$store) {
            throw new JWTException('默认应用 未配置.', 500);
        }

        return $store;
    }

    /**
     * 获取 app jwt 配置
     *
     * @return void
     */
    public function getStoreConfig()
    {
        $config = $this->app->config->get("jwt.apps.{$this->store}.token", []);
        if (empty($config)) {
            throw new JWTException("应用: {$this->store} 未配置完整.", 500);
        }

        return $config;
    }

    protected function setStoreConfig()
    {
        $config = $this->getStoreConfig();
        foreach ($config as $key => $v) {
            $this->$key = $v;
        }
    }

    /**
     * 生成 Token.
     *
     * @param array $claims
     *
     * @return Token
     */
    public function token(array $claims): Token
    {
        $uniqid = $this->makeTokenId($claims);

        $exp = time() + $this->ttl();
        $refreshAt = $exp + $this->refreshTTL();

        $builder = new Builder();
        $builder->setIssuer($this->iss())
            ->setAudience($this->aud())
            ->setId($uniqid, true)
            ->setIssuedAt(time())
            ->setNotBefore(time() + $this->notBefore())
            ->setExpiration($exp)
            ->set('refreshAt', $refreshAt);

        foreach ($claims as $key => $claim) {
            $builder->set($key, $claim);
        }

        $token = $builder->getToken($this->getSigner(), $this->makeSignerKey());

        $this->app['jwt.manager']->login($token);

        return $token;
    }

    /**
     * 生成 Token ID.
     *
     * @param array $claims
     *
     * @return string
     */
    private function makeTokenId(array $claims): string
    {
        if (empty($claims[$this->getUniqidKey()])) {
            throw new JWTException('uniqidKey 未配置', 500);
        }

        return (string) $claims[$this->getUniqidKey()];
    }

    /**
     * 获取 当前用户.
     *
     * @return Model
     */
    public function user(): Model
    {
        return $this->app['jwt.user']->get();
    }

    public function getToken()
    {
        return $this->token;
    }

    /**
     * 刷新 Token.
     *
     * @param Token $token
     *
     * @return Token
     */
    public function refresh(Token $token = null): Token
    {
        $token = $token ?: $this->getRequestToken();

        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);

        // 加入黑名单
        $this->app['jwt.manager']->refresh($token);

        return $this->token($claims);
    }

    /**
     * 自动获取请求下的Token.
     *
     * @return Token
     */
    protected function getRequestToken(): Token
    {
        $requestToken = new RequestToken($this->app);

        $token = $requestToken->get($this->type());

        try {
            $token = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new JWTInvalidArgumentException('此 Token 解析失败', 500);
        }

        return $token;
    }

    /**
     * 解析 Token.
     *
     * @return Token
     */
    public function parseToken($token): Token
    {
        try {
            $token = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new JWTInvalidArgumentException('此 Token 解析失败', 500);
        }

        return $token;
    }

    /**
     * 登出.
     *
     * @param Token $token
     *
     * @return void
     */
    public function logout(Token $token = null)
    {
        $token = $token ?: $this->getRequestToken();

        $this->app['jwt.manager']->logout($token);
    }

    /**
     * 验证 Token.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function verify(Token $token = null)
    {
        $token = $token ?: $this->getRequestToken();

        try {
            $this->validateToken($token);
            $this->token = $token;
        } catch (\BadMethodCallException $e) {
            throw new JWTException('此 Token 未进行签名', 500);
        }

        return true;
    }

    /**
     * Token 自动续期
     *
     * @param Token $token
     * @param int|string $ttl 秒数
     * @return void
     */
    protected function automaticRenewalToken(Token $token)
    {
        $this->logout($token);
        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);
        unset($claims['refreshAt']);

        $token = $this->token($claims);
        $claims = $token->getClaims();
        $refreshAt = $claims['refreshAt'];

        header('Access-Control-Expose-Headers:Automatic-Renewal-Token,Automatic-Renewal-Token-RefreshAt');
        header("Automatic-Renewal-Token:$token");
        header("Automatic-Renewal-Token-RefreshAt:$refreshAt");

        return $token;
    }

    /**
     * 效验 Token.
     *
     * @return void
     */
    protected function validateToken(Token $token)
    {
        // 是否在黑名单
        if ($this->app['jwt.manager']->hasBlacklist($token)) {
            throw new TokenAlreadyEexpired('此 Token 已注销，请重新登录', $this->getReloginCode());
        }

        // 验证密钥是否与创建签名的密钥一致
        if (false === $token->verify($this->getSigner(), $this->makeSignerKey())) {
            throw new JWTException('此 Token 与 密钥不匹配', $this->getReloginCode());
        }

        // 是否可用
        $exp = $token->getClaim('nbf');
        if (time() < $exp) {
            throw new JWTException('此 Token 暂未可用', 500);
        }

        // 是否已过期
        if (true === $token->isExpired()) {
            if (time() <= $token->getClaim('refreshAt')) {
                // 是否开启自动续签
                if ($this->automaticRenewal()) {
                    $token = $this->automaticRenewalToken($token);
                } else {
                    throw new TokenAlreadyEexpired('Token 已过期，请重新刷新', $this->getAlreadyCode());
                }
            } else {
                throw new TokenAlreadyEexpired('Token 刷新时间已过，请重新登录', $this->getReloginCode());
            }
        }

        $data = new ValidationData();

        $jwt_id = $token->getHeader('jti');
        $data->setIssuer($this->iss());
        $data->setAudience($this->aud());
        $data->setId($jwt_id);

        if (!$token->validate($data)) {
            throw new JWTException('此 Token 效验不通过', $this->getReloginCode());
        }
    }
}
