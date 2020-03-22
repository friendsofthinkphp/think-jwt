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
    /**
     * @var User
     */
    private $user;

    /**
     * @var Token
     */
    private $token;

    /**
     * @var Manager
     */
    private $manager;

    /**
     * @var Builder
     */
    private $builder;

    use \xiaodi\JWTAuth\Traits\Jwt;

    public function __construct(App $app, Manager $manager, Builder $builder, User $user)
    {
        $this->app = $app;
        $this->manager = $manager;
        $this->builder = $builder;
        $this->user = $user;

        $config = $this->getConfig();
        foreach ($config as $key => $v) {
            $this->$key = $v;
        }
    }

    /**
     * 获取jwt配置.
     *
     * @return array
     */
    public function getConfig(): array
    {
        return $this->app->config->get('jwt.default', []);
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

        $this->builder->setIssuer($this->iss())
            ->setAudience($this->aud())
            ->setId($uniqid, true)
            ->setIssuedAt(time())
            ->setNotBefore(time() + $this->notBefore())
            ->setExpiration(time() + $this->ttl())
            ->set('refreshAt', time() + $this->refreshTTL());

        foreach ($claims as $key => $claim) {
            $this->builder->set($key, $claim);
        }

        $token = $this->builder->getToken($this->getSigner(), $this->makeSignerKey());

        $this->manager->login($token);

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
            throw new JWTException('用户唯一值·uniqidKey·未配置', 500);
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
        return $this->user->get();
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
        $this->manager->refresh($token);

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
    public function parseToken(): Token
    {
        $token = $this->getRequestToken();

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
        $this->token = $token ?: $this->getRequestToken();

        $this->manager->logout($this->token);
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
        $this->token = $token ?: $this->getRequestToken();

        try {
            $this->validateToken();
        } catch (\BadMethodCallException $e) {
            throw new JWTException('此 Token 未进行签名', 500);
        }

        return true;
    }

    /**
     * 效验 Token.
     *
     * @return void
     */
    protected function validateToken()
    {
        // 是否在黑名单
        if ($this->manager->hasBlacklist($this->token)) {
            throw new TokenAlreadyEexpired('此 Token 已注销，请重新登录', $this->getReloginCode());
        }

        // 验证密钥是否与创建签名的密钥一致
        if (false === $this->token->verify($this->getSigner(), $this->makeSignerKey())) {
            throw new JWTException('此 Token 与 密钥不匹配', 500);
        }

        // 是否可用
        $exp = $this->token->getClaim('nbf');
        if (time() < $exp) {
            throw new JWTException('此 Token 暂未可用', 500);
        }

        // 是否已过期
        if (true === $this->token->isExpired()) {
            if (time() <= $this->token->getClaim('refreshAt')) {
                throw new TokenAlreadyEexpired('Token 已过期，请重新刷新'.time().'-'.$this->token->getClaim('refreshAt'), $this->getAlreadyCode());
            }

            throw new TokenAlreadyEexpired('Token 刷新时间已过，请重新登录', $this->getReloginCode());
        }

        $data = new ValidationData();

        $jwt_id = $this->token->getHeader('jti');
        $data->setIssuer($this->iss());
        $data->setAudience($this->aud());
        $data->setId($jwt_id);

        if (!$this->token->validate($data)) {
            throw new JWTException('此 Token 效验不通过', 500);
        }
    }
}
