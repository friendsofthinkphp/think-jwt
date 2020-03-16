<?php

namespace xiaodi;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use think\App;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\JWTException;
use xiaodi\Exception\JWTInvalidArgumentException;
use xiaodi\Exception\TokenAlreadyEexpired;

class Jwt
{
    private $token;

    private $blacklist;

    private $user;

    use \xiaodi\Traits\Jwt;

    public function __construct(App $app, Blacklist $blacklist)
    {
        $this->app = $app;
        $this->blacklist = $blacklist;
        $this->builder = new Builder();

        $config = $this->getConfig();
        foreach ($config as $key => $v) {
            $this->$key = $v;
        }
    }

    /**
     * 获取jwt配置.
     *
     * @return void
     */
    public function getConfig()
    {
        return $this->app->config->get('jwt');
    }

    /**
     * 生成 Token.
     *
     * @param array $claims
     *
     * @return \Lcobucci\JWT\Token
     */
    public function token(array $claims)
    {
        $time = time();
        $uniqid = uniqid();

        // 单点登录
        if ($this->sso()) {
            $sso_key = $this->ssoKey();

            if (empty($claims[$sso_key])) {
                throw new JWTInvalidArgumentException("未设置 \$claims['{$this->ssoKey}']值", 500);
            }
            $uniqid = $claims[$sso_key];
        }

        $this->builder->issuedAt($time)
            ->identifiedBy($uniqid, true)
            ->canOnlyBeUsedAfter($time + $this->notBefore())
            ->expiresAt($time + $this->ttl());

        foreach ($claims as $key => $claim) {
            $this->builder->withClaim($key, $claim);
        }

        $token = $this->builder->getToken($this->getSigner(), $this->makeKey());

        if (true === $this->sso()) {
            $this->setCacheIssuedAt($uniqid, $time);
        }

        return $token;
    }

    /**
     * 解析Token.
     *
     * @param string $token
     *
     * @return Token
     */
    public function parse(string $token)
    {
        try {
            $token = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new JWTInvalidArgumentException('此 Token 解析失败', 500);
        }

        return $token;
    }

    protected function getRequestToken()
    {
        switch ($this->type) {
            case 'Header':
                $bearer = new BearerToken($this->app);
                $token = $bearer->getToken();
                break;
            case 'Cookie':
                $token = $this->app->cookie->get('token');
                break;
            case 'Url':
                $token = $this->app->request->param('token');
                break;
            default:
                $token = $this->app->request->param('token');
                break;
        }

        if (!$token) {
            throw new JwtException('获取Token失败.', 500);
        }

        return $token;
    }

    /**
     * 验证 Token.
     *
     * @param string $token
     *
     * @return bool
     */
    public function verify(string $token = '')
    {
        // 自动获取请求token
        if ($token == '') {
            $token = $this->getRequestToken();
        }

        // 解析Token
        $this->token = $this->parse($token);

        try {
            $this->validateToken();
            // 是否已过期
            if ($this->token->isExpired()) {
                if (time() < ($this->token->getClaim('iat') + $this->refreshExp())) {
                    throw new TokenAlreadyEexpired('Token 已过期，请重新刷新', 401, $this->getAlreadyCode());
                } else {
                    throw new TokenAlreadyEexpired('Token 刷新时间已过，请重新登录', 401, $this->getReloginCode());
                }
            }

            // 单点登录
            if ($this->sso()) {
                $jwt_id = $this->token->getHeader('jti');
                // 当前Token签发时间
                $issued_at = $this->token->getClaim('iat');
                // 最新Token签发时间
                $cache_issued_at = $this->getCacheIssuedAt($jwt_id);
                if ($issued_at != $cache_issued_at) {
                    throw new HasLoggedException('此账号已在其它终端登录，请重新登录', 401, $this->getHasLoggedCode());
                }
            }
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
        // 验证密钥是否与创建签名的密钥匹配
        if (false === $this->token->verify($this->getSigner(), $this->makeKey())) {
            throw new JWTException('此 Token 与 密钥不匹配', 500);
        }

        // 是否可用
        $exp = $this->token->getClaim('nbf');
        if (time() < $exp) {
            throw new JWTException('此 Token 暂未可用', 500);
        }

        if ($this->blacklist->has($this->token)) {
            throw new JWTException('此 Token 已注销', 500);
        }
    }

    /**
     * 获取 Token 对象.
     *
     * @return \Lcobucci\JWT\Token
     */
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
    public function refresh(Token $token)
    {
        // 移除Token
        $this->remove($token);

        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);

        return $this->token($claims);
    }

    /**
     * 删除 Token.
     *
     * @param Token $token
     *
     * @return void
     */
    public function remove(Token $token)
    {
        $this->blacklist->push($token);
    }

    /**
     * 生成私钥.
     *
     * @return Key
     */
    private function makeKey()
    {
        $key = $this->getSignerKey();
        if (empty($key)) {
            throw new JWTException('私钥未配置.', 500);
        }

        return new Key($key);
    }

    /**
     * 缓存最新签发时间.
     *
     * @param string|int $jwt_id 唯一标识
     * @param string     $value  签发时间
     *
     * @return void
     */
    public function setCacheIssuedAt($jwt_id, $value)
    {
        $key = $this->ssoCachePrefix.'-'.$jwt_id;
        $ttl = $this->ttl() + $this->notBefore();

        $this->app->cache->set($key, $value, $ttl);
    }

    /**
     * 获取最新签发时间.
     *
     * @param string|int $jwt_id 唯一标识
     *
     * @return string
     */
    protected function getCacheIssuedAt($jwt_id)
    {
        return $this->app->cache->get($this->ssoCachePrefix.'-'.$jwt_id);
    }

    /**
     * 是否注入用户对象.
     *
     * @return bool
     */
    public function injectUser()
    {
        return $this->injectUser;
    }

    /**
     * 获取用户模型.
     *
     * @return void
     */
    public function userModel()
    {
        return $this->userModel;
    }

    /**
     * 获取用户模型对象
     *
     * @return void
     */
    public function user()
    {
        $uid = $this->token->getClaim($this->ssoKey());
        if ($uid) {
            $namespace = $this->userModel();
            if (empty($namespace)) {
                throw new JWTInvalidArgumentException('用户模型文件未配置.', 500);
            }

            $r = new \ReflectionClass($namespace);
            $model = $r->newInstance();
            $this->user = $model->find($uid);
        }

        return $this->user;
    }
}
