<?php

namespace xiaodi;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use think\facade\Cache;
use think\facade\Cookie;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\JWTException;
use xiaodi\Exception\TokenAlreadyEexpired;

class Jwt
{
    private $user;
    private $token;

    public $sso = true;
    public $ssoCacheKey = 'jwt-auth-user';
    public $ssoKey = 'uid';
    public $signerKey;
    public $notBefore = 0;
    public $expiresAt = 3600;
    public $signer = \Lcobucci\JWT\Signer\Hmac\Sha256::class;

    /**token传参方式 Bearer Cookie  Url**/
    public $type = 'Bearer';
    public $injectUser = false;
    public $userModel;
    public $hasLogged = 50401;
    public $tokenAlready = 50402;

    public function __construct(Builder $builder)
    {
        $this->builder = $builder;

        $config = config('jwt', []);
        foreach ($config as $key=> $v) {
            $this->$key = $v;
        }
    }

    /**
     * 生成 Token.
     *
     * @param array $claims
     *
     * @return string
     */
    public function token(array $claims)
    {
        $time = time();
        $uniqid = uniqid();

        // 单点登录
        if ($this->sso()) {
            $sso_key = $this->ssoKey();

            if (empty($claims[$sso_key])) {
                throw new JWTException("未设置 \$claims['{$this->ssoKey}']值", 500);
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

        return $token->__toString();
    }

    public function notBefore()
    {
        return (int) $this->notBefore;
    }

    public function ttl()
    {
        return (int) $this->expiresAt;
    }

    public function type()
    {
        return $this->type;
    }

    public function getAlreadyCode()
    {
        return $this->tokenAlready;
    }

    public function getHasLoggedCode()
    {
        return $this->hasLogged;
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
            throw new JWTException('此 Token 解析失败', 500);
        }

        return $token;
    }

    /**
     * 根据$type获取请求token.
     *
     * @return false|mixed|string
     */
    public function getRequestToken()
    {
        switch ($this->type) {
            case 'Bearer':
                $authorization = request()->header('authorization');
                $token = strpos($authorization, 'Bearer ') !== 0 ? false : substr($authorization, 7); ; break;
            case 'Cookie':$token = Cookie::get('token'); break;
            case 'Url': $token = request()->param('token'); break;
            default:$token = request()->param('token'); break;
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
                throw new TokenAlreadyEexpired('Token 已过期', 401, $this->getAlreadyCode());
            }

            // 单点登录
            if ($this->sso()) {
                $jwt_id = $this->token->getHeader('jti');
                // 当前Token签发时间
                $issued_at = $this->token->getClaim('iat');
                // 最新Token签发时间
                $cache_issued_at = $this->getCacheIssuedAt($jwt_id);
                if ($issued_at != $cache_issued_at) {
                    throw new HasLoggedException('已在其它终端登录，请重新登录', 401, $this->getHasLoggedCode());
                }
            }
        } catch (\BadMethodCallException $e) {
            throw new JWTException('此 Token 未进行签名', 500);
        }

        return true;
    }

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
    }

    /**
     * 缓存最新签发时间.
     *
     * @param string|int $jwt_id 唯一标识
     * @param string     $value  签发时间
     *
     * @return void
     */
    protected function setCacheIssuedAt($jwt_id, $value)
    {
        $key = $this->ssoCacheKey.'-'.$jwt_id;
        $ttl = $this->ttl() + $this->notBefore();

        Cache::set($key, $value, $ttl);
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
        return Cache::get($this->ssoCacheKey.'-'.$jwt_id);
    }

    /**
     * 获取Token对象
     *
     * @return void
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * 刷新 Token.
     *
     * @return void
     */
    public function refresh(Token $token)
    {
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
     * 是否单点登录.
     *
     * @return bool
     */
    private function sso()
    {
        return $this->sso;
    }

    /**
     * 获取 sso_key.
     *
     * @return string
     */
    private function ssoKey()
    {
        $key = $this->ssoKey;
        if (empty($key)) {
            throw new JWTException('sso_key 未配置', 500);
        }

        return $key;
    }

    /**
     * 获取私钥.
     *
     * @return string|null
     */
    private function getSignerKey()
    {
        return $this->signerKey;
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
     * 获取加密方式.
     *
     * @return Signer|Exception
     */
    private function getSigner()
    {
        $signer = $this->signer;

        if (empty($signer)) {
            throw new JWTException('加密方式未配置.', 500);
        }

        $signer = new $signer();

        if (!$signer instanceof Signer) {
            throw new JWTException('加密方式错误.', 500);
        }

        return $signer;
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
                throw new JWTException('用户模型文件未配置.', 500);
            }

            $r = new \ReflectionClass($namespace);
            $model = $r->newInstance();
            $this->user = $model->find($uid);
        }

        return $this->user;
    }

    /**
     * 获取用户uid.
     *
     * @return mixed
     */
    public function userId()
    {
        $uid = $this->token->getClaim($this->ssoKey());

        return $uid;
    }

    public function getClaims()
    {
        return $this->token->getClaims();
    }
}
