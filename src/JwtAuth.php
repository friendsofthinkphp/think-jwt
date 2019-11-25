<?php

namespace xiaodi;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use think\facade\Cache;
use xiaodi\Exception\Exception;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\SignerKeyException;
use xiaodi\Exception\TokenExpiredException;
use xiaodi\Exception\TokenInvalidException;
use xiaodi\Exception\TokenNotAvailableException;
use xiaodi\Exception\VerifyDataException;

class JwtAuth
{
    // 缓存前缀
    const CACHE_PRE = 'jwt-auth-user-';

    private $user;

    private $options = [
        // 单点登录
        'sso' => true,

        // 单点登录用户唯一标识
        'sso_key' => 'id',

        // 秘钥
        'signer_key' => '',

        // 在此时间前不可用(秒)
        'not_before' => 0,

        // 默认有效时间为一小时（秒）
        'expires_at' => 3600,

        // 默认使用sha256签名
        'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,

        'claims' => [
            //发布端url
            'iss' => '',
            //请求端url
            'aud' => '',
        ],

        'header' => 'Authorization',

        // 中间件自动注入用户模型
        'inject_user' => false,
        // 用户模型
        'user' => '',
    ];

    private $builder;

    private $token;

    public function __construct()
    {
        $this->builder = new Builder();
        // TODO 5.1 config() 得加 "."
        $this->options = array_merge($this->options, config('jwt-auth'));
    }

    /**
     * 生成Token.
     *
     * @param array $claims 自定义数据
     *
     * @return void
     */
    public function getToken(array $claims)
    {
        $time = time();
        $expires_at = (int) $this->options['expires_at'] + $time;
        $not_before = (int) $this->options['not_before'] + $time;

        // 单点登录
        if ($this->options['sso']) {
            if (!isset($claims[$this->options['sso_key']])) {
                throw new Exception('sso_key not found');
            }
            $uniqid = $claims[$this->options['sso_key']];
        } else {
            $uniqid = uniqid();
        }

        $this->builder->setIssuedAt($time)
            ->identifiedBy($uniqid, true)
            ->setNotBefore($not_before)
            ->set('refresh_time', $time)
            ->setExpiration($expires_at);

        $claims = array_merge($this->options['claims'], $claims);
        foreach ($claims as $k => $v) {
            $this->builder->withClaim($k, $v);
        }

        $token = $this->builder->getToken($this->getSigner(), $this->getSignerKey());

        Cache::set(self::CACHE_PRE.$uniqid, $time, $this->options['expires_at'] + $this->options['not_before']);

        return $token;
    }

    /**
     * 解析Token.
     *
     * @param [type] $token
     *
     * @return void
     */
    protected function parseToken($token)
    {
        try {
            $token = (new Parser())->parse((string) $token);
        } catch (\Exception $e) {
            throw new TokenInvalidException('此 Token 解析失败');
        }

        return $token;
    }

    /**
     * 获取Token对象
     *
     * @return void
     */
    public function getParse()
    {
        return $this->token;
    }

    public function getClaims()
    {
        return $this->token->getClaims();
    }

    /**
     * 验证Token.
     *
     * @param [type] $token
     *
     * @return void
     */
    public function verify($token)
    {
        $this->token = $this->parseToken($token);

        try {
            if (false === $this->token->verify($this->getSigner(), $this->getSignerKey())) {
                throw new SignerKeyException('效验秘钥错误');
            }
        } catch (\BadMethodCallException $e) {
            throw new \BadMethodCallException('此 Token 未进行签名');
        } catch (\InvalidArgumentException $e) {
            throw new \BadMethodCallException('此 Token 解析失败');
        }

        // 验证token是否过期
        if ($this->verifyData() && $this->injectUser()) {
            $uid = $this->token->getClaim($this->options['sso_key']);
            if ($uid) {
                $model = $this->options['user'];
                $this->user = $model::get($uid);
            }
        }
    }

    /**
     * 验证数据.
     *
     * @return void
     */
    protected function verifyData()
    {
        $aud = $this->token->getClaim('aud');
        $iss = $this->token->getClaim('iss');
        $jwt_id = $this->token->getHeader('jti');

        $data = new ValidationData();

        $data->setAudience($aud);
        $data->setIssuer($iss);
        $data->setId($jwt_id);

        if (false === $this->token->validate($data)) {
            $exp = $this->token->getClaim('exp');
            if (time() < $exp) {
                throw new TokenNotAvailableException('Token 暂未可用');
            } elseif (time() > $exp) {
                throw new TokenExpiredException('Token 已过期');
            }

            throw new VerifyDataException('数据验证失败');
        }

        // 单点登录
        if ($this->options['sso']) {
            $refresh_time = $this->token->getClaim('refresh_time');
            $cache_time = Cache::get(self::CACHE_PRE.$jwt_id);
            if ($refresh_time != $cache_time) {
                throw new HasLoggedException('已在其它终端登录，请重新登录');
            }
        }

        return true;
    }

    /**
     * 刷新Token.
     *
     * @param Token $token
     *
     * @return void
     */
    public function refreshToken(Token $token)
    {
        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);

        return $this->getToken($claims);
    }

    protected function getSigner()
    {
        $className = $this->options['signer'];
        $signer = new $className();
        if (false === $signer instanceof Hmac) {
            throw new Exception("{$className} is not extend Lcobucci\JWT\Signer\Hmac");
        }

        return $signer;
    }

    protected function getSignerKey()
    {
        return new Key($this->options['signer_key']);
    }

    /**
     * 获取用户模型对象
     *
     * @return void
     */
    public function user()
    {
        return $this->user;
    }

    public function getHeader()
    {
        return $this->options['header'];
    }

    public function injectUser()
    {
        return $this->options['inject_user'];
    }
}
