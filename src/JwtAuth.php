<?php

namespace think\JwtAuth;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Hmac;
use think\JwtAuth\Exception\Exception;
use think\JwtAuth\Exception\SignerKeyException;
use think\JwtAuth\Exception\VerifyDataException;
use think\JwtAuth\Exception\TokenInvalidException;
use think\JwtAuth\Exception\TokenNotAvailableException;
use think\JwtAuth\Exception\TokenExpiredException;
use RuntimeException;

class JwtAuth
{
    private $options = [
        // 秘钥
        'signer_key' => '5k*!X^oF',

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
            'aud' => ''
        ]
    ];

    private $builder;

    private $token;

    public function __construct()
    {
        $this->builder = new Builder();
    }

    /**
     * 生成Token
     *
     * @param array $claims 自定义数据
     * @return void
     */
    public function getToken(array $claims)
    {
        $time = time();
        $expires_at = (int) $this->options['expires_at'] + $time;
        $not_before = (int) $this->options['not_before'] + $time;

        $this->builder->setIssuedAt($time)
            ->identifiedBy(uniqid(), true)
            ->setNotBefore($not_before)
            ->setExpiration($expires_at);

        $claims = array_merge($this->options['claims'], $claims);
        foreach ($claims as $k => $v) {
            $this->builder->withClaim($k, $v);
        }

        $token = $this->builder->getToken($this->getSigner(), $this->getSignerKey());

        return $token;
    }

    /**
     * 解析Token
     *
     * @param [type] $token
     * @return void
     */
    protected function parseToken($token)
    {
        try {
            $token = (new Parser())->parse((string) $token);
        } catch (RuntimeException $e) {
            throw new TokenInvalidException('Token 解析出错');
        }

        return $token;
    }

    /**
     * 验证Token
     *
     * @param [type] $token
     * @return void
     */
    public function verify($token)
    {
        $this->token = $this->parseToken($token);
        if (false === $this->token->verify($this->getSigner(), $this->getSignerKey())) {
            throw new SignerKeyException('验证秘钥不正确');
        }

        // 验证token是否过期
        return $this->verifyData();
    }

    /**
     * 验证数据
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
            } else if (time() > $exp) {
                throw new TokenExpiredException('Token 已过期');
            }

            throw new VerifyDataException('数据验证失败');
        }

        return true;
    }

    /**
     * 刷新Token
     *
     * @param Token $token
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
        $signer = new $className;
        if (false === $signer instanceof Hmac) {
            throw new Exception("{$className} is not extend Lcobucci\JWT\Signer\Hmac");
        }

        return $signer;
    }

    protected function getSignerKey()
    {
        return new Key($this->options['signer_key']);
    }
}
