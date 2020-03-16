<?php

namespace xiaodi\Traits;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use xiaodi\Exception\JWTException;
use xiaodi\Exception\JWTInvalidArgumentException;

trait Jwt
{
    private $sso = false;
    private $ssoCacheKey = 'jwt-auth-user';
    private $ssoKey = 'uid';
    private $signerKey;
    private $notBefore = 0;
    private $expiresAt = 3600;
    private $signer = \Lcobucci\JWT\Signer\Hmac\Sha256::class;

    private $type = 'Bearer';
    private $injectUser = false;
    private $userModel;
    private $hasLogged = 50401;
    private $tokenAlready = 50402;

    public function notBefore()
    {
        return (int) $this->notBefore;
    }

    public function setNotBefore($value)
    {
        $this->notBefore = (int) $value;
    }

    public function ttl()
    {
        return (int) $this->expiresAt;
    }

    public function setTTL(int $value)
    {
        $this->ttl = $value;
    }

    public function getType()
    {
        return $this->type;
    }

    public function setType($type)
    {
        return $this->type = $type;
    }

    public function getAlreadyCode()
    {
        return $this->tokenAlready;
    }

    public function getHasLoggedCode()
    {
        return $this->hasLogged;
    }

    public function setExpiresAt($value)
    {
        $this->expiresAt = (int) $value;
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
     * 设置单点登录.
     *
     * @return bool
     */
    public function setSso($bool)
    {
        return $this->sso = $bool;
    }

    /**
     * 获取 sso_key.
     *
     * @return string
     */
    public function ssoKey()
    {
        $key = $this->ssoKey;
        if (empty($key)) {
            throw new JWTInvalidArgumentException('sso_key 未配置', 500);
        }

        return $key;
    }

    /**
     * 设置 sso_key.
     *
     * @return string
     */
    public function setSSOKey($key)
    {
        $this->ssoKey = $key;
    }

    /**
     * 获取私钥.
     *
     * @return string|null
     */
    public function getSignerKey()
    {
        return $this->signerKey;
    }

    /**
     * 设置私钥.
     *
     * @return void
     */
    public function setSignerKey($key)
    {
        return $this->signerKey = $key;
    }

    /**
     * 设置加密方式.
     *
     * @return void
     */
    public function setSigner($signer)
    {
        $this->signer = $signer;
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
     * 获取加密方式.
     *
     * @return Signer|Exception
     */
    private function getSigner()
    {
        $signer = $this->signer;

        if (empty($signer)) {
            throw new JWTInvalidArgumentException('加密方式未配置.', 500);
        }

        $signer = new $signer();

        if (!$signer instanceof Signer) {
            throw new JWTException('加密方式错误.', 500);
        }

        return $signer;
    }

    public function getKey()
    {
        $key = $this->getSignerKey();
        if (empty($key)) {
            throw new JWTException('私钥未配置.', 500);
        }

        return new Key($key);
    }
}
