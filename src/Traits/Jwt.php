<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Traits;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\Exception\JWTInvalidArgumentException;

trait Jwt
{
    private $signerKey;
    private $notBefore = 0;
    private $expiresAt = 3600;
    private $refreshTTL = 7200;
    private $signer = \Lcobucci\JWT\Signer\Hmac\Sha256::class;

    private $type = 'Header';

    private $hasLogged = 50401;
    private $tokenAlready = 50402;
    private $relogin = 50400;

    private $iss;
    private $aud;

    public function refreshTTL()
    {
        return (int) $this->refreshTTL;
    }

    public function setRefreshTTL($value)
    {
        $this->refreshTTL = (int) $value;
    }

    public function getReloginCode()
    {
        return (int) $this->relogin;
    }

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

    public function type()
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

    /**
     * 生成Key.
     *
     * @return Key
     */
    private function makeSignerKey()
    {
        $key = $this->getSignerKey();
        if (empty($key)) {
            throw new JWTException('私钥未配置.', 500);
        }

        return new Key($key);
    }

    public function iss()
    {
        $iss = $this->app->request->root(true);

        return $this->iss ?: $iss;
    }

    public function aud()
    {
        return $this->aud;
    }
}
