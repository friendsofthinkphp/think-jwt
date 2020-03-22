<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Traits;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\Exception\JWTInvalidArgumentException;

trait Jwt
{
    private $uniqidKey = 'uid';
    private $signerKey;
    private $notBefore = 0;
    private $expiresAt = 3600;
    private $refreshTTL = 7200;
    private $signer = \Lcobucci\JWT\Signer\Hmac\Sha256::class;

    private $type = 'Header';

    private $refresh = 50001;
    private $relogin = 50002;

    private $iss;
    private $aud;

    /**
     * 获取 Token获取途径.
     *
     * @return string
     */
    public function type()
    {
        return $this->type;
    }

    /**
     * 设置 Token获取途径.
     *
     * @return void
     */
    public function setType($type)
    {
        return $this->type = $type;
    }

    /**
     * 获取 用户表唯一标识值名.
     *
     * @return void
     */
    public function getUniqidKey()
    {
        return $this->uniqidKey;
    }

    /**
     * 获取 刷新Token TTL.
     *
     * @return void
     */
    public function refreshTTL()
    {
        return (int) $this->refreshTTL;
    }

    /**
     * 设置 刷新Token TTL.
     *
     * @param [type] $value
     *
     * @return void
     */
    public function setRefreshTTL($value)
    {
        $this->refreshTTL = (int) $value;
    }

    /**
     * @return void
     */
    public function getReloginCode()
    {
        return (int) $this->relogin;
    }

    /**
     * 获取 检测延迟
     *
     * @return void
     */
    public function notBefore()
    {
        return (int) $this->notBefore;
    }

    /**
     * 设置 检测延迟
     *
     * @param [type] $value
     *
     * @return void
     */
    public function setNotBefore($value)
    {
        $this->notBefore = (int) $value;
    }

    /**
     * 获取  TTl.
     *
     * @return void
     */
    public function ttl()
    {
        return (int) $this->expiresAt;
    }

    /**
     * 设置 TTL.
     *
     * @param int $value
     *
     * @return void
     */
    public function setTTL(int $value)
    {
        $this->expiresAt = $value;
    }

    /**
     * @return void
     */
    public function getAlreadyCode()
    {
        return $this->refresh;
    }

    /**
     * @return void
     */
    public function getHasLoggedCode()
    {
        return $this->hasLogged;
    }

    /**
     * 设置有效期
     *
     * @param [type] $value
     *
     * @return void
     */
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

    /**
     * 获取 发布端 url.
     *
     * @return void
     */
    public function iss()
    {
        $iss = $this->app->request->root(true);

        return $this->iss ?: $iss;
    }

    /**
     * 获取 请求端 url.
     *
     * @return void
     */
    public function aud()
    {
        return $this->aud;
    }

    /**
     * 获取 已验证的Token对象
     *
     * @return Token
     */
    public function getToken()
    {
        return $this->token;
    }
}
