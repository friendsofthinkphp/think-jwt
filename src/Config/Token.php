<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Config;

use Lcobucci\JWT\Signer;
use xiaodi\JWTAuth\Exception\JWTException;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Rsa;

class Token
{
    protected $signer_key = null;
    protected $not_before = 0;
    protected $expires_at = 3600;
    protected $refresh_ttL = 7200;
    protected $signer = \Lcobucci\JWT\Signer\Hmac\Sha256::class;
    protected $type = 'Header';
    protected $relogin_code = 50002;
    protected $refresh_code = 50001;
    protected $iss = 'client.xiaodim.com';
    protected $aud = 'server.xiaodim.com';
    protected $automatic_renewal = false;
    protected $public_key = '';
    protected $private_key = '';

    public function __construct(array $options)
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                $this->$key = $value;
            }
        }
    }

    public function getHamcKey(): Key
    {
        if (empty($this->signer_key)) {
            throw new JWTException('config signer_key required.', 500);
        }

        return InMemory::base64Encoded((string)$this->signer_key);
    }

    public function RSASigner()
    {
        $signer = $this->getSigner();

        return $signer instanceof Rsa;
    }

    public function getSignerKey(): Key
    {
        $signer = $this->getSigner();

        if ($this->RSASigner()) {
            return $this->getPrivateKey();
        } else if ($signer instanceof Hmac) {
            return $this->getHamcKey();
        } else {
            throw new JWTException('not support.', 500);
        }
    }

    public function getPublicKey(): Key
    {
        return LocalFileReference::file($this->public_key);
    }

    public function getPrivateKey(): Key
    {
        return LocalFileReference::file($this->private_key);
    }

    public function getExpires()
    {
        return $this->expires_at;
    }

    public function getRefreshTTL()
    {
        return $this->refresh_ttL;
    }

    public function getIss(): string
    {
        return $this->iss;
    }

    public function getAud(): string
    {
        return $this->aud;
    }

    public function getNotBefore()
    {
        return $this->not_before;
    }

    public function getSigner(): Signer
    {
        return new $this->signer;
    }

    public function getReloginCode()
    {
        return $this->relogin_code;
    }

    public function getRefreshCode()
    {
        return $this->refresh_code;
    }

    public function getAutomaticRenewal()
    {
        return $this->automatic_renewal;
    }

    public function getType()
    {
        return $this->type;
    }
}
