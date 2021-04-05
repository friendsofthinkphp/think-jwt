<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Config;

use Lcobucci\JWT\Signer;
use xiaodi\JWTAuth\Exception\JWTException;

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

    public function __construct(array $options)
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                $this->$key = $value;
            }
        }
    }

    public function getSigningKey()
    {
        if (empty($this->signer_key)) {
            throw new JWTException('config signer_key required.', 500);
        }

        return base64_encode($this->signer_key);
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
