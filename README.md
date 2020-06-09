# think-jwt

[![Build Status](https://travis-ci.org/edenleung/think-jwt.svg?branch=master)](https://travis-ci.org/edenleung/think-jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)

只支持 `thinkphp 6.0`
## 安装
```sh
$ composer require xiaodi/think-jwt
```

## 使用
~~1. 命令生成签名key~~
```sh
$ php think jwt:make
```

2. 配置
`config/jwt.php`

完整多应用配置
```php
<?php

return [
    'default' => 'admin',
    'apps' => [
        'admin' => [
            'token' => [
                'uniqidKey'    => 'uid',
                'signerKey'    => '',
                'notBefore'    => 0,
                'expiresAt'    => 3600,
                'refreshTTL'   => 7200,
                'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
                'type'         => 'Header',
                'refresh'      => 50001,
                'relogin'      => 50002,
                'iss'          => '',
                'aud'          => '',
                'automaticRenewal' => false,
            ],
            'user' => [
                'bind' => false,
                'model'  => '',
            ],
            'blacklist' => [
                'cacheKey' => 'admin',
            ],
        ]
    ]
];

```
## token
* `uniqidKey` 用户唯一标识
* `signerKey` 密钥
* `notBefore` 时间前不能使用 默认生成后直接使用
* `expiresAt` Token有效期（秒）
* `signer` 加密算法
* `type`  获取 Token 途径
* `refresh` Token过期抛异常code = 50001
* `relogin` Token失效异常code = 50002
* `automaticRenewal` [开启过期自动续签](过期自动续签)

## user
* `bind` 是否注入用户模型(中间件有效)
* `model` 用户模型文件 

## blacklist
* `cacheKey` 黑名单缓存key

以下两个异常都会抛一个HTTP异常 StatusCode = 401
* `xiaodi\Exception\HasLoggedException`
* `xiaodi\Exception\TokenAlreadyEexpired`

## Token 生成
```php
use xiaodi\JWTAuth\Facade\Jwt;

public function login()
{
    //...登录判断逻辑

    // 默认应用
    return json([
        'token' => Jwt::token(['uid' => 1]),
        'token_type' => Jwt::type(),
        'expires_in' => Jwt::ttl(),
        'refresh_in' => Jwt::refreshTTL()
    ]);
    
    // 指定应用
    return json([
        'token' => Jwt::store('wechat')->token(['uid' => 1]),
        'token_type' => Jwt::type(),
        'expires_in' => Jwt::ttl(),
        'refresh_in' => Jwt::refreshTTL()
    ]);
}
```

## Token 验证

### 手动验证
```php
use xiaodi\JWTAuth\Facade\Jwt;
use xiaodi\JWTAuth\Exception\HasLoggedException;
use xiaodi\JWTAuth\Exception\TokenAlreadyEexpired;

class User {

    public function test()
    {
        try {
            // 默认应用
            Jwt::verify($token);
            
            // 指定应用
            // Jwt::store('wechat')->verify($token);
        } catch (HasLoggedException $e) {
            // 已在其它终端登录
        } catch (TokenAlreadyEexpired $e) {
            // Token已过期
        }
        
        // 验证成功
        // 如 开启用户注入功能 可获取当前用户信息
        dump(Jwt::user());
    }
}

```

### 路由验证
```php
use xiaodi\JWTAuth\Middleware\Jwt;

// 默认应用
Route::get('/hello', 'index/index')->middleware(Jwt::class);

// 指定应用
Route::get('/hello', 'index/index')->middleware(Jwt::class, 'wechat');
```

## Token 自动获取

支持以下方式自动获取

* `Header`
* `Cookie`
* `Url`

赋值方式

类型 | 途径 | 标识 |
:-: | :-: | :-: | 
Header | Authorization | Bearer Token |
Cookie | Cookie| token |
Url | Request | token |

```php
# config/jwt.php

<?php

return [

    'apps' => [
        'admin' => [
            'token' => [
                // ...其它配置
                'type' => 'Header',
                
                // 'type' => 'Cookie',
                // 'type' => 'Url',
            ]
        ]
    ]
    
];
```

## 过期自动续签
`app/config/jwt.php`

`automaticRenewal => true`

系统检测到 Token 已过期， 会自动续期并返回以下 header 信息。 

* Automatic-Renewal-Token
* Automatic-Renewal-Token-RefreshAt

前端需要接收最新 Token，下次异步请求时，携带此 Token。
