# think-jwt

[![Build Status](https://travis-ci.org/edenleung/think-jwt.svg?branch=master)](https://travis-ci.org/edenleung/think-jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)

只支持 `thinkphp 6.0`
## 安装
稳定版
```sh
$ composer require xiaodi/think-jwt
```

开发版
```sh
$ composer require xiaodi/think-jwt:dev-next
```

## 使用
1. 配置
`config/jwt.php`

完整多应用配置
```php
<?php

return [
    'stores' => [
        'admin' => [
            'sso' => [
                'enable' => false,
            ],
            'token' => [
                'signer_key'    => 'tant',
                'not_before'    => 0,
                'expires_at'    => 3600,
                'refresh_ttL'   => 7200,
                'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
                'type'         => 'Header',
                'relogin_code'      => 50001,
                'refresh_code'      => 50002,
                'iss'          => 'client.tant',
                'aud'          => 'server.tant',
                'automatic_renewal' => false,
            ],
            'user' => [
                'bind' => false,
                'class'  => null,
            ]
        ]
    ],
    'manager' => [
        // 缓存前缀
        'prefix' => 'jwt',
        // 黑名单缓存名
        'blacklist' => 'blacklist',
        // 白名单缓存名
        'whitelist' => 'whitelist'
    ]
];

```
## token
* `signer_key` 密钥
* `not_before` 时间前不能使用 默认生成后直接使用
* `refresh_ttL` Token有效期（秒）
* `signer` 加密算法
* `type`  获取 Token 途径
* `relogin_code` Token过期抛异常code = 50001
* `refresh_code` Token失效异常code = 50002
* `automatic_renewal` [开启过期自动续签](#过期自动续签)

## user
* `bind` 是否注入用户模型(中间件有效)
* `class` 用户模型类文件 

## manager
* `prefix` 缓存前缀
* `blacklist` 黑名单缓存名
* `whitelist` 白名单缓存名

以下两个异常都会抛一个HTTP异常 StatusCode = 401
* `xiaodi\Exception\HasLoggedException`
* `xiaodi\Exception\TokenAlreadyEexpired`

### 缓存支持
* File
* Redis

## Token 生成
```php
namespace app\home\controller\Auth;

use xiaodi\JWTAuth\Facade\Jwt;

public function login()
{
    //...登录判断逻辑

    // 自动获取当前应用下的jwt配置
    return json([
        'token' => Jwt::token($uid, ['params1' => 1, 'params2' => 2'])->toString(),
    ]);
    
    // 自定义用户模型
    return json([
        'token' => Jwt::token($uid, ['model' => CustomMember::class])->toString(),
    ]);
}
```

## Token 验证

自动获取当前应用（多应用下）配置。

### 手动验证
```php
use xiaodi\JWTAuth\Facade\Jwt;
use xiaodi\JWTAuth\Exception\HasLoggedException;
use xiaodi\JWTAuth\Exception\TokenAlreadyEexpired;

class User {

    public function test()
    {
        if (true === Jwt::verify($token)) {
            // 验证成功
        }
        
        // 验证成功
        // 如配置用户模型文件 可获取当前用户信息
        dump(Jwt::user());
    }
}

```

### 路由验证
```php
use xiaodi\JWTAuth\Middleware\Jwt;

// 自动获取当前应用配置
Route::get('/hello', 'index/index')->middleware(Jwt::class);

// 自定义应用 使用api应用配置
Route::get('/hello', 'index/index')->middleware(Jwt::class, 'api');
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
                // 支持多种方式获取
                // 'type' => 'Header|Url',
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

## 注销应用Token(所有)

注销指定应用下缓存的用户 （强制下线 重新登录）

```php

$store = 'wechat';

app('jwt.manager')->destroyStoreWhitelist($store);
```

## 注销应用Token(指定某个)

注销指定某个用户（强制下线 重新登录）

```php

$store = 'wechat';
$uid = '9527';

app('jwt.manager')->destroyToken($id, $store);
```
