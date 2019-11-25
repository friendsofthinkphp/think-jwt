<?php

namespace xiaodi\Command;

use Nette\PhpGenerator\Helpers;
use Nette\PhpGenerator\PhpFile;
use think\console\Command;
use think\console\Input;
use think\console\Output;

function randomKey()
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~0123456789#$%^&';
    $pass = [];
    $alphaLength = strlen($alphabet) - 1;
    for ($i = 0; $i < 10; $i++) {
        $n = rand(0, $alphaLength);
        $pass[] = $alphabet[$n];
    }

    return implode($pass);
}

class JwtAuthCommand extends Command
{
    protected function configure()
    {
        $this->setName('auth:sign_key')->setDescription('生成一个签名密钥');
    }

    protected function execute(Input $input, Output $output)
    {
        $file = new PhpFile();
        $file->addComment('JwtAuth 配置');
        $file->setStrictTypes();

        $config = config('jwt-auth');
        $config['signer_key'] = randomKey();
        $config = 'return '.Helpers::dump($config).';';

        file_put_contents($this->app->getConfigPath().'jwt-auth.php', $file.$config);
        $output->writeln('> success!');
    }
}
