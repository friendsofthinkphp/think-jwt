<?php

if (!function_exists('jwt')) {
    function jwt($uid, $options = [])
    {
        return app('jwt')->token($uid, $options)->toString();
    }
}

if (!function_exists('multi_app')) {
    function multi_app()
    {
        return app()->getService('think\app\Service') !== null;
    }
}
