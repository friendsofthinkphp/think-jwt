<?php

if (!function_exists('jwt')) {
    function jwt($uid, $options = [])
    {
        return app('jwt')->token($uid, $options)->toString();
    }
}
