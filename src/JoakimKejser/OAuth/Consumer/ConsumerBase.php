<?php

namespace JoakimKejser\OAuth\Consumer;

class ConsumerBase implements \JoakimKejser\OAuth\ConsumerInterface
{
    protected $key;

    protected $secret;

    public function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    public function getKey()
    {
        return $this->key;
    }

    public function getSecret()
    {
        return $this->secret;
    }
}