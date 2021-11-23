<?php
namespace JoakimKejser\OAuth\ConsumerStore;

use JoakimKejser\OAuth\Consumer\ConsumerBase;

class ArrayConsumerStore implements \JoakimKejser\OAuth\ConsumerStoreInterface
{
    protected $consumers;

    public function __construct(array $consumers)
    {
        $this->consumers = $consumers;
    }

    public function getConsumer($publicKey)
    {
        if (array_key_exists($publicKey, $this->consumers)) {
            return new ConsumerBase($publicKey, $this->consumers[$publicKey]);
        }

        return null;
    }
}
