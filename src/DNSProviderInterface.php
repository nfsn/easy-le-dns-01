<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


interface DNSProviderInterface {


    public function setAuthKey( Target $i_target, string $i_stAuthKey ) : bool;


    public function setup() : bool;


}