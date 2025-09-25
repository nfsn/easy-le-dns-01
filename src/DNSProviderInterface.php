<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\Result\Result;


interface DNSProviderInterface {


    /** @return Result<mixed> */
    public function removeAuthKey( Target $i_target ) : Result;


    /** @return Result<mixed> */
    public function setAuthKey( Target $i_target, string $i_stAuthKey ) : Result;


    /** @return Result<mixed> */
    public function setup() : Result;


}