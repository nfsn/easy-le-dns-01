<?php


declare( strict_types = 1 );


namespace NFSN\DNS01;


use JDWX\Result\Result;


trait OutputTrait {


    protected bool $bVerbose;


    /** @param Result<mixed> $i_res */
    protected function failure( string $i_stContext, Result $i_res ) : void {
        $this->output( $i_stContext, ': ', $i_res->message(), "\n" );
        if ( $i_res->hasValue() ) {
            /** @noinspection ForgottenDebugOutputInspection */
            var_dump( $i_res->xValue );
        }
    }


    protected function output( mixed ...$i_rArgs ) : void {
        echo implode( '', $i_rArgs );
    }


    protected function verbose( mixed ...$i_rArgs ) : void {
        if ( ! $this->bVerbose ) {
            return;
        }
        echo implode( '', $i_rArgs );
    }


}