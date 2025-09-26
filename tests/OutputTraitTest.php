<?php


declare( strict_types = 1 );


namespace NFSN\DNS01\Tests;


use JDWX\Result\Result;
use NFSN\DNS01\OutputTrait;
use PHPUnit\Framework\TestCase;


final class OutputTraitTest extends TestCase {


    public function testFailure() : void {
        $res = Result::err( 'Something went wrong', 'foo' );
        $obj = $this->newObject();
        ob_start();
        /** @phpstan-ignore method.notFound */
        $obj->f( 'Context', $res );
        $st = ob_get_clean();
        assert( is_string( $st ) );
        self::assertStringContainsString( 'Context: Something went wrong', $st );
        self::assertStringContainsString( 'foo', $st );
    }


    public function testOutput() : void {
        $obj = $this->newObject();
        ob_start();
        /** @phpstan-ignore method.notFound */
        $obj->o( 'Test:', 'Message' );
        $st = ob_get_clean();
        self::assertSame( 'Test:Message', $st );
    }


    public function testVerboseOff() : void {
        $obj = $this->newObject();
        ob_start();
        /** @phpstan-ignore method.notFound */
        $obj->v( 'This', 'Will', 'Not', 'Be', 'Seen' );
        $st = ob_get_clean();
        self::assertSame( '', $st );
    }


    public function testVerboseOn() : void {
        $obj = $this->newObject( true );
        ob_start();
        /** @phpstan-ignore method.notFound */
        $obj->v( 'This', 'Will', 'Be', 'Seen' );
        $st = ob_get_clean();
        self::assertSame( 'ThisWillBeSeen', $st );
    }


    private function newObject( bool $i_bVerbose = false ) : object {
        return new class( $i_bVerbose ) {


            use OutputTrait;


            public function __construct( bool $i_bVerbose ) {
                $this->bVerbose = $i_bVerbose;
            }


            /** @param Result<mixed> $i_res */
            public function f( string $i_stContext, Result $i_res ) : void {
                $this->failure( $i_stContext, $i_res );
            }


            public function o( mixed ...$args ) : void {
                $this->output( ...$args );
            }


            public function v( mixed ...$args ) : void {
                $this->verbose( ...$args );
            }


        };
    }


}
