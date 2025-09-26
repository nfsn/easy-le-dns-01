<?php


declare( strict_types = 1 );


namespace NFSN\DNS01\Tests;


use NFSN\APIClient\DNSInterface;
use NFSN\APIClient\ManagerInterface;
use NFSN\DNS01\NFSNAPIDNSProvider;
use NFSN\DNS01\Target;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;


class NFSNAPIDNSProviderTest extends TestCase {


    public function testRemoveAuthKeyForException() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );
        $dns->method( 'listRRs' )->willThrowException( new \RuntimeException( 'some-error' ) );
        $provider = new NFSNAPIDNSProvider( $api, true );
        $target = new Target( 'example.com' );
        $res = $provider->removeAuthKey( $target );
        self::assertTrue( $res->isError() );
        self::assertStringContainsString( 'some-error', $res->messageEx() );
    }


    public function testRemoveAuthKeyForNotFound() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );
        $dns->method( 'listRRs' )->willReturn( false );
        $provider = new NFSNAPIDNSProvider( $api, true );
        $target = new Target( 'example.com' );
        $res = $provider->removeAuthKey( $target );
        self::assertTrue( $res->isError() );
        self::assertSame( 'Could not find TXT record to remove.', $res->message() );
    }


    public function testRemoveAuthKeyForOK() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );
        $dns->method( 'listRRs' )->willReturn( [
            [ 'name' => 'zok', 'type' => 'TXT', 'data' => 'some-txt-value' ],
        ] );
        $dns->method( 'removeRR' )->willReturn( true );
        $provider = new NFSNAPIDNSProvider( $api, true );
        $target = new Target( 'example.com' );
        $res = $provider->removeAuthKey( $target );
        self::assertTrue( $res->isOK() );
    }


    private function newMockAPI() : ManagerInterface&MockObject {
        $dns = $this->createMock( DNSInterface::class );
        $api = $this->createMock( ManagerInterface::class );
        $api->method( 'newDNS' )->willReturn( $dns );
        return $api;
    }


}
