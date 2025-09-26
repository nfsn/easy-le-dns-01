<?php


declare( strict_types = 1 );


namespace NFSN\DNS01\Tests;


use JDWX\Result\Result;
use NFSN\APIClient\DNSInterface;
use NFSN\APIClient\ManagerInterface;
use NFSN\DNS01\NFSNAPIDNSProvider;
use NFSN\DNS01\Target;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;


#[CoversClass( NFSNAPIDNSProvider::class )]
class NFSNAPIDNSProviderTest extends TestCase {


    public function testFromCredentialsFactory() : void {
        $this->expectNotToPerformAssertions();
        $provider = NFSNAPIDNSProvider::fromCredentials( 'test-login', 'test-key', true );
        unset( $provider );
    }


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


    public function testSetAuthKeyForException() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );

        $dns->expects( $this->once() )
            ->method( 'listRRs' )
            ->willThrowException( new \RuntimeException( 'Network error' ) );

        $provider = new NFSNAPIDNSProvider( $api, false );

        $target = new Target( 'example.com' );
        $res = $provider->setAuthKey( $target, 'auth-key' );
        self::assertTrue( $res->isError() );
        self::assertStringContainsString( 'Failed to set DNS TXT record', $res->messageEx() );
        self::assertStringContainsString( 'Network error', $res->messageEx() );
    }


    public function testSetAuthKeyForExistingRecord() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );

        $dns->expects( $this->once() )
            ->method( 'listRRs' )
            ->with( '_acme-challenge', 'TXT' )
            ->willReturn( [
                [ 'name' => '_acme-challenge', 'type' => 'TXT', 'data' => 'existing-auth-key' ],
            ] );

        $dns->expects( $this->never() )
            ->method( 'replaceRR' );

        $provider = $this->createPartialMock( NFSNAPIDNSProvider::class, [ 'recordVerify' ] );
        $provider->method( 'recordVerify' )
            ->willReturn( Result::ok() );
        /** @noinspection PhpExpressionResultUnusedInspection */
        $provider->__construct( $api, false );

        $target = new Target( 'example.com' );
        $res = $provider->setAuthKey( $target, 'existing-auth-key' );
        self::assertTrue( $res->isOK() );
    }


    public function testSetAuthKeyForNewRecord() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );

        $dns->expects( $this->once() )
            ->method( 'listRRs' )
            ->with( '_acme-challenge', 'TXT' )
            ->willReturn( [] );

        $dns->expects( $this->once() )
            ->method( 'replaceRR' )
            ->with( '_acme-challenge', 'TXT', 'new-auth-key', 180 )
            ->willReturn( true );

        $provider = $this->createPartialMock( NFSNAPIDNSProvider::class, [ 'recordVerify' ] );
        $provider->method( 'recordVerify' )
            ->willReturn( Result::ok() );
        /** @noinspection PhpExpressionResultUnusedInspection */
        $provider->__construct( $api, false );

        $target = new Target( 'example.com' );
        $res = $provider->setAuthKey( $target, 'new-auth-key' );
        self::assertTrue( $res->isOK() );
    }


    public function testSetAuthKeyForReplaceError() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );

        $dns->expects( $this->once() )
            ->method( 'listRRs' )
            ->with( '_acme-challenge', 'TXT' )
            ->willReturn( [] );

        $dns->expects( $this->once() )
            ->method( 'replaceRR' )
            ->with( '_acme-challenge', 'TXT', 'new-auth-key', 180 )
            ->willReturn( 'API error message' );

        $provider = new NFSNAPIDNSProvider( $api, false );

        $target = new Target( 'example.com' );
        $res = $provider->setAuthKey( $target, 'new-auth-key' );
        self::assertTrue( $res->isError() );
        self::assertStringContainsString( 'Failed to replace record: API error message', $res->messageEx() );
    }


    public function testSetAuthKeyForVerificationError() : void {
        $api = $this->newMockAPI();
        $dns = $api->newDNS( 'example.com' );
        assert( $dns instanceof MockObject );

        $dns->expects( $this->once() )
            ->method( 'listRRs' )
            ->with( '_acme-challenge', 'TXT' )
            ->willReturn( [] );

        $dns->expects( $this->once() )
            ->method( 'replaceRR' )
            ->with( '_acme-challenge', 'TXT', 'new-auth-key', 180 )
            ->willReturn( true );

        $provider = $this->createPartialMock( NFSNAPIDNSProvider::class, [ 'recordVerify' ] );
        $provider->method( 'recordVerify' )
            ->willReturn( Result::err( 'Verification failed' ) );
        /** @noinspection PhpExpressionResultUnusedInspection */
        $provider->__construct( $api, false );

        $target = new Target( 'example.com' );
        $res = $provider->setAuthKey( $target, 'new-auth-key' );
        self::assertTrue( $res->isError() );
        self::assertStringContainsString( 'Verification failed', $res->messageEx() );
    }


    public function testSetupReturnsOK() : void {
        $api = $this->newMockAPI();
        $provider = new NFSNAPIDNSProvider( $api, false );
        $res = $provider->setup();
        self::assertTrue( $res->isOK() );
    }


    private function newMockAPI() : ManagerInterface&MockObject {
        $dns = $this->createMock( DNSInterface::class );
        $api = $this->createMock( ManagerInterface::class );
        $api->method( 'newDNS' )->willReturn( $dns );
        return $api;
    }


}
