<?php


declare( strict_types = 1 );


namespace NFSN\DNS01\Tests;


use NFSN\DNS01\Config;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( Config::class )]
final class ConfigTest extends TestCase {


    private Config $cfg;

    private string $stPath;


    public function testAcmeAccountUrl() : void {
        self::assertNull( $this->cfg->getAcmeAccountUrl() );
        $this->cfg->setAcmeAccountUrl( 'https://example.com/acme/acct/1' );
        self::assertSame( 'https://example.com/acme/acct/1', $this->cfg->getAcmeAccountUrl() );
    }


    public function testAcmeAgreedTerms() : void {
        self::assertFalse( $this->cfg->getAcmeAgreedTerms() );
        $this->cfg->setAcmeAgreedTerms( true );
        self::assertTrue( $this->cfg->getAcmeAgreedTerms() );
    }


    public function testAcmeContact() : void {
        self::assertNull( $this->cfg->getAcmeContact() );
        self::assertFalse( $this->cfg->hasAcmeContact() );
        $this->cfg->setAcmeContact( 'user@example.com' );
        self::assertSame( 'user@example.com', $this->cfg->getAcmeContact() );
        self::assertSame( 'user@example.com', $this->cfg->getAcmeContactEx() );
        self::assertTrue( $this->cfg->hasAcmeContact() );
    }


    public function testAcmeContactExForNotSet() : void {
        $this->expectException( \RuntimeException::class );
        $x = $this->cfg->getAcmeContactEx();
        unset( $x );
    }


    public function testApiValue() : void {
        self::assertNull( $this->cfg->getApiValue( 'whatever' ) );
        $this->cfg->setApiValue( 'whatever', 'some-value' );
        self::assertSame( 'some-value', $this->cfg->getApiValue( 'whatever' ) );
        self::assertSame( 'some-value', $this->cfg->getApiValueEx( 'whatever' ) );
    }


    public function testApiValueExForNotSet() : void {
        $this->expectException( \RuntimeException::class );
        $x = $this->cfg->getApiValueEx( 'whatever' );
        unset( $x );
    }


    public function testPersistence() : void {
        self::assertNull( $this->cfg->getAcmeAccountUrl() );
        $this->cfg->setAcmeAccountUrl( 'https://example.com/acme/acct/1' );
        self::assertSame( 'https://example.com/acme/acct/1', $this->cfg->getAcmeAccountUrl() );
        $this->cfg = new Config( $this->stPath );
        self::assertSame( 'https://example.com/acme/acct/1', $this->cfg->getAcmeAccountUrl() );
    }


    protected function setUp() : void {
        parent::setUp();
        $this->stPath = sys_get_temp_dir() . '/dns01-test-' . bin2hex( random_bytes( 5 ) ) . '.json';
        $this->cfg = new Config( $this->stPath );
    }


    protected function tearDown() : void {
        parent::tearDown();
        if ( file_exists( $this->stPath ) ) {
            unlink( $this->stPath );
        }
    }


}
