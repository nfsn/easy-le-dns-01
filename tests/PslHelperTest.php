<?php


declare( strict_types = 1 );


namespace NFSN\DNS01\Tests;


use NFSN\DNS01\PslHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( PslHelper::class )]
final class PslHelperTest extends TestCase {


    public function testDownloading() : void {
        PslHelper::clearCacheFile();
        $st = PslHelper::getPSLData();
        self::assertStringContainsString( 'com', $st );
    }


    public function testInferDomainFromFQDN() : void {
        self::assertSame( 'example.com', PslHelper::inferDomainFromFQDN( 'example.com' ) );
        self::assertSame( 'example.com', PslHelper::inferDomainFromFQDN( 'www.example.com' ) );
        self::assertSame( 'example.com', PslHelper::inferDomainFromFQDN( 'sub.www.example.com' ) );
        self::assertSame( 'example.co.uk', PslHelper::inferDomainFromFQDN( 'example.co.uk' ) );
        self::assertSame( 'example.co.uk', PslHelper::inferDomainFromFQDN( 'www.example.co.uk' ) );
        self::assertSame( 'example.co.uk', PslHelper::inferDomainFromFQDN( 'sub.www.example.co.uk' ) );
        self::assertSame( 'example.org.au', PslHelper::inferDomainFromFQDN( 'example.org.au' ) );
        self::assertSame( 'example.org.au', PslHelper::inferDomainFromFQDN( 'www.example.org.au' ) );
        self::assertSame( 'example.org.au', PslHelper::inferDomainFromFQDN( 'sub.www.example.org.au' ) );
        self::assertSame( '例子.测试', PslHelper::inferDomainFromFQDN( '例子.测试' ) );
        self::assertSame( '例子.测试', PslHelper::inferDomainFromFQDN( 'www.例子.测试' ) );
        self::assertSame( '例子.测试', PslHelper::inferDomainFromFQDN( 'sub.www.例子.测试' ) );
    }


}
