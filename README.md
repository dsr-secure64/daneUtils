# DANE utilities

 * [smimeaUtil](#SMIMEA Utility)
 * [tlsaUtil](#TLSA Utility)

## Build dependencies

The smimea-util is designed for testing of SMIMEA records generated by
miekg/dns go package. To build the file assumes the following branch:

remotes/origin/smimea                  f13c21d Fix for miekg/dns issue #289: support the SMIMEA record

Until such time as the changes are added to master development branch.

## SMIMEA Utility

The smimea-util go program generates an SMIMEA record from the following:

```
1) An Email Certificate  
2) A user name  
3) A user domain
```

The utility further allows any valid value for the usage, selector,
and matching type fields to support the desired formating of the
SMIMEA RDATA section.

### Usage

```
Usage of ./smimea-util:  
  -certPEMFile string  
    certificate file in PEM format  
  -matchType int  
     Dane matching type field  
  -selector int  
    DANE certificate selector field
  -usage int
    DANE certificate usage field
  -userdomain string
    email user domain association
  -username string
    email user name
```

### Example Output
```
dsr@enigma:~/go/src/dsr/certs-test$ ./smimea-util -username=bilbo.baggins -userdomain=theshire.com -certPEMFile=certs/bbaggins.pem -usage=3 -selector=0 -matchType=0

SMIMEA record for bilbo.baggins@theshire.com

2e85e1db3e62be6ea76d855de96d8dce26e29b8323be936b13f71bbb._smimecert.theshire.com	3600	IN	SMIMEA	3 0 0 3082053c30820324020101300d06092a864886f70d01010b05003057310b3009060355040613025553310b300906035504080c02434f310d300b06035504070c04464f434f31133011060355040a0c0a536175726f6e20496e633117301506035504030c0e7777772e736175726f6e2e636f6d301e170d3136313030393033343034375a170d3137313030393033343034375a3071310b3009060355040613025553310b300906035504080c02434f310d300b06035504070c04464f434f3121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643123302106035504030c1a62696c626f2e62616767696e734074686573686972652e636f6d30820222300d06092a864886f70d01010105000382020f003082020a0282020100d19f6e2462b3e216ff3f8dcb263dbd325b5a23df522ebd9f6eb72a9768c3413f2829c5c93d5fae3ac7d1db377a79d457172661e16efe0e135b39b2c60306a1d2e4a934c6928d4e25d3fabf2d5a11291f75059951b5052c6f0807edeae33cc62f53c2e14a1016005c4a0a9850c357b87ef27bcf05f1c77e59066f6fb07fd3ec27e94ecc7951956099ef81f0484ff4529b609f2f4287cd29db5c14e710aef6219308b27649e5862b1a1318ff51ca8b8ea09b09e48a56b47398495840af93b7e363078c1374677f7a2df19f6aceb9a09ae2f1f07ed347d24d48988db606c52e9366483f1963086af2a077fe7d2220c66196dcde4e18e214199f8f6c5d48c3cd9892d513e68025b061c2822c773fa6a5c6a52d92ea790c65c4b94c6726825adb5784ca1963383152853bab0503d1057783125c5ca8fbff1f48364e60d70f612a0fb6229fc2b297a4ea0f50483765bb3d6ab2830887a96092810d35a2d8736402845f8c9f52aa4ac20f286f9a04d99bf2968e331242904441b1be7c91beec49dbd3c95b38d4ef4912f534f7bfe8cf758378f2b8e4a91dc6c51ab37c072e05640f27d292a10985ba9971e67809018eb02aa759529007d0b16951508c2ed47d6553bac0f99eccc886354d4cd487bdb8ca640085f51e4608b3e12a8f0b824d88531e84c3b6c52e43999828d3c220af678cdb3d3b32a889cc8b2db47e70c23c517d8554510203010001300d06092a864886f70d01010b05000382020100a8cfb43cf39eea17c85797f9111ecb74907f5e102e1f8799043b53d8a94a1d0dde3f045fcfd09a2910a1db318917e04b1e22de316e3008e9f12ab7f7e259a1dc02334118de9f5897e02df0a4f024cb8ec4df9a030d83820c464638e4180d95a989a209cab79bb469ca76f2cd327691e86776bb76834560ec9c66a1a572367b7164b96fa3bfc8999ddc57b34113291fd43ae401be4f554820c7dd543ddedcdeb6b96a4bdb8fc5895a89e8cbb5cfb58ea15bb72b307b0915840cf75cad4954b50229c117ca4c2cd4ca4e57b7a46c60131d69b41151c8af2bc0b7fbbe2f4d6827c6dedd2cf0f334ce790220a5d63f4cc729cba9953a8b9fcda3b954fcb76e2379d4933458cdf0ec3a04470e39c624a76a6bd74c33c219c25bb98520767d9a6bb702eaf8ce4a86f8689e32cf0b373e166ee9f09ff70151b99734a1ba1d91e4899fa8f8f7ec0d3778e61091db212e921ac5232143443ccc62611d59efce41f2921013ccc9157b3da25ccec0999513afd18a641f34cf46ee31485f4a8ccd8dab2eaa4271466c01b5e7f4151af4e80917f665415d87435933e2c6296f06df33735cb706045b632cb1889bc5d561b67592199eb40804a3b49dfe94154256481565d747f7b09ea97ed375915c292b5c6b440f5eb6a074d78843ac9bf015a1cccdd78d67462b182bdfb53bc7f43896fafbe06cc4056f6be86364add6d9e823fc3a79b2f5b6
```

### SMIMEA Certificate

The certs/ directory contains the following certificate files for Mr. Baggins:

1) bbaggins.crt
2) bbaggins.pem

The contents of the certificate are as follows.

```
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 1 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=CO, L=FOCO, O=Sauron Inc, CN=www.sauron.com
        Validity
            Not Before: Oct  9 03:40:47 2016 GMT
            Not After : Oct  9 03:40:47 2017 GMT
        Subject: C=US, ST=CO, L=FOCO, O=Internet Widgits Pty Ltd, CN=bilbo.baggins@theshire.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:d1:9f:6e:24:62:b3:e2:16:ff:3f:8d:cb:26:3d:
                    bd:32:5b:5a:23:df:52:2e:bd:9f:6e:b7:2a:97:68:
                    c3:41:3f:28:29:c5:c9:3d:5f:ae:3a:c7:d1:db:37:
                    7a:79:d4:57:17:26:61:e1:6e:fe:0e:13:5b:39:b2:
                    c6:03:06:a1:d2:e4:a9:34:c6:92:8d:4e:25:d3:fa:
                    bf:2d:5a:11:29:1f:75:05:99:51:b5:05:2c:6f:08:
                    07:ed:ea:e3:3c:c6:2f:53:c2:e1:4a:10:16:00:5c:
                    4a:0a:98:50:c3:57:b8:7e:f2:7b:cf:05:f1:c7:7e:
                    59:06:6f:6f:b0:7f:d3:ec:27:e9:4e:cc:79:51:95:
                    60:99:ef:81:f0:48:4f:f4:52:9b:60:9f:2f:42:87:
                    cd:29:db:5c:14:e7:10:ae:f6:21:93:08:b2:76:49:
                    e5:86:2b:1a:13:18:ff:51:ca:8b:8e:a0:9b:09:e4:
                    8a:56:b4:73:98:49:58:40:af:93:b7:e3:63:07:8c:
                    13:74:67:7f:7a:2d:f1:9f:6a:ce:b9:a0:9a:e2:f1:
                    f0:7e:d3:47:d2:4d:48:98:8d:b6:06:c5:2e:93:66:
                    48:3f:19:63:08:6a:f2:a0:77:fe:7d:22:20:c6:61:
                    96:dc:de:4e:18:e2:14:19:9f:8f:6c:5d:48:c3:cd:
                    98:92:d5:13:e6:80:25:b0:61:c2:82:2c:77:3f:a6:
                    a5:c6:a5:2d:92:ea:79:0c:65:c4:b9:4c:67:26:82:
                    5a:db:57:84:ca:19:63:38:31:52:85:3b:ab:05:03:
                    d1:05:77:83:12:5c:5c:a8:fb:ff:1f:48:36:4e:60:
                    d7:0f:61:2a:0f:b6:22:9f:c2:b2:97:a4:ea:0f:50:
                    48:37:65:bb:3d:6a:b2:83:08:87:a9:60:92:81:0d:
                    35:a2:d8:73:64:02:84:5f:8c:9f:52:aa:4a:c2:0f:
                    28:6f:9a:04:d9:9b:f2:96:8e:33:12:42:90:44:41:
                    b1:be:7c:91:be:ec:49:db:d3:c9:5b:38:d4:ef:49:
                    12:f5:34:f7:bf:e8:cf:75:83:78:f2:b8:e4:a9:1d:
                    c6:c5:1a:b3:7c:07:2e:05:64:0f:27:d2:92:a1:09:
                    85:ba:99:71:e6:78:09:01:8e:b0:2a:a7:59:52:90:
                    07:d0:b1:69:51:50:8c:2e:d4:7d:65:53:ba:c0:f9:
                    9e:cc:c8:86:35:4d:4c:d4:87:bd:b8:ca:64:00:85:
                    f5:1e:46:08:b3:e1:2a:8f:0b:82:4d:88:53:1e:84:
                    c3:b6:c5:2e:43:99:98:28:d3:c2:20:af:67:8c:db:
                    3d:3b:32:a8:89:cc:8b:2d:b4:7e:70:c2:3c:51:7d:
                    85:54:51
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
         a8:cf:b4:3c:f3:9e:ea:17:c8:57:97:f9:11:1e:cb:74:90:7f:
         5e:10:2e:1f:87:99:04:3b:53:d8:a9:4a:1d:0d:de:3f:04:5f:
         cf:d0:9a:29:10:a1:db:31:89:17:e0:4b:1e:22:de:31:6e:30:
         08:e9:f1:2a:b7:f7:e2:59:a1:dc:02:33:41:18:de:9f:58:97:
         e0:2d:f0:a4:f0:24:cb:8e:c4:df:9a:03:0d:83:82:0c:46:46:
         38:e4:18:0d:95:a9:89:a2:09:ca:b7:9b:b4:69:ca:76:f2:cd:
         32:76:91:e8:67:76:bb:76:83:45:60:ec:9c:66:a1:a5:72:36:
         7b:71:64:b9:6f:a3:bf:c8:99:9d:dc:57:b3:41:13:29:1f:d4:
         3a:e4:01:be:4f:55:48:20:c7:dd:54:3d:de:dc:de:b6:b9:6a:
         4b:db:8f:c5:89:5a:89:e8:cb:b5:cf:b5:8e:a1:5b:b7:2b:30:
         7b:09:15:84:0c:f7:5c:ad:49:54:b5:02:29:c1:17:ca:4c:2c:
         d4:ca:4e:57:b7:a4:6c:60:13:1d:69:b4:11:51:c8:af:2b:c0:
         b7:fb:be:2f:4d:68:27:c6:de:dd:2c:f0:f3:34:ce:79:02:20:
         a5:d6:3f:4c:c7:29:cb:a9:95:3a:8b:9f:cd:a3:b9:54:fc:b7:
         6e:23:79:d4:93:34:58:cd:f0:ec:3a:04:47:0e:39:c6:24:a7:
         6a:6b:d7:4c:33:c2:19:c2:5b:b9:85:20:76:7d:9a:6b:b7:02:
         ea:f8:ce:4a:86:f8:68:9e:32:cf:0b:37:3e:16:6e:e9:f0:9f:
         f7:01:51:b9:97:34:a1:ba:1d:91:e4:89:9f:a8:f8:f7:ec:0d:
         37:78:e6:10:91:db:21:2e:92:1a:c5:23:21:43:44:3c:cc:62:
         61:1d:59:ef:ce:41:f2:92:10:13:cc:c9:15:7b:3d:a2:5c:ce:
         c0:99:95:13:af:d1:8a:64:1f:34:cf:46:ee:31:48:5f:4a:8c:
         cd:8d:ab:2e:aa:42:71:46:6c:01:b5:e7:f4:15:1a:f4:e8:09:
         17:f6:65:41:5d:87:43:59:33:e2:c6:29:6f:06:df:33:73:5c:
         b7:06:04:5b:63:2c:b1:88:9b:c5:d5:61:b6:75:92:19:9e:b4:
         08:04:a3:b4:9d:fe:94:15:42:56:48:15:65:d7:47:f7:b0:9e:
         a9:7e:d3:75:91:5c:29:2b:5c:6b:44:0f:5e:b6:a0:74:d7:88:
         43:ac:9b:f0:15:a1:cc:cd:d7:8d:67:46:2b:18:2b:df:b5:3b:
         c7:f4:38:96:fa:fb:e0:6c:c4:05:6f:6b:e8:63:64:ad:d6:d9:
         e8:23:fc:3a:79:b2:f5:b6
Trusted Uses:
  E-mail Protection
Rejected Uses:
  TLS Web Client Authentication, TLS Web Server Authentication
Alias: Self Signed SMIME
-----BEGIN CERTIFICATE-----
MIIFPDCCAyQCAQEwDQYJKoZIhvcNAQELBQAwVzELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAkNPMQ0wCwYDVQQHDARGT0NPMRMwEQYDVQQKDApTYXVyb24gSW5jMRcwFQYD
VQQDDA53d3cuc2F1cm9uLmNvbTAeFw0xNjEwMDkwMzQwNDdaFw0xNzEwMDkwMzQw
NDdaMHExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzENMAsGA1UEBwwERk9DTzEh
MB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMSMwIQYDVQQDDBpiaWxi
by5iYWdnaW5zQHRoZXNoaXJlLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBANGfbiRis+IW/z+NyyY9vTJbWiPfUi69n263Kpdow0E/KCnFyT1frjrH
0ds3ennUVxcmYeFu/g4TWzmyxgMGodLkqTTGko1OJdP6vy1aESkfdQWZUbUFLG8I
B+3q4zzGL1PC4UoQFgBcSgqYUMNXuH7ye88F8cd+WQZvb7B/0+wn6U7MeVGVYJnv
gfBIT/RSm2CfL0KHzSnbXBTnEK72IZMIsnZJ5YYrGhMY/1HKi46gmwnkila0c5hJ
WECvk7fjYweME3Rnf3ot8Z9qzrmgmuLx8H7TR9JNSJiNtgbFLpNmSD8ZYwhq8qB3
/n0iIMZhltzeThjiFBmfj2xdSMPNmJLVE+aAJbBhwoIsdz+mpcalLZLqeQxlxLlM
ZyaCWttXhMoZYzgxUoU7qwUD0QV3gxJcXKj7/x9INk5g1w9hKg+2Ip/Cspek6g9Q
SDdluz1qsoMIh6lgkoENNaLYc2QChF+Mn1KqSsIPKG+aBNmb8paOMxJCkERBsb58
kb7sSdvTyVs41O9JEvU097/oz3WDePK45KkdxsUas3wHLgVkDyfSkqEJhbqZceZ4
CQGOsCqnWVKQB9CxaVFQjC7UfWVTusD5nszIhjVNTNSHvbjKZACF9R5GCLPhKo8L
gk2IUx6Ew7bFLkOZmCjTwiCvZ4zbPTsyqInMiy20fnDCPFF9hVRRAgMBAAEwDQYJ
KoZIhvcNAQELBQADggIBAKjPtDzznuoXyFeX+REey3SQf14QLh+HmQQ7U9ipSh0N
3j8EX8/QmikQodsxiRfgSx4i3jFuMAjp8Sq39+JZodwCM0EY3p9Yl+At8KTwJMuO
xN+aAw2DggxGRjjkGA2VqYmiCcq3m7RpynbyzTJ2kehndrt2g0Vg7JxmoaVyNntx
ZLlvo7/ImZ3cV7NBEykf1DrkAb5PVUggx91UPd7c3ra5akvbj8WJWonoy7XPtY6h
W7crMHsJFYQM91ytSVS1AinBF8pMLNTKTle3pGxgEx1ptBFRyK8rwLf7vi9NaCfG
3t0s8PM0znkCIKXWP0zHKcuplTqLn82juVT8t24jedSTNFjN8Ow6BEcOOcYkp2pr
10wzwhnCW7mFIHZ9mmu3Aur4zkqG+GieMs8LNz4Wbunwn/cBUbmXNKG6HZHkiZ+o
+PfsDTd45hCR2yEukhrFIyFDRDzMYmEdWe/OQfKSEBPMyRV7PaJczsCZlROv0Ypk
HzTPRu4xSF9KjM2Nqy6qQnFGbAG15/QVGvToCRf2ZUFdh0NZM+LGKW8G3zNzXLcG
BFtjLLGIm8XVYbZ1khmetAgEo7Sd/pQVQlZIFWXXR/ewnql+03WRXCkrXGtED162
oHTXiEOsm/AVoczN141nRisYK9+1O8f0OJb6++BsxAVva+hjZK3W2egj/Dp5svW2
-----END CERTIFICATE-----
```

## TLSA Utility

The smimea-util go program generates an SMIMEA record from the following:

```
1) An Email Certificate  
2) A user name  
3) A user domain
```

The utility further allows any valid value for the usage, selector,
and matching type fields to support the desired formating of the
SMIMEA RDATA section.

```

### Usage
Usage of ./tlsa-util:
  -certPEMFile string
       TLS certificate file iQn PEM format
  -fqdn string
       fully qualified domain name
  -matchType int
       Dane matching type field
  -network string
       network protocol: tcp, udp
  -selector int
       DANE certificate selector field
  -service string
       /etc/services defined application
  -usage int
       DANE certificate usage field
```

### Example Output

```
> ./tlsa-util -certPEMFile=certs/enigma-tls.pem -fqdn enigma.i.secure64.com -network tcp -service https -usage=3 -selector=0 -matchType=0

dsr@enigma:~/go/src/github.com/dsr-secure64/daneUtils$ ./tlsa-util -certPEMFile=certs/enigma-tls.pem -fqdn enigma.i.secure64.com -network tcp -service https -usage=3 -selector=0 -matchType=0
TLSA name: _443._tcp.enigma.i.secure64.com.
TLSA record: _443._tcp.enigma.i.secure64.com.	3600	IN	TLSA	3 0 0 308205453082032d020103300d06092a864886f70d01010b0500306d3111300f060355040a13085365637572653634311530130603550407130c466f727420436f6c6c696e73310b300906035504081302434f310b3009060355040613025553312730250603550403131e536563757265363420436572746966696361746520417574686f72697479301e170d3136313031323135343834395a170d3236313031303135343834395a30643111300f060355040a13085365637572653634311530130603550407130c466f727420436f6c6c696e73310b300906035504081302434f310b3009060355040613025553311e301c06035504031315656e69676d612e692e73656375726536342e636f6d30820222300d06092a864886f70d01010105000382020f003082020a02820201009856dec13c10400d79a2dc8ecf0ab2c9846fc87fccd20ccb447ae11cf4b21f9fbc323121f0b7c600026e302794efe61692deb66b2bc41751ddbe7f6433118431240edf7688e400bcc36d97a4808e935c3144c18cc0021eac7724c8db5f30a8643ba4c74e7bb81b799c8d1dcad5f267339cad3b09f9b0f8787a8e79c339cea0ef1ba181fa0e52b82d9b4b1d4bc8c0cacbdc425c1e76c610b9e78e88cc21fc37872f6e090fcb83100d11e446ac15468d3d981e673949251141307e57b20947460f1caee28447433d1e7cb1d1c1ad15d14560068c56707ce568f951b2fab4e3b57a3c0f339d3d6b4abb06e29725a6d11feb6066e32c492d729b7a2abcc5ccae93bd6b6d5c1d384058b95a58e7dc2d3210d81c8c0018b962e6a2ab463f47a977869566e8714cf928590c3d6f760509ae83d94cf0a7d15d0c86904ad52f538b55e98bda5a575810efc8b200fb3a27803d01b6f1f40d38ce80b8fd4b2a6b8472ae83657abf873f723764586a475dca1698c66d95d55434ea215f6de65fc4153b587064db45e80fccba38cd3973138fa50c3fd74ee04a0bf807d746b539e4730cdfa6663df3beb5544544bde77e2a0b28f6985845242910ab0a1867d7a9c2d28a9f05c57a661d1b1fda0c34a0b4ad3c4f1101210198c25a40d1382c956642fcaae1e62dee16d5d40053114a30cb257d7d272351fda208bf04f6f60fa509916128cbd0630203010001300d06092a864886f70d01010b050003820201000552418f12c32ff57958c71f476f3cda02cc13c2cb1569fde983eb493da86554a845b034143d5348ec6a740095314cfb1c3bcc664bd46c646c4f5c0b4c981baa6a79c17dafc69dbbbcc0c6dfc32f960d1ae14789848a22c04c5f326e57c96cbde3a9f7a764416f73aee2aa720c7a492fe4f1ced594a370ffd6be527f0eccabc7baa83cf9a388af18a3004492b1e3f8303c79c36e8d29d1cf6fba42db9a27132d458e30968ff3e221d13b1abeeaaaf7c94f31a86fef54f8fce57070a9e9718c492d0a3c6ffc0e6c4fe7ee0c3bae08c72edf44f9fc6bcdb2c134362bb21bd284bb32356d15ecca0dfb2c2175ef5298b1c633cb184e732597a16bd10e14e90879a35e4cf878e46954c94edccf523ad411b1c04aab6cf1818ef84e4e6fa08f8db870b32f2c772b171d63e31217bed725857786dc8b6d61c0820db39fa71b9da89a1215d0c00ed89735ef463eb0e6de3a3944bed17d2d261d48f6b22e41045086e36b6361267d27d02f24e4e23ee85bf48c681d34175134a561d1870f7c191b22c78b0d33986ca0d45d68aa1ec9a2c640992730218fd32806a6814ef53104960943c1bbf766c0590728aec7307e5a979053f17d9b420fceca0f9ebea2fcff70d1c88c3c17b579b668c71e72d4a55001bbb9c80b5b2f05a35129b8e7769c86b9e74bc9a8f13ec21c3972bc1e2bf235527d6f47938519fa41c702f4e0842a06280b97b4

```


