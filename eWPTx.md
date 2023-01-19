# eWPTx (Web Penetration Testing xTreme)

## Module 1

### Data Encoding Basics
> URL encoding
* Safe Characters -> [0-9a-zA-Z] and $-.+!()'_* and  reserved chars
* ASCII Control Controls -> ISO-8859-1 (ISO LATIN - 00-1F hex [0-31 decimal])
* Non-ASCII Characters -> Top half of ISO latin (80-FF hex [128-255 decimal])
* Reserved Characters -> $&+,/:;=?@
* Unsafe Characters -> "<>#%{}|^~[]`\`

> HTML encoding
> Base 32|64 encoding
> Unicode encoding


## Module 2 

### Evasions

#### Base64 Encoding Evasion
* Specific keywords like alert, eval, prompt, document.cookie etc are blaclisted so encode them  

Ex ->> eval(document.cookie) --> eval(atob(ZG9jdW1lbnQuY29va2ll))
Eval can be blacklisted so instead use --> [].constructor.constructor("code")()

Ex ->> eval(document.cookie) --> [].constructor.constructor("atob(ZG9jdW1lbnQuY29va2ll)")()

### URL Obfuscation Techniques
> URL Shortner 
* If `https://example.com` is not allowed use URL shortners like bitly.com (ex. bit.ly/5475 or j.mp/5874), tinyurl.com, tiny.cc etc to bypass it.

> URL Hostname Obfuscation
* Normal URLs are like `https://example.com/s/#n:xss` but RFC_3986 says `https://_[valid_too]_@example.com` is valid too.
> URL Authority Obfuscation
* Structure :
foo://example.com:8080/over/here?name=legend#killer
In general :
scheme://authority/path/path?query#fragment

Ex ->> http://username:password@example.com/protected_path and http://www.google.com@example.com/t/xss

If no such auth mechanism is present the text before authority is ignored.

* DWORD - Double Word also known as Integer IP. Google IP 216.58.215.78 translate to 3627734862 and can be accessed at -> http://3627734862
* OCTAL - Google IP can be represented in Octal form like http://0330.0072.0327.0116 and we can feed leading zeros http://00000330.00000072.00000327.00000116
* HEXADECIMAL - Google IP can be represented in Hexadecimal like http://0xd83ad74e, also can be http://0xd8.0x3a.0xd7.0x4e, we can also add leading zeros http://0x000000d8.0x0000003a.0x000000d7.0x0000004e

#### Java Obfuscation Techniques
* Techniques ->> JJencode and Aaencode from JSFuck
* Minifying (Closure compiler, YUICompressor, JSMin, Packer)

#### PHP Obfuscation Techniques
* Type Juggling
* Single (No escapes) vs Double (escapes) quotes
* Curly brackets {$var} for variable parsing --> {$var}, ${var}, {${var}} etc
* Heredoc (for double quotes) vs Nowdoc (for single quotes) 

## Module 3 

### XSS - Cross Site Scripting
* Types ->> Stored, Reflected, DOM, Universal


