#!/usr/local/bin/perl
#
# The Cyber Anonymizer 1.1 1998 (www.cyberarmy.com).
#
# Based on "CGI-Proxy" by James Marshall (who did 90% of the script).
# This script sets up an anonymous web surfing gateway on the net.
# You need cgi access, and the two cgi script should be chmod
# to 755 through Cute-FTP or whatever FTP program you use.
#
# This script is Open Source and Public Domain. Please reference
# cyberarmy.com if using the script.
#


$textonly= 1 ;      # set to 1 to allow only text data, 0 to allow all


$SIG{'ALRM'} = 'timeexit' ;
alarm(240);

# Exit upon timeout.  If you wish, add code to clean up and log an error.
sub timeexit { exit 1 }

# Requires Perl 5.  To run in Perl 4, or for more speed, remove this line and 
#   hard-code $AF_INET and $SOCK_STREAM (usually in /usr/include/sys/socket.h
#   or /usr/include/linux/socket.h) into &newsocketto().
use Socket ;


$ENV{'SCRIPT_NAME'}=~ s#^/## ;

# Copy often-used environment vars into scalars, for efficiency
$env_accept= $ENV{'HTTP_ACCEPT'} || '*/*' ;     # may be modified later

# QUERY_STRING with question mark prepended
$qs_out=  $ENV{'QUERY_STRING'} ne ''   ?  '?' . $ENV{'QUERY_STRING'}   :  '' ;

# Calculate $thisurl, useful in many places
$portst=  $ENV{'SERVER_PORT'}==80  ?  ''   :  ':' . $ENV{'SERVER_PORT'} ;
$thisurl= join('', 'http://', $ENV{'SERVER_NAME'}, $portst, 
                    '/', $ENV{'SCRIPT_NAME'}, '/') ;


#------ parsing of URL and other input ------------------------------------

# Read the URL from PATH_INFO, stripping leading slash
($URL= $ENV{'PATH_INFO'})=~ s#^/## ;

($scheme, $host, $port, $path)= 
    ($URL=~ m#^([\w+.-]+)://([^/:]*):?([^/]*)(/.*)?$#i) ;
$port || ($port= 80) ;

# Alert the user to non-HTTP URL, with an intermediate page
&nonHTTPwarning($URL.$qs_out) unless ($scheme=~ /^http$/i) ;

# If path is empty, send back Location: to include the final slash.
#   Otherwise, the browser itself will resolve relative URL's wrong.
if ($path eq '') {
    print "HTTP/1.0 302 Found\012Location: ", $thisurl, $URL, "/\012\012" ;
    exit ;
}


# Exclude non-text if it's not allowed.  Err on the side of allowing too much.
if ($textonly) {

    $nontext= 'gif|jpeg|jpe|jpg|tiff|tif|png|bmp|xbm'   # images
            . '|mp2|mp3|wav|aif|aiff|au|snd'            # audios
            . '|avi|qt|mov|mpeg|mpg|mpe'                # videos
            . '|gz|Z|exe|gtar|tar|zip|sit|hqx|pdf'      # applications
            . '|ram|rm|ra' ;                            # others

    &nontextdie if ($path=~ /\.($nontext)(;|$)/i) ;

    # Then, filter the "Accept:" header to accept only text
    $env_accept=~ s#\*/\*#text/*#g ;    # not strictly perfect
    $env_accept= join(', ', grep(m#^text/#i, split(/\s*,\s*/, $env_accept)) ) ;
    &nontextdie unless $env_accept ne '' ;
}


$realhost= $host ;
$realport= $port ;
$realpath= $path ;

# there must be a smoother way to handle proxies....
if ($ENV{'http_proxy'}) {
    local($dontproxy) ;
    foreach (split(/\s*,\s*/, $ENV{'no_proxy'})) {
        last if ($dontproxy= $host=~ /$_$/) ;
    }
    unless ($dontproxy) {
	# could be slightly more efficient in Perl 5
        ($dummy,$realhost,$realport)=
            $ENV{'http_proxy'}=~ m#^(http://)?([^/:]*):?([^/]*)#i ;
        $realport= ($realport || 80) ;
        $realpath= $URL ;
    }
}



&newsocketto(*S, $realhost, $realport) ;

print S $ENV{'REQUEST_METHOD'}, ' ', $realpath, $qs_out, " HTTP/1.0\015\012",
	'Host: ', $host, ':', $port, "\015\012",
        'Accept: ', $env_accept, "\015\012",        # possibly modified above
        'User-Agent: Mozilla/4.01 (compatible; NORAD National Defence Network)', "\015\012" ;

# If request method is POST, copy content headers and body to request.  Loop
#   to guarantee all is read from STDIN.
if ($ENV{'REQUEST_METHOD'} eq 'POST') {
    $lefttoget= $ENV{'CONTENT_LENGTH'} ;
    print S 'Content-type: ', $ENV{'CONTENT_TYPE'}, "\015\012", 
            'Content-length: ', $lefttoget, "\015\012\015\012" ;
    do {
        $lefttoget-= read(STDIN, $postbody, $lefttoget) ;
        print S $postbody ;
    } while $lefttoget && length($postbody) ;

# For GET requests, just add extra blank line
} else {
    print S "\015\012" ;
}

vec($rin= '', fileno(S), 1)= 1 ;
select($rin, undef, undef, 60) 
    || &HTMLdie("No response from $realhost:$realport") ;




# Support both HTTP 1.x and HTTP 0.9
$status= <S> ;  # first line, which is the status line in HTTP 1.x

# HTTP 1.x
if ($status=~ m#^HTTP/#) {
    do {
        $headers.= $_= <S> ;    # $headers includes last blank line
    } until (/^(\015\012|\012)$/) ;   # lines may be terminated with LF or CRLF

    # Unfold long header lines, a la RFC 822 section 3.1.1
    $headers=~ s/(\015\012|\012)[ \t]/ /g ;

    # If we're text only, then cut off non-text responses
    if ($textonly) {
        $*= 1 ;
        if ($headers=~ m#^Content-type:\s*([\w/]*)#i) {
            (close(S), &nontextdie) unless $1=~ m#^text/#i ;
        }
    }

    $/= '>' ;
    @body= <S> ;

# HTTP 0.9 
} else {
    undef $/ ;
    $_= $status . <S> ;
    $status= '' ;

    # split through ">", including "delimiters", and remove (via grep)
    #   the "actual" matches, which are blank
    @body= grep(length,split( /([^>]*>?)/ )) ;
}

close(S) ;




$*= 1 ;     # allow multi-line matching

# Set $basehost correctly-- first see if there's a <base> tag, then if
#   there's a Location: header; otherwise, use original URL.
# This is part of &fullurl(), placed here for speed.
($_)= grep(/<\s*base\b/i, @body) ;
if      ( ($basehost) = m#<\s*base\b[^>]*\bhref\s*=\s*"?([\w+.-]+://[^/\s">]+)#i ) {
} elsif ( ($basehost)= ($headers=~ m#^Location:\s*([\w+.-]+://[^/\s]+)#i) ) {
} else  { ($basehost= join('', 'http://', $host, (($port==80) ?'' :":$port") ) ) }

$basehost= $thisurl . $basehost ;


# If we get a 300-level response code, update the Location: header to point
#   back through the script, so the browser will retrieve it correctly.
if ($status=~ m#^HTTP/[0-9.]*\s*3\d\d#) {
    $headers=~ s/^Location:\s*(.*)/'Location: ' . &fullurl($1)/gie ;
    $headers=~ s/^URI:\s*(.*)/     'URI: '      . &fullurl($1)/gie ;
}



# Update all URLs in all tags that refer to URLs
# Only update the URLs if it's HTML (or using HTTP 0.9), and if it's not
#   empty.

if ( (($headers=~ m#^Content-type:\s*text/html#i) || !$headers) 
     && ($body[0] ne '') ) {

  

    foreach (@body) {

	# Put the most common cases first

        s/(<[^>]*\bhref\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*a\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\blowsrc\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
        s/(<[^>]*\blongdesc\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
        s/(<[^>]*\busemap\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
        s/(<[^>]*\bdynsrc\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
            next if /<\s*img\b/i ;

        s/(<[^>]*\bbackground\s*=\s*"?)([^\s">]*)/ $1 . &fullurl($2) /ie,
            next if /<\s*body\b/i ;

        s/(<[^>]*\bhref\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*base\b/i ;     # has special significance

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\blongdesc\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
            next if /<\s*frame\b/i ;

        s/(<[^>]*\baction\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
        s/(<[^>]*\bscript\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
            next if /<\s*form\b/i ;     # needs special attention

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\busemap\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
            next if /<\s*input\b/i ;

        s/(<[^>]*\bhref\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*area\b/i ;

        s/(<[^>]*\bcodebase\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
        s/(<[^>]*\bcode\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
        s/(<[^>]*\bobject\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
        s/(<[^>]*\barchive\s*=\s*"?)([^\s">]*)/    $1 . &fullurl($2) /ie,
            next if /<\s*applet\b/i ;


        # These are seldom-used tags, or tags that seldom have URLs in them

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*bgsound\b/i ;  # Microsoft only

        s/(<[^>]*\bcite\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*blockquote\b/i ;

        s/(<[^>]*\bcite\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*del\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*embed\b/i ;    # Netscape only

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\bimagemap\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
            next if /<\s*fig\b/i ;      # HTML 3.0

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*h[1-6]\b/i ;   # HTML 3.0

        s/(<[^>]*\bprofile\s*=\s*"?)([^\s">]*)/    $1 . &fullurl($2) /ie,
            next if /<\s*head\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*hr\b/i ;       # HTML 3.0

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\blongdesc\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
            next if /<\s*iframe\b/i ;

        s/(<[^>]*\bcite\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*ins\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*layer\b/i ;

        s/(<[^>]*\bhref\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
        s/(<[^>]*\burn\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*link\b/i ;

        s/(<[^>]*\burl\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*meta\b/i ;     # Netscape only

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*note\b/i ;     # HTML 3.0

        s/(<[^>]*\busemap\s*=\s*"?)([^\s">]*)/     $1 . &fullurl($2) /ie,
        s/(<[^>]*\bcodebase\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
        s/(<[^>]*\bdata\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
        s/(<[^>]*\barchive\s*=\s*"?)([^\s">]*)/    $1 . &fullurl($2) /ie,
        s/(<[^>]*\bclassid\s*=\s*"?)([^\s">]*)/    $1 . &fullurl($2) /ie,
        s/(<[^>]*\bname\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*object\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\bimagemap\s*=\s*"?)([^\s">]*)/   $1 . &fullurl($2) /ie,
            next if /<\s*overlay\b/i ;  # HTML 3.0

        s/(<[^>]*\bcite\s*=\s*"?)([^\s">]*)/       $1 . &fullurl($2) /ie,
            next if /<\s*q\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
        s/(<[^>]*\bfor\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*script\b/i ;

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*select\b/i ;   # HTML 3.0

        s/(<[^>]*\bsrc\s*=\s*"?)([^\s">]*)/        $1 . &fullurl($2) /ie,
            next if /<\s*ul\b/i ;       # HTML 3.0

    }   # foreach (@body)


    $body[0]= "<title>You are surfing through the CYBER ANONYMIZER</title>\n" 
            . $body[0] ;

    # Change Content-Length header, since we're changing the content
    $headers=~ s/^Content-Length:.*\012/ 'Content-Length: ' 
            . (grep($newlength+=length(),@body), $newlength) 
            . "\015\012"/ie ;

}

# print the status line, headers, and the entire (modified) resource
print $status, $headers, @body ;





exit ;



sub fullurl {
    local($relurl)= @_ ;
    $relurl=~ m#^[\w+.-]*:#i  && return ($thisurl.$relurl) ;  # absolute URL
    $relurl=~ m#^/#           && return ($basehost.$relurl) ; # absolute path, relative URL
                                 return $relurl ;             # relative URL
}



sub newsocketto {
    local(*S, $host, $port)= @_ ;

    # Create the remote host data structure, from host name or IP address
    $hostaddr= ($host=~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)
                  ?  pack('c4', $1, $2, $3, $4)     # for IP address
                  :  ( (gethostbyname($host))[4]    # for alpha host name
                       || &HTMLdie("Couldn't find address for $host: $!") ) ;
    $remotehost= pack('S n a4 x8', AF_INET, $port, $hostaddr) ;

    # Create the socket and connect to the remote host
    socket(S, AF_INET, SOCK_STREAM, (getprotobyname('tcp'))[2])
        || &HTMLdie("Couldn't create socket: $!") ;
    connect(S, $remotehost) 
        || &HTMLdie("Couldn't connect to $host:$port: $!") ;
    select((select(S), $|=1)[0]) ;      # unbuffer the socket
}


# Alert the user to non-HTTP URL, with this intermediate page
sub nonHTTPwarning {
    print <<EOF ;
HTTP/1.0 200 OK
Content-type: text/html

<html>
<head><title>WARNING: Entering non-anonymous area!</title></head>
<body>
<h1>WARNING: Entering non-anonymous area!</h1>
<h3>This proxy only supports HTTP.  Any browsing to a non-HTTP URL will
be directly from your browser, and no longer anonymous.</h3>
<h3>Click the link below to continue to the URL, non-anonymously.</h3>
<blockquote><tt><a href="$_[0]">$_[0]</a></tt></blockquote>
<p>
<hr>
<a href="http://www.cyberarmy.com"><i>Cyber Anonymizer</i></a>
<p>
</body>
</html>
EOF

    exit ;
}


# Return "403 Forbidden" message, with explanatory text
sub nontextdie {
    print <<EOF ;
HTTP/1.0 403 Forbidden
Content-type: text/html

<html>
<head><title>Cyber Anonymizer will not download</title></head>
<body>
<h1>Cyber Anonymizer will not download files</h1>
<p>Due to abuse, the Cyber Anonymizer will not download files because of bandwidth considerations. In particular, compressed files, some large graphics files, MP3 files, or ram files. For best results, turn off automatic image 
loading if your browser lets you.
<p>If you need access to images or other binary data, route your browser 
through a different proxy.
<p>
<hr>
<a href="http://www.cyberarmy.com"><i>Cyber Anonymizer</i></a>
<p>
</body>
</html>
EOF

    exit ;
}


# Die, outputting HTML error page
sub HTMLdie {
    local($msg)= @_ ;
    print <<EOF ;
HTTP/1.0 200 OK
Content-Type: text/html

<html>
<head><title>CGI Proxy Error</title></head>
<body>
<h1>CGI Proxy Error</h1>
<h3>$msg</h3>
<p>
<hr>
<a href="http://www.cyberarmy.com"><i>Cyber Anonymizer</i></a>
<p>
</body>
</html>
EOF

    exit ;
}
