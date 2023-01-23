#!/usr/local/bin/perl
#
# The Cyber Anonymizer 1998 (www.cyberarmy.com).
#
# Based on "CGI-Proxy" by James Marshall (who did 90% of the script).
# This script sets up an anonymous web surfing gateway on the net.
# You need cgi access, and the two cgi script should be chmod
# to 755 through Cute-FTP or whatever FTP program you use.
#
# This script is Open Source and Public Domain. Please reference
# cyberarmy.com if using the script.
#

# If you change the name of the main proxy script, reflect it here.
$proxyname= 'nph-cyberanon.cgi' ;


# Read the URL from the query input
($ENV{'QUERY_STRING'}=~ /^URL=([^&]*)/)  || &showstartform ;
$URL= $1 ;

# un-encode the URL
$URL=~ s/\+/ /g ;
$URL=~ s/%([\da-fA-F]{2})/pack("c", hex($1))/ge ;

# Warn the user against FTP or other URL's
($scheme)= $URL=~ /^(.[\w+.-]*):/ ;
(($scheme eq '') || ($scheme=~ /^http$/i))
    || &HTMLdie("Sorry, only HTTP browsing is currently supported.") ;

# Support abbreviated URL entries (but only HTTP)
$URL=~ s#^http:##i ;
$URL=~ s#^//##i ;
($host, $port, $path)= ($URL=~ m#([^/:]*)(:?[^/]*)(/.*)?$#) ;
$host= "www.$host.com" unless $host=~ /\./ ;
$path || ($path= "/") ;
$URL= "http://$host$port$path" ;

# Print the Location: header
print "Location: $proxyname/$URL\n\n" ;

exit ;


# Present entry form
sub showstartform {
    print <<EOF ;
Content-type: text/html

<html>
<head>
<title>Start Using CGI Proxy</title>
</head>
<body>

<h1>CGI Proxy</h1>

<p>Start browsing through this CGI-based HTTP proxy by entering a URL
below.  Not all functions will work (e.g. cookies), but most pages will
be fine.

<form action="$ENV{'SCRIPT_NAME'}" method=get>
<input name="URL" size=50>
<p><input type=submit value="   Begin browsing   ">
</form>
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
Content-type: text/html

<html>
<head>
<title>CGI Proxy Error</title>
</head>
<body>
<h1>CGI
 Proxy Error</h1>
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
