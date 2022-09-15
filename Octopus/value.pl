use LWP::Simple;
use URI;

print "[+] Enter Target URL : " ;
#my $url   = <STDIN>;
foreach my $url ( <STDIN> ) {
    chomp( $url );
my $u1 = URI->new($url);
print "[+] scheme    : ", $u1->scheme, "\n"; 
print "[+] authority : ", $u1->authority, "\n"; 
print "[+] path      : ", $u1->path, "\n";
print "[+] fragment  : ", $u1->fragment, "\n";
print "[+] segments  : ", $u1->path_segments, "\n";
print "[+] query     : ", $u1->query, "\n";
print "[+] keywords  : ", $u1->query_keywords, "\n";
}
