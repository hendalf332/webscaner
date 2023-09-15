# webscaner
urls and websites scaner 
scaner.py - can scan website based on default dictionaries in userdict folder or dictionaries specified by -d 
            -s you can scan directories on that website with combination with -r recursive scaning of directories
            you can also add field to headers add cookies use basic authentification by -u 
            you can exclude specific codes from search -N , exclude titles from search --not
            you can set delay between scaning requests in miliseconds -z
            you can set number of processes -n so my scaner utilize multiprocessing for faster scaning 
scanurls.py - url scaning tool which generates possible urls by template find wildcards in them ?,*,(alt1|alt2|alt3)
            and check their avaliability and scrap title if possible it support the same options as the scaner.py 
            but doesn't support default dictionary so you have to specify your list of dictionaries manualy -d option
            separated by comas you can use either a local file or a weblinkurl.
            Three modes of scaning possible mask scaning without -s and -r options and directory scaning with -s or 
            recursive directory scaning -s -r options. In mask scaning you use wildcards like 
            ? -replaced by any character allowed in domain names, *,character ranges [a-z],
            $ - will be replaces by word from the dictionary 
