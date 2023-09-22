## Baldovin Razvan-Mihai-Marian 312CA

# Overview

The program does a quick simple check on links and traffic in an attempt to
determine with an accuracy as high as possible, which are malicious and which
are benign.

================================================================================

# Files

The program is split in 4 .c files with a .h header file for each .c apart from
'my_av.c' which contains the main function. It also uses some bonus resources to
aid in finding malicious links.

Source files are named accordingly to represent exactly what their job is:
    - 'my_av.c' - calls the functions to check links and traffic (the antivirus)
    - 'url_check.c' - all the functions for checking if an URL is legit
    - 'traffic_check.c' - all the function for checking if traffic is legit
    - 'file_manager.c' - handles opening and reading files

In resources we have the following files:
    - 'tld_list.txt' - a comprehensive list of all legitimate top-level domains

================================================================================

# Heuristics

## URLs

### Dictionary (check_dictionary)

We check if the domain is from a dictionary of known malware links

### Extension (check_extension)

We check if the link opens a file whose extension is commonly malicious in links

### Number proportion in domain (check_number_proportion)

If the domain is made-up of more than 10% digits, the link is very likely to be
malicious

### subdomain (check_subdomain)

Some links may contain a suspicious subdomains (instead of 'www', something like
'www-i2')

### TLDs (check_tld)

Malware links might sometime contain a non-registered top-level domain or a
suspicious top-level domain, therefore we check if it is a legitimate TLD

### Suspicious keyword

Checks if the links contain words commonly associated with malicious links

## Traffic

### Response ip

If the adress is masked (255.255.255.255) it is generally safe

### Traffic flow & flow packets average

Usually traffic flow over 1 second combined with a high flow packets average it 
is most likely to be a brute force attack

### Flow flags

If all flags are 0, that is most of the time a sign of crypto-mining traffic