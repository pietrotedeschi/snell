# SNELL: Selective Authenticated Pilot Location Disclosure for Remote ID-enabled Drones

### Introduction

Remote Identification (RID) regulations recently emitted throughout the world are forcing commercial drones to broadcast wirelessly the location of the pilot in clear-text. However, in many use-cases, the plain-text availability of such information leads to privacy issues, allowing the extraction of sensitive information about the pilot, as well as confidential details about the business the drone is used for. In this paper, we propose SNELL, a RID-compliant solution for selective authenticated operator location disclosure. Through SNELL, a drone can disclose encrypted information about the operator location. At the same time, thanks to the smart integration of Ciphertext-Policy Attribute-Based Encryption (CP-ABE) techniques, the information about the pilot location can be decrypted only by receivers with a set of attributes satisfying an access control policy chosen by the drone at run-time. Thanks to an extensive experimental assessment carried out on a real drone (Holybro X500), we demonstrated that SNELL can fulfill all the requirements imposed by RID in terms of messages generation time and size, while also requiring negligible energy toll on RID-compliant drones.

_The contribution was accepted at 24th Privacy Enhancing Technologies Symposium (PETS 2024)._

### Prerequisites

_Hardware Requirements_

- A programmable drone with a GNU/Linux embedded operating system, or a Raspberry Pi 4
- AWUS036ACH - USB Type-C dual-band AC1200 WiFi adapter (1 for the Generic Receiver, 1 for the Transmitter, 1 for the Authority) if you want broadcast the messages

_Software Requirements_

- A laptop with a distro GNU/Linux (e.g. [Ubuntu](https://ubuntu.com/))
- [Wireshark](https://www.wireshark.org/)
- [scapy](https://www.wireshark.org/](https://scapy.net/))
- [VSC](https://code.visualstudio.com/)
- [Charm-Crypto 0.50](https://jhuisi.github.io/charm/)
- [PBC Cryptography Library](https://crypto.stanford.edu/pbc/times.html)
- [Python3.7](https://www.python.org/)

### How to Compile and Run

### Python3 Requirements
The ```requirements.txt``` lists all Python3 libraries that you should install to run this project:

```
pip3 install -r requirements.txt
```

To execute ```SNELL```, you should download the script ```remote_abe.py``` from the ```proof-of-concept``` folder, and use the following syntax:

```
python3 remote_abe.py
```

In the code, you can specify the Elliptic Curve for the Scnorr Signatures, i.e., _secp256k1_, _secp384r1_ and _secp521r1_.

Further, in order to run the code, please verify that you wireless network card interface is in monitor mode and supports the packet injection.

```sudo python3 remote_abe.py [WIFI_INTERFACE_IN_MONITOR_MODE]```

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/snell`)
3. Commit your Changes (`git commit -m 'Add some features'`)
4. Push to the Branch (`git push origin feature/snell`)
5. Open a Pull Request

### Formal Security Verification with ProVerif
The security properties of ```SNELL``` have been verified formally and experimentally by using the open-source tool ProVerif 2.04pl1, demonstrating enhanced security protection with respect to state-of-the-art approaches.

In order to test the security properties, download the file ```test.pv``` from the ```proverif``` folder and run: ```./proverif test.pv | grep "RESULT"```.

![proverif_result](img/snell.png?raw=true "ProVerif")


<!-- LICENSE -->
## License

Distributed under the GNU General Public License v3.0 License. See  [LICENSE](./LICENSE) for more information.


<!-- CONTACT -->
## Contact

Anonymous Authors

<!-- DISCLAIMER -->
## Disclaimer

Any actions and or activities related to the material contained within this github repository is solely your responsibility. The misuse of the information in this repository can result in criminal charges brought against the persons in question. The author(s) will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this repository to break the law.
