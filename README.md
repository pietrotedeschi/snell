# SNELL: Selective Authenticated Pilot Location Disclosure for Remote ID-enabled Drones

### Introduction

Remote Identification (RID) regulations recently emitted throughout the world are forcing commercial drones to broadcast wirelessly the location of the pilot in clear-text. However, in many use-cases, the plain-text availability of such information leads to privacy issues, allowing the extraction of sensitive information about the pilot, as well as confidential details about the business the drone is used for. In this paper, we propose SNELL, a RID-compliant solution for selective authenticated operator location disclosure. Through SNELL, a drone can disclose encrypted information about the operator location. At the same time, thanks to the smart integration of Ciphertext-Policy Attribute-Based Encryption (CP-ABE) techniques, the information about the pilot location can be decrypted only by receivers with a set of attributes satisfying an access control policy chosen by the drone at run-time. Thanks to an extensive experimental assessment carried out on a real drone (Holybro X500), we demonstrated that SNELL can fulfill all the requirements imposed by RID in terms of messages generation time and size, while also requiring negligible energy toll on RID-compliant drones.

The contribution is submitted to The Annual Computer Security Applications Conference (ACSAC) 2023.

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

In order to test the security properties, download the file ```test.pv``` from the ```proverif``` folder and run: ```./proverif snell.pv | grep "RESULT"```.

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
