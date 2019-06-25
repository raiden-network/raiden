<!-- PROJECT SHIELDS -->

<h2 align="center">
  <br/>
  <a href='https://raiden.network/'><img 
      width='400px' 
      alt='' 
      src="https://user-images.githubusercontent.com/35398162/54018436-ee3f6300-4188-11e9-9b4e-0666c44cda53.png" /></a>
  <br/>
  Raiden
  <br/>
</h2>

<h4 align="center">
  Fast, cheap, scalable token transfers for Ethereum
</h4>

<p align="center">
  <a href="#getting-started">Getting Started</a> ∙
  <a href="#repositories">Repositories</a> ∙
  <a href='#contact'>Contact</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/raiden/">
    <img src="https://img.shields.io/pypi/pyversions/raiden.svg">
  </a>
  <a href="https://gitter.im/raiden-network/raiden">
    <img src="https://badges.gitter.im/gitterHQ/gitter.png" alt="Gitter Raiden Badge">
  </a>
</p>


The Raiden Network is an off-chain scaling solution, enabling near-instant, low-fee and scalable payments. It’s complementary to the Ethereum blockchain and works with any ERC20 compatible token. The Raiden project is work in progress. Its goal is to research state channel technology, define protocols and develop reference implementations.

>**INFO:** The Raiden client and smart contracts have been [released for mainnet](https://medium.com/raiden-network/red-eyes-mainnet-release-announcement-d48235bbef3c) with a limited alpha release of the Raiden Network in December 2018.

The Raiden Network is an infrastructure layer on top of the Ethereum blockchain. While the basic idea is simple, the underlying protocol is quite complex and the implementation non-trivial. Nonetheless the technicalities can be abstracted away, such that developers can interface with a rather simple API to build scalable decentralized applications based on the Raiden Network.

<p align="left">
  <a href="https://youtu.be/R1tIy1XgdPw" target="_blank">
    <img
      width="824px"
      alt="Raiden in a Nutshell"
      src="https://user-images.githubusercontent.com/35398162/59496225-46c18300-8e91-11e9-9253-1465f5fd5985.PNG"
    />
  </a>
</p>

## Table of Contents
- [Getting Started](#getting-started)
  * [Learn about Raiden](#learn-about-raiden)
- [Specification](#specification)
- [Repositories](#repositories)
  * [Core](#core)
  * [Tools](#tools)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Getting Started

### Learn about Raiden

If you didn't use Raiden before, you can

* Checkout the [developer portal](http://developer.raiden.network)
* Look at the [documentation](https://raiden-network.readthedocs.io/en/stable/index.html)
* Learn more by watching explanatory [videos](https://www.youtube.com/channel/UCoUP_hnjUddEvbxmtNCcApg)
* Read the blog posts on [Medium](https://medium.com/@raiden_network)

### Use Raiden

If you want to use Raiden:
* [Install and fire up](https://raiden-network.readthedocs.io/en/stable/overview_and_guide.html) a Raiden client.
* Check out the [WebUI tutorial](https://raiden-network.readthedocs.io/en/stable/webui_tutorial.html) to quickly get started doing payments.
* Read the thorough guide to [get started with the Raiden API](https://raiden-network.readthedocs.io/en/stable/api_walkthrough.html).

## Specification
Read the [tentative specification for the Raiden Network](https://raiden-network-specification.readthedocs.io/en/latest/index.html) to understand in detail how Raiden works. It is maintained within [this repository](https://github.com/raiden-network/spec).

## Repositories
The Raiden Network is getting created with a set of tools, which are maintained in different repositories.
### Core
- The [solidity smart contracts, librairies and deployment tools](https://github.com/raiden-network/raiden-contracts) are used to bootstrap a Raiden Network on an Ethereum Chain.

- The Raiden Python client within the current repository is used to manage payment channels and to make token transfers.

- A [configured matrix server](https://github.com/raiden-network/raiden-transport) joins a federation of Matrix servers which is used as the transport layer for the Raiden Network. 

- The [Service repository](https://github.com/raiden-network/raiden-services) contains the code for following services:
    - The Monitoring Service watches open payment channels when the user is not online. 
    - The Pathfinding service supports users in finding the cheapest or shortest way to route a payment through the network.
    
- The [Light Client repository](https://github.com/raiden-network/light-client) contains the code for following applications:
    - The Raiden Light Client SDK is a Raiden Network compatible client written in JavaScript/Typescript.
    - The Raiden dApp is a reference implementation of the Raiden Light Client SDK.

### Tools
- The [Raiden WebUI](https://github.com/raiden-network/webui) is Raiden Web User Inteface to manage channels and make token transfers.

- The [Raiden Explorer](https://github.com/raiden-network/explorer) visualizes the nodes of the Raiden Networks and shows more statistical information.

- The [One-Click-Installer](https://github.com/raiden-network/raiden-installer) makes it easy to install a Raiden client and join the Raiden Network.

- The [Scenario Player](https://github.com/raiden-network/scenario-player) is an integration testing tool for the Raiden contracts, the Raiden client and the services.

- The [Workshop Scripts](https://github.com/raiden-network/workshop) enable workshop fascilitators to easily host a Raiden Workshop.

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

Also have a look at the [Raiden Development Guide](./CONTRIBUTING.md) and the [Raiden Developer Onboarding Guide](https://raiden-network.readthedocs.io/en/stable/onboarding.html) for more info.

## License

Distributed under the [MIT License](./LICENSE).

## Contact

Dev Chat: [Gitter](https://gitter.im/raiden-network/raiden)

Twitter: [@raiden_network](https://twitter.com/raiden_network)

Website: [Raiden Network](https://raiden.network/)

Blog: [Medium](https://medium.com/@raiden_network)

Mail: contact@raiden.network 

*The Raiden project is led by brainbot labs Est.*

> Disclaimer: Please note, that even though we do our best to ensure the quality and accuracy of the information provided, this publication may contain views and opinions, errors and omissions for which the content creator(s) and any represented organization cannot be held liable. The wording and concepts regarding financial terminology (e.g. “payments”, “checks”, “currency”, “transfer” [of value]) are exclusively used in an exemplary way to describe technological principles and do not necessarily conform to the real world or legal equivalents of these terms and concepts.
