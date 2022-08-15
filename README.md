# Learing-Portfolio
In this thesis, we propose a self-sovereign identity based personal information security control infrastructure for the e-portfolio ecosystem. The decentralized identity chain and e- portfolio application chain are included in this system. The decentralized identity chain integrates the identities of users in different ecosystems and gives users a self-sovereign identity that can be fully controlled by themselves. The e-portfolio application chain records the authorization of the user. Besides, the trusted education unit audits the source of the review data together.

DID-chain provide users with a self-sovereign identity. Users can fully control their own identity no longer rely on centralized services. 
* login with digital signature 
* Integrate the identities of user in different ecosystem
* Auditable and traceable identity

E-portfolio app-chain provides users to authorize and share their own data for review, and trusted educational organizations audit the application of activity vendors to ensure the data source.


As shown in the following figure, the role relationship in e-portfolio ecosystem.  
<p align="center">
    <img src="public/images/overview.png" alt="system_architecture" width="80%"/>
</p>

### Built With
* [Node v14.15.1](https://nodejs.org/en/)
* [Docker](https://www.docker.com/)

## Getting Started
Before getting started, you should build the [ethereum environment](https://github.com/trufflesuite/ganache) (e.g., ganache) and setup the [hyperledger fabric environment](https://github.com/hyperledger-labs/fablo).

### Ethereum network
(optional) Here is an example of using docker to create a ethereum test network.
```sh
    docker run --detach --publish 8545:8545 trufflesuite/ganache-cli:latest --seed 0 --gasPrice 0
```
Deploy ethereun smart contract

(optional) If you don't have `truffle` toolkit, you also can compile your contract code by online IDE, e.g., [Remix](https://remix.ethereum.org/).

### Fabric network
* Fablo setup
Put [fablo-config.json](https://github.com/junyuwow/Learing-Portfolio/blob/main/config/fablo-config.json) and [chaincode](https://github.com/junyuwow/Learing-Portfolio/tree/main/contracts/chaincodes) to your fablo repository.
#### fablo folder structure
    .
    ├─ fablo repository
       ├── fablo-config.json
       ├── chaincodes                    
       │   ├── chaincode-accessControlManager-node   
       │   ├── chaincode-certManager-node                 
       │   │   └── index.js
       |   |   └── package.json
       │   │    
       |   └── chaincode-issueAward-node
       ├── fablo-target
       └── fablo
       
run test-network
```sh
    ./fablo up
```

### Installation
1. Clone the repo
    ```sh 
    git clone https://github.com/junyuwow/Learing-Portfolio.git
    ```
2. Install NPM packages
    ```sh
    npm install
    ```
3. Copy connection-profiles to config dir
4. Launch Dapp.
    ```sh
    npm start
    ```
