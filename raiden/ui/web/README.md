# Helper guide to install and test the Raiden UI

* Once you come in the `raiden/ui/web/` folder please run

> **npm install**.

This will install all the dependencies needed by Angular to run the project.

* We make Cross domain requests to many servers including the Geth Server and Raiden API server we need to proxy our requests hence run the server in this way.

> **ng serve --proxy-config proxy.config.json --base-href /ui/ --deploy-url /ui/ --delete-output-path false**

You can read more about this [here](https://github.com/angular/angular-cli/blob/master/docs/documentation/stories/proxy.md)

* If the `@angular/cli`'s `ng` command isn't available globally, you can find locally installed one at:

> **./node_modules/.bin/ng**

* You can also run *serve* command with

> **npm start**

* You can build production-ready UI files with

**npm run build:prod**

It'll lay in the `dist` subfolder, and can be served directly by flask API.

* Inside the folder src/assets/config we have a config.development.json. This file contains configuration details about host port etc for the raiden as well as geth because we query both the api servers simultaneously. We need to change this file so that it can pick up details according our local configuration.
```
{
  "raiden":
  {
    "host": "localhost",
    "port": 5001,
    "version": 1
  },
  "web3":
  {
    "host": "localhost",
    "port": 8545
  }
}
```

* If we run geth and raiden locally these are additional configurations that we need to do on our local machine.

	1. Generate a genesis JSON file containing all the contracts, configurations.
	> **python tools/config_builder.py full_genesis > mycustomgenesis.json**

	2. Initialise the Geth with the genesis file along with the data directory  
	> **geth --datadir /home/user/privategeth init mycustomgenesis.json**

	3. Start geth with this command
	> geth --rpccorsdomain "*" --datadir /home/krishna/privategeth --networkid 123 --nodiscover --maxpeers 0 --rpc --mine 1

	4. Start Raiden with the registry-contract-address and the discovery-contract-address generated in the last lines in the **mycustomgenesis.json**
file.
	```
    raiden --eth-rpc-endpoint 127.0.0.1:8545 --registry-contract-address 7d73424a8256c0b2ba245e5d5a3de8820e45f390 --discovery-contract-address 08425d9df219f93d5763c3e85204cb5b4ce33aaa --keystore-path ~/privategeth/keystore --console
    ```

 Attach an ipc connection with geth
 ```
 geth attach ipc:/home/krishna/privategeth/geth.ipc
 ```

 From the IPC console quickly check the ether and transfer Ether for a user.
 ```
 web3.fromWei(eth.getBalance(eth.accounts[0]), 'ether')

 eth.sendTransaction({from:eth.coinbase, to:eth.accounts[1], value: web3.toWei(10, "ether")})

```

# Raidenwebui

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 1.6.5.

## Development server

Run `ng serve` for a dev server. Navigate to `http://localhost:4200/`. The app will automatically reload if you change any of the source files.

## Code scaffolding

Run `ng generate component component-name` to generate a new component. You can also use `ng generate directive|pipe|service|class|guard|interface|enum|module`.

## Build

Run `ng build` to build the project. The build artifacts will be stored in the `dist/` directory. Use the `-prod` flag for a production build.

## Running unit tests

Run `ng test` to execute the unit tests via [Karma](https://karma-runner.github.io).

## Running end-to-end tests

Run `ng e2e` to execute the end-to-end tests via [Protractor](http://www.protractortest.org/).

## Further help

To get more help on the Angular CLI use `ng help` or go check out the [Angular CLI README](https://github.com/angular/angular-cli/blob/master/README.md).
