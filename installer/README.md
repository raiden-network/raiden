# Raiden Installer
an user friendly installer for Raiden-Network on Linux powered by DeepIT

## Prerequisites

  * [Infura](https://www.google.com) api key
  * [Ethereum](https://github.com/ethereum/go-ethereum/wiki/geth) json address (for Ropsten)

## Installing

* Download the latest of this project release [here](https://github.com/Giulio2002/Raiden-Installer/releases).
* extract the files and then you double click on the AppImage executable
* press the Install button
* insert your json and your infura api key into the form
* You are ready to go

## Development

### Build from source
``` sh
  npm run build
  cp -a version raiden-cli -b dist/ # The executeble is in the dist folder
```
### Development
to start the project in development mod you just need to digit
``` sh
  npm start # this will run the installer in development mod
```
## Authors

* **Giulio Rebuffo** - *The creator* -

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
