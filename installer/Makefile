start:
	gcc launcher/launcher.c -o Raiden -no-pie
	npm start

build:
	npm run dist
	gcc launcher/launcher.c -o dist/Raiden -no-pie
	rm -rf dist/linux-unpacked dist/electron-builder.yaml dist/latest-linux.yml
	cp -a version raiden-cli dist/

clean:
	rm dist -rf