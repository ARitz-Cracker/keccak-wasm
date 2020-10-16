#!/bin/bash
if [ "$NODE_ENV" == "production" ]; then
	rm -rf src;
	rm -rf test;
	rm .eslintignore 2> /dev/null;
	rm .eslintrc.json 2> /dev/null;
	rm .gitignore 2> /dev/null;
	rm .npmignore 2> /dev/null;
	rm lisence.txt;
	rm readme.md;
fi;
