#!/usr/bin/env bash

# Export the Environment Variables to ~/bashrc and source them
cat env_vars.txt > ~/.bashrc
source ~/.bashrc

#Create a local ENV file and export the vars there
touch .env
cat env_vars.txt > ~/.bashrc