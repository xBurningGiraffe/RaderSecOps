#!/bin/bash

# Prompt user to select an interface
read -p "Enter the destination interface (e.g. 0/48): " destination

# Set destination interface description
echo "configure
interface $destination
description 'Perch Port Mirror Destination'
exit" | sudo tee /dev/null

# Configure monitor session for all interfaces except the destination
for i in {2..47}
do
  if [ "$i" != "${destination#*/}" ]; then
    echo "monitor session 1 source interface 0/$i" | sudo tee -a /dev/null
  fi
done

# Set destination interface as monitor session destination
echo "monitor session 1 destination interface $destination" | sudo tee -a /dev/null

# Save configuration
echo "exit
write memory confirm" | sudo tee -a /dev/null
