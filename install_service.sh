#!/usr/bin/env bash

# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Generate name for unique systemd unit
$unit = dhcpmon_$(hostname)_$(</etc/machine-id).service

# Copy our service definition to new file with cwd substituted
sed -e “s|SCRIPTDIR|$(pwd)|g dhcpmon.service > $unit

# Symlink unit definition to system unit repo
ln -s $(pwd)/$unit /etc/systemd/system/dhcpmon.service

# Rescan systemd units
systemctl daemon-reload

# Start an enable (symlink) service
#systemctl enable dhcpmon.service --now
