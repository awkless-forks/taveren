#!/usr/bin/env bash

mkdir -p ~/angr-taveren
cd ~/angr-taveren

git clone https://github.com/angr/archinfo.git
git clone --recursive https://github.com/angr/pyvex.git
git clone https://github.com/angr/cle.git
git clone https://github.com/angr/claripy.git
git clone https://github.com/angr/angr.git
git clone https://github.com/angr/angr-management.git


cd archinfo
git checkout 8039d553517342c2619a4776e7fa74f8d0f23efe
cd ../pyvex
git checkout e02f43bd7f2a421cdb3fec64d9b38b0eecd38f94
cd ../cle
git checkout a07cf1f1c12f466227bde9d19562457edd33eb83
cd ../claripy
git remote add bonnie https://github.com/Bonnie1256/claripy
git fetch bonnie taveren
git checkout bonnie/taveren
cd ../angr
git remote add bonnie https://github.com/Bonnie1256/angr
git fetch bonnie taveren
git checkout bonnie/taveren
cd ../angr-management
git checkout 7f4c5cb36f63547ff85f0ccbde018b4800f74ba4
cd ..

python -m pip install -U pip wheel setuptools setuptools-rust cffi "unicorn==2.0.1.post1" nanobind scikit_build_core

pip install ${PIP_OPTIONS-} -e ./archinfo --config-settings editable_mode=strict
pip install ${PIP_OPTIONS-} -e ./pyvex
pip install ${PIP_OPTIONS-} -e ./cle --config-settings editable_mode=strict
pip install ${PIP_OPTIONS-} -e ./claripy --config-settings editable_mode=strict
pip install ${PIP_OPTIONS-} --no-build-isolation -e ./angr --config-settings editable_mode=compat
pip install ${PIP_OPTIONS-} -e ./angr-management --config-settings editable_mode=strict
