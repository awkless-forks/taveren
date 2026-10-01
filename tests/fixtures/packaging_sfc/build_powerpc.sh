#!/bin/bash
# Build script for PowerPC cross-compilation

set -e

echo "Building PLC for PowerPC architecture..."

# Check for cross-compiler
if ! command -v powerpc-linux-gnu-gcc &> /dev/null; then
    echo "Error: powerpc-linux-gnu-gcc not found"
    echo "Install with: sudo apt-get install gcc-powerpc-linux-gnu"
    exit 1
fi

# Set compiler
CROSS_COMPILE="powerpc-linux-gnu-"
CC="${CROSS_COMPILE}gcc"
CFLAGS="-g -no-pie -fcf-protection=none -O0 -fPIC -shared -include POUS.h -DTARGET_DEBUG_AND_RETAIN_DISABLE"

echo "Using compiler: $CC"
$CC --version | head -1

# Check for MATIEC library headers
MATIEC_PATH=""
if [ -d "/snap/beremiz/current/matiec/lib/C" ]; then
    MATIEC_PATH="/snap/beremiz/current/matiec/lib/C"
    echo "Found MATIEC library at: $MATIEC_PATH"
elif [ -d "/snap/beremiz/6/matiec/lib/C" ]; then
    MATIEC_PATH="/snap/beremiz/6/matiec/lib/C"
    echo "Found MATIEC library at: $MATIEC_PATH"
else
    echo "Error: MATIEC library headers not found!"
    echo "Please install Beremiz with: sudo snap install beremiz"
    exit 1
fi

# Build
cd build
$CC $CFLAGS \
    -I../runtime \
    -I$MATIEC_PATH \
    -o packaging_sfc_powerpc.so \
    Config0.c Res0.c plc_main.c plc_debugger.c py_ext.c

echo ""
echo "Build complete!"
file packaging_sfc_powerpc.so
cd ..

