#!/bin/bash
# UCarp 1.6.0 Build Script

# Change to the UCarp directory
cd /home/miha/Github/UCarp

# Generate the build system
echo "Generating build system..."
autoreconf -fiv

# Configure the project
echo "Configuring..."
./configure

# Build the project
echo "Building..."
make

echo "Build complete! UCarp executable is at src/ucarp"
echo "To test: src/ucarp --help"
