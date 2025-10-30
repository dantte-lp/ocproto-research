# Reverse Engineering Tools Container
# Includes: Ghidra, Reko, angr, radare2, Binary Ninja Community, and utilities
# Based on Oracle Linux 10

FROM oraclelinux:10

LABEL maintainer="ocserv-modern team"
LABEL description="Comprehensive reverse engineering environment for Cisco Secure Client analysis"
LABEL version="1.0"

# Install system dependencies
RUN dnf install -y \
    # Java for Ghidra
    java-21-openjdk-devel \
    java-21-openjdk-headless \
    # Python for angr and scripting
    python3.12 \
    python3.12-pip \
    python3.12-devel \
    # .NET/Mono for Reko
    mono-complete \
    # Build tools
    gcc \
    gcc-c++ \
    make \
    cmake \
    git \
    wget \
    curl \
    unzip \
    tar \
    # Binary analysis tools
    binutils \
    file \
    strace \
    ltrace \
    gdb \
    valgrind \
    # Network tools
    nmap \
    tcpdump \
    wireshark-cli \
    # Text processing
    vim \
    nano \
    less \
    grep \
    sed \
    awk \
    jq \
    # Other utilities
    tree \
    findutils \
    which \
    procps-ng \
    && dnf clean all

# Create workspace
WORKDIR /workspace
RUN mkdir -p /tools /analysis /binaries /output

# Install Ghidra 11.3
ENV GHIDRA_VERSION=11.3_PUBLIC_20250115
RUN cd /tools && \
    wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3_build/ghidra_${GHIDRA_VERSION}.zip && \
    unzip -q ghidra_${GHIDRA_VERSION}.zip && \
    rm ghidra_${GHIDRA_VERSION}.zip && \
    ln -s /tools/ghidra_${GHIDRA_VERSION} /tools/ghidra

# Add Ghidra to PATH
ENV PATH="/tools/ghidra:${PATH}"
ENV GHIDRA_INSTALL_DIR="/tools/ghidra"

# Install Reko Decompiler 0.12.0
RUN cd /tools && \
    wget -q https://github.com/uxmal/reko/releases/download/version-0.12.0/Reko-0.12.0.zip && \
    unzip -q Reko-0.12.0.zip -d reko && \
    rm Reko-0.12.0.zip && \
    chmod +x /tools/reko/Reko.exe

# Create Reko wrapper script
RUN echo '#!/bin/bash\nmono /tools/reko/Reko.exe "$@"' > /usr/local/bin/reko && \
    chmod +x /usr/local/bin/reko

# Install angr (symbolic execution framework)
RUN python3.12 -m pip install --no-cache-dir \
    angr==9.2.142 \
    angr-management \
    capstone \
    keystone-engine \
    unicorn \
    pwntools \
    ropper \
    z3-solver \
    cle \
    archinfo \
    pyvex

# Install radare2 (optional but useful)
RUN cd /tmp && \
    git clone --depth 1 https://github.com/radareorg/radare2 && \
    cd radare2 && \
    sys/install.sh && \
    cd / && rm -rf /tmp/radare2

# Install additional Python tools for analysis
RUN python3.12 -m pip install --no-cache-dir \
    lief \
    pyelftools \
    pefile \
    intervaltree \
    networkx \
    matplotlib \
    pandas \
    numpy

# Install Binary Ninja (community/demo version) - optional
# Note: Commercial license required for full features
# RUN cd /tools && \
#     wget https://cdn.binary.ninja/installers/binaryninja_free_linux.zip && \
#     unzip binaryninja_free_linux.zip && \
#     rm binaryninja_free_linux.zip

# Create analysis scripts directory
RUN mkdir -p /workspace/scripts

# Copy analysis scripts (to be mounted or added)
# COPY scripts/ /workspace/scripts/

# Set up environment variables
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV PYTHONPATH=/usr/local/lib/python3.12/site-packages
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Create user for analysis (non-root)
RUN useradd -m -s /bin/bash analyst && \
    chown -R analyst:analyst /workspace /analysis /output

# Switch to analyst user
USER analyst
WORKDIR /workspace

# Default command: interactive shell
CMD ["/bin/bash"]

# Usage:
# Build: podman build -t reverse-engineering-tools:latest .
# Run: podman run -it -v /opt/projects/repositories/cisco-secure-client:/binaries:ro -v /opt/analysis:/analysis reverse-engineering-tools:latest
