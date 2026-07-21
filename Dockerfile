FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git bash jq tar gzip python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir rich pyyaml

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Syft (SBOM)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Install KICS
RUN KICS_VERSION=$(curl -s https://api.github.com/repos/Checkmarx/kics/releases/latest \
    | jq -r '.tag_name') && \
    curl -sL "https://github.com/Checkmarx/kics/releases/download/${KICS_VERSION}/kics_${KICS_VERSION}_Linux_x64.tar.gz" \
    -o /tmp/kics.tar.gz && \
    mkdir -p /opt/kics && \
    tar -xzf /tmp/kics.tar.gz -C /opt/kics && \
    ln -s /opt/kics/kics /usr/local/bin/kics && \
    rm /tmp/kics.tar.gz

COPY swis.py /usr/local/bin/swis.py
RUN chmod +x /usr/local/bin/swis.py

ENTRYPOINT ["python3", "/usr/local/bin/swis.py"]
