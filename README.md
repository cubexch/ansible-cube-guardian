## 1. Ansible Collection - cubexch.guardian

- [1. Ansible Collection - cubexch.guardian](#1-ansible-collection---cubexchguardian)
- [2. Requirements](#2-requirements)
  - [2.1. Guardian Server](#21-guardian-server)
  - [2.2. Hashicorp Vault Cluster](#22-hashicorp-vault-cluster)
  - [2.3. Public Guardian List Approval](#23-public-guardian-list-approval)
- [3. Conventions](#3-conventions)
- [4. Ansible Configuration](#4-ansible-configuration)
  - [4.1. Configure your virtual environment.](#41-configure-your-virtual-environment)
  - [4.2. Create the `.ansible-vault.key` file to contain your Ansible Vault password.](#42-create-the-ansible-vaultkey-file-to-contain-your-ansible-vault-password)
  - [4.3. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`](#43-create-ansiblecfg-and-set-the-vault_password_file-to-ansible-vaultkey)
  - [4.4. Install pip \& Ansible Galaxy requirements inside `cube-guardian` virtual environment.](#44-install-pip--ansible-galaxy-requirements-inside-cube-guardian-virtual-environment)
- [5. Setup Hashicorp Vault Cluster](#5-setup-hashicorp-vault-cluster)
  - [5.1. Inventory Setup](#51-inventory-setup)
    - [5.1.1. Create an Ansible inventory for your Hashicorp Vault Cluster](#511-create-an-ansible-inventory-for-your-hashicorp-vault-cluster)
    - [5.1.2. Optional - Set `ansible_user` and `ansible_ssh_private_key_file` in `group_vars` under the `all` group](#512-optional---set-ansible_user-and-ansible_ssh_private_key_file-in-group_vars-under-the-all-group)
    - [5.1.3. Verify Connectivity to Vault Cluster Nodes](#513-verify-connectivity-to-vault-cluster-nodes)
    - [5.1.4. Create `group_vars` for the `geerlingguy.swap` role under the `all` group](#514-create-group_vars-for-the-geerlingguyswap-role-under-the-all-group)
    - [5.1.5. Create `group_vars` for the `cubexch.guardian.hashicorp_vault_cluster` role under your Vault Cluster group:](#515-create-group_vars-for-the-cubexchguardianhashicorp_vault_cluster-role-under-your-vault-cluster-group)
  - [5.2. Deploy Vault Cluster](#52-deploy-vault-cluster)
    - [5.2.1. Create Ansible Playbook to Deploy Hashicorp Vault Cluster](#521-create-ansible-playbook-to-deploy-hashicorp-vault-cluster)
    - [5.2.2. SENSITIVE: Generate Self-Signed Certs Locally](#522-sensitive-generate-self-signed-certs-locally)
    - [5.2.3. SENSITIVE: Encrypt Private Keys for Self-Signed Certs](#523-sensitive-encrypt-private-keys-for-self-signed-certs)
    - [5.2.4. SENSITIVE: Deploy Hashicorp Vault Cluster](#524-sensitive-deploy-hashicorp-vault-cluster)
    - [5.2.5. SENSITIVE: Encrypt Vault Init Data](#525-sensitive-encrypt-vault-init-data)
- [6. Guardian Configuration](#6-guardian-configuration)
  - [6.1. Create an Ansible inventory for your Guardian node.](#61-create-an-ansible-inventory-for-your-guardian-node)
  - [6.2. Verify Connectivity to Guardian Node with Ansible](#62-verify-connectivity-to-guardian-node-with-ansible)
  - [6.3. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:](#63-optional-create-host_vars-for-the-geerlingguycertbot-role)
  - [6.4. Create `host_vars` for your non-sensitive Guardian Vault Configuration](#64-create-host_vars-for-your-non-sensitive-guardian-vault-configuration)
  - [6.5. SENSITIVE: Create `host_vars` for sensitive Guardian Node Configuration](#65-sensitive-create-host_vars-for-sensitive-guardian-node-configuration)
  - [6.6. SENSITIVE: Encrypt `host_vars` for sensitive Guardian Node Configuration with Ansible Vault](#66-sensitive-encrypt-host_vars-for-sensitive-guardian-node-configuration-with-ansible-vault)
  - [6.7. Create `host_vars` for your non-sensitive Guardian Node Configuration](#67-create-host_vars-for-your-non-sensitive-guardian-node-configuration)
  - [6.8. Create an Ansible playbook to deploy](#68-create-an-ansible-playbook-to-deploy)
  - [6.9. Run the playbook to configure the Guardian Node](#69-run-the-playbook-to-configure-the-guardian-node)
  - [6.10. Verify inbound connectivity to your Guardian Node](#610-verify-inbound-connectivity-to-your-guardian-node)
  - [6.11. Verify your Guardian Certificate has the expected CN](#611-verify-your-guardian-certificate-has-the-expected-cn)
- [7. SENSITIVE: Ensure All Sensitive Information Encrypted with Ansible Vault](#7-sensitive-ensure-all-sensitive-information-encrypted-with-ansible-vault)
- [8. FAQ](#8-faq)
  - [8.1. How can I check the status of the Guardian service?](#81-how-can-i-check-the-status-of-the-guardian-service)
  - [8.2. How can I check the deployed configuration?](#82-how-can-i-check-the-deployed-configuration)
  - [8.3. How can I view the Guardian logs?](#83-how-can-i-view-the-guardian-logs)
  - [8.4. Example Log Messages](#84-example-log-messages)
    - [8.4.1. Successful Guardian Connection to Hashicorp Vault](#841-successful-guardian-connection-to-hashicorp-vault)
    - [8.4.2. Successful Guardian Key Initialization](#842-successful-guardian-key-initialization)
    - [8.4.3. Successful Guardian Peer Connection](#843-successful-guardian-peer-connection)
    - [8.4.4. Successful User Key Generation](#844-successful-user-key-generation)
    - [8.4.5. Failed Peer Connection - Received Invalid TLS Certificate Name](#845-failed-peer-connection---received-invalid-tls-certificate-name)
    - [8.4.6. Other Errors](#846-other-errors)

## 2. Requirements

### 2.1. Guardian Server

- 1x Guardian Server
  - Minimum Recommended Spec:
    - OS: Ubuntu 20.04
    - CPU: 24 core
    - MEM: 64gb
    - DISK: 1TB NVME SSD
    - NET:
      - Guardian `<->` Guardian: 1Gbps internet connectivity
      - Guardian `->` Hashicorp Vault: 1Gbps internal connectivity
    - Public DNS and SSL/TLS certificates (guardian to guardian)

### 2.2. Hashicorp Vault Cluster

- 3x Hashicorp Vault Cluster Nodes
  - Recommend physical servers in accordance with the `Large` cluster specifications if possible, or single tenant virtual machines at a minimum.
  - REF:
    - [Hashicorp Vault - System Requirements](https://developer.hashicorp.com/vault/tutorials/day-one-raft/raft-reference-architecture#system-requirements)
    - [Hashicorp Vault - Production Hardening](https://developer.hashicorp.com/vault/tutorials/day-one-raft/production-hardening)
- The Hashicorp Vault cluster should be initialized in accordance with your standard practices.
- An Authentication token is not required to _**create**_ the Hashicorp Vault configuration files (\*.hcl)
- An Authentication token is required to _**deploy**_ the Hashicorp Vault configurations _**and**_ to retrieve the AppRole ID and SecretID credentials used by the Guardian to authenticate to the Vault cluster.

### 2.3. Public Guardian List Approval

Guardian software will only communicate with instances that have been added to the approved list by Cube Exchange. Cube Exchange will add new Guardians to the public list after they have been reviewed and approved.

View the public list of Guardians at `public_guardian_list` in [roles/guardian/defaults/main.yml](roles/guardian/defaults/main.yml)

## 3. Conventions

- Files containing sensitive variables have a `.ansible_vault.yml` suffix to indicate they contain sensitive variable definitions and should be encrypted with Ansible Vault.

  - You can use the following commands to easily encrypt/decrypt all sensitive files

    ```bash
    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault decrypt $f ;done
    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
    ```

- Variables containing sensitive information have a `_vault` suffix to indicate that they should be encrypted with Ansible Vault

  - This allows you to easily search for where the base variable is used even when the file containing the sensitive variable definition is encrypted.

    ```bash
    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault encrypt $f ;done
    Encryption successful
    Encryption successful

    grep -R guardian_access_token .
    ./inventory/host_vars/example-guard-1/guardian.yml:guardian_access_token: "{{ guardian_access_token_vault }}"

    for f in $(find inventory/ -type f -name "*.ansible_vault.yml") ;do ansible-vault decrypt $f ;done
    Decryption successful
    Decryption successful

    grep -R guardian_access_token .
    ./inventory/host_vars/example-guard-1/guardian.ansible_vault.yml:guardian_access_token_vault: "my_guardian_access_token"
    ./inventory/host_vars/example-guard-1/guardian.yml:guardian_access_token: "{{ guardian_access_token_vault }}"
    ```

## 4. Ansible Configuration

> While any Python 3.8+ version should be sufficient for running this collection with Ansible, only Python 3.8.10 has been verified.
>
> As an option, you can use Python 3.8.10 within a `pyenv` virtual environment. Please refer to the [PyEnv Installation Guide](https://github.com/pyenv/pyenv#installation) for detailed instructions.

### 4.1. Configure your virtual environment.

1.  If you'd like to install `pyenv` on a Ubuntu host

    ```bash
    # Ubuntu pyenv pre-reqs
    sudo apt update
    sudo apt install build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev curl libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

    # Get pyenv with automatic installer
    curl https://pyenv.run | bash

    # Activate pyenv according to installer output
    export PYENV_ROOT="$HOME/.pyenv"
    command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    ```

    Once you have `pyenv` installed and activated, install Python 3.8.10 and create a virtualenv with it

    ```bash
    # Setup pyenv and pyenv virtual environment
    pyenv install 3.8.10
    pyenv virtualenv 3.8.10 cube-guardian
    pyenv activate 3.8.10/envs/cube-guardian
    cd example
    ```

2.  If you'd like to just use a Python Virtual Environment

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    cd example
    ```

### 4.2. Create the `.ansible-vault.key` file to contain your Ansible Vault password.

> Ensure you are in the example folder

`.ansible-vault.key`

```text
my_secret_ansible_vault_password
```

### 4.3. Create `ansible.cfg` and set the `vault_password_file` to `.ansible-vault.key`

`ansible.cfg`

```ini
[defaults]
roles_path = .ansible-galaxy-roles:./roles
collections_paths = .ansible-galaxy-collections
vault_password_file = .ansible-vault.key
inventory = ./inventory/hosts-example.ini

# host_key_checking = False
# host_key_auto_add = False

[ssh_connection]
retries = 3
pipelining = true
```

### 4.4. Install pip & Ansible Galaxy requirements inside `cube-guardian` virtual environment.

```bash
pip install -r requirements.txt
ansible-galaxy install -r requirements.yml --force
```

## 5. Setup Hashicorp Vault Cluster

### 5.1. Inventory Setup

#### 5.1.1. Create an Ansible inventory for your Hashicorp Vault Cluster

`inventory/hosts-example.ini`

```ini
[all]

# Update hostnames and IP addresses
example-vault-1  ansible_host=127.0.0.1
example-vault-2  ansible_host=127.0.0.2
example-vault-3  ansible_host=127.0.0.3

# Update group name
[example_hashicorp_vault_cluster]
example-vault-[1:3]
```

#### 5.1.2. Optional - Set `ansible_user` and `ansible_ssh_private_key_file` in `group_vars` under the `all` group

`inventory/group_vars/all/all.yml`

```yml
ansible_user: ansible
ansible_ssh_private_key_file: ~/.ssh/id_ed25519
```

#### 5.1.3. Verify Connectivity to Vault Cluster Nodes

> Update the group name `example_hashicorp_vault_cluster` to your new group name

```bash
ansible example_hashicorp_vault_cluster -i inventory/hosts-example.ini -m ping --one-line
```

#### 5.1.4. Create `group_vars` for the `geerlingguy.swap` role under the `all` group

> It is strongly recommended to disable swap on both the Guardian _**and**_ all of your Vault Cluster Nodes

`inventory/group_vars/all/geerlingguy.swap.yml`

```yml
swap_file_state: absent
```

#### 5.1.5. Create `group_vars` for the `cubexch.guardian.hashicorp_vault_cluster` role under your Vault Cluster group:

> Update the path to use your new group name

`inventory/group_vars/example_hashicorp_vault_cluster/cubexch.guardian.hashicorp_vault_cluster.yml`

```yml
### Hashicorp Vault Initialization ###

# Local directory where SENSITIVE vault initialization data will be stored (root token and unseal keys)
hashicorp_vault_init_data_local_dir: '{{ inventory_dir }}/hashicorp-vault-init'

# Option to generate self-signed TLS CA & certificates for Vault Cluster Members
self_signed_certs_generate: true

# Required: Local directory where TLS CA & certificates are stored. Used to copy the certificates to the Vault cluster nodes
self_signed_certs_local_dir: '{{ inventory_dir }}/hashicorp-vault-certs'

# Number of shamir secret shares to create (unseal keys)
vault_init_secret_shares: 5

# Threshold of how many shamir secret shares needed to unseal the vault
vault_init_secret_threshold: 3

######################################

### Hashicorp Vault Cluster Config ###

# Inventory Group Name for your Hashicorp Vault Cluster
hashicorp_vault_cluster_group_name: 'example_hashicorp_vault_cluster'

# Vault Cluster FQDN Suffix - Used to copy certificates and create /etc/hosts entries
vault_cluster_fqdn: 'example.hashicorp.vault.cluster.com'

# Optional: Name of your HA Cluster within Hashicorp Vault. Vault will auto-generate a cluster name if not specified.
hashicorp_vault_cluster_name: 'example-guardian-vault-ha-cluster'

### Option to create /etc/hosts entries ###

# Option to create /etc/hosts entries for each cluster member
create_etc_hosts_entries: true

### Required Inventory Variables when creating /etc/hosts entries ###
# Select an interface to get an IP address from when creating /etc/hosts entries
#
## Select the default interface detected by ansible
# hashicorp_vault_interface_api_interface: "{{ ansible_default_ipv4.interface }}"
## Or specify an interface name
# hashicorp_vault_interface_api_interface: 'bond0'
# hashicorp_vault_interface_api_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ hashicorp_vault_interface_api_interface]['ipv4']['address'] }}"

###########################################

# Port used for API communications to the cluster
hashicorp_vault_cluster_port_api: 8200
# Port used for internal cluster node-to-node communication
hashicorp_vault_cluster_port_cluster: 8201

### Optional Firewall Configuration ###

# Optional: Open Firewall Rules with iptables
open_iptables: true

### Required when open_iptables=true
# Vault client-facing network for Vault API communications
# Update with the source network your Guardian node will use to connect to the Vault Cluster
open_iptables_source_network_api_port: '127.0.0.0/24'

# Internal Vault-to-Vault cluster communications
# Update with the Vault cluster's internal network for vault-to-vault communications
open_iptables_source_network_cluster_port: '127.0.0.0/24'
#######################################
```

### 5.2. Deploy Vault Cluster

#### 5.2.1. Create Ansible Playbook to Deploy Hashicorp Vault Cluster

`playbooks/deploy_hashicorp_vault.yml`

```yml
- name: Deploy Hashicorp Vault Cluster
  # Update hosts selector with new inventory group name of Vault Cluster Hosts
  # Ensure group_vars folder matches when changed
  hosts: example_hashicorp_vault_cluster
  gather_facts: false
  become: true
  become_user: root
  roles:
    - geerlingguy.swap
    - cubexch.guardian.hashicorp_vault_cluster
```

#### 5.2.2. SENSITIVE: Generate Self-Signed Certs Locally

The `self_signed_certs_generate` setting in `inventory/group_vars/example_hashicorp_vault_cluster/cubexch.guardian.hashicorp_vault_cluster.yml` controls whether the `hashicorp_vault_cluster` will automatically generate self-signed certificates for the Vault Cluster nodes.

You can optionally use the tag `generate_self_signed_certs` to only run the tasks to create the self-signed certificates, but the `hashicorp_vault_cluster` role will always check for and create the self-signed certificates if the variable `self_signed_certs_generate` is set to `true`.

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/deploy_hashicorp_vault.yml --diff -v --tags generate_self_signed_certs
```

#### 5.2.3. SENSITIVE: Encrypt Private Keys for Self-Signed Certs

```bash
for f in $(find . -type f -name "*.private.key") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

#### 5.2.4. SENSITIVE: Deploy Hashicorp Vault Cluster

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/deploy_hashicorp_vault.yml --diff -v
```

#### 5.2.5. SENSITIVE: Encrypt Vault Init Data

The `hashicorp_vault_cluster` role initializes the Vault Cluster and saves the secret keys and root token to the default location of `{{ inventory_dir }}/hashicorp-vault-init`.

You can override the default location to store this sensitive information by changing `hashicorp_vault_init_data_local_dir` in `inventory/group_vars/example_hashicorp_vault_cluster/cubexch.guardian.hashicorp_vault_cluster.yml`.

> Ensure this sensitive information is encrypted wherever it is stored.

```bash
for f in $(find . -type f -name "*.private.key") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
for f in $(find . -type f -name "*.ansible_vault.yml") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

## 6. Guardian Configuration

### 6.1. Create an Ansible inventory for your Guardian node.

`inventory/hosts-example.ini`

```ini
[all]
example-vault-1  ansible_host=127.0.0.1
example-vault-2  ansible_host=127.0.0.2
example-vault-3  ansible_host=127.0.0.3

# Update guardian hostname and IP address
example-guard-1  ansible_host=127.0.0.11

[example_hashicorp_vault_cluster]
example-vault-[1:3]
```

### 6.2. Verify Connectivity to Guardian Node with Ansible

```bash
ansible all -i inventory/hosts-example.ini -m ping --one-line
```

### 6.3. OPTIONAL: Create `host_vars` for the `geerlingguy.certbot` role:

Unless you are providing your own public SSL certificates, use the recommended configurations below:

> NOTE:
>
> - Certbot's standalone verification process will start a temporary http web server on the guardian to handle the Let's Encrypt challenge process.
> - In order for the challenge process to work, Let's Encrypt will try to access the FQDN on HTTP port 80.
> - You will need to ensure DNS has been configured for your Guardian's FQDN, and that firewall rules are opened for HTTP port 80.

> Update the path to use your new guardian hostname

`inventory/host_vars/example-guard-1/geerlingguy_certbot.yml`

```yml
# Update the admin email address used to create the ACME certificate account for certbot
certbot_admin_email: my_name@my_email_address.com

# Recommended settings listed below, please consult the geerlingguy.certbot role documentation before changing
# REF: https://github.com/geerlingguy/ansible-role-certbot
certbot_install_method: package
certbot_auto_renew: true
certbot_auto_renew_user: 'root'
certbot_auto_renew_hour: '{{ 24 | random(seed=guardian_instance.public_fqdn) }}'
certbot_auto_renew_minute: '{{ 60 | random(seed=guardian_instance.public_fqdn) }}'
certbot_auto_renew_options: '--quiet'
certbot_create_if_missing: true
certbot_create_method: standalone
certbot_certs:
  - domains:
      - '{{ guardian_instance.public_fqdn }}'
```

### 6.4. Create `host_vars` for your non-sensitive Guardian Vault Configuration

> Update the path to use your new guardian hostname

`inventory/host_vars/example-guard-1/guardian_vault_config.yml`

```yml
# Update the Vault URL to point to your Vault Cluster
# Should match a vault hostname and your vault_cluster_fqdn
vault_url: 'https://example-vault-1.example.hashicorp.vault.cluster.com:8200'

# Vault Cluster FQDN used for copying Vault Cluster CA Cert and generating /etc/host entries
vault_cluster_fqdn: 'example.hashicorp.vault.cluster.com'

# Ansible Inventory Group Name for your Hashicorp Vault Cluster
hashicorp_vault_cluster_group_name: 'example_hashicorp_vault_cluster'

# Update the guardian_hostname to match the hostname set in inventory (i.e. inventory_hostname)
# Update the guardian_id to match the Guardian ID number assigned to you by Cube.Exchange
guardian_instances:
  - guardian_hostname: example-guard-1
    guardian_id: 000

# The guardian_vault_config role is able to handle all the Vault configuration required, but you must explicitly enable the actions below to allow it to connect to your cluster and make changes.
# Set vault_policy_deploy to false if you prefer to manually deploy the vault configurations
vault_policy_deploy: true
# Set vault_secrets_engine_deploy to false if you prefer to manually configure the Secrets Engine
vault_secrets_engine_deploy: true
# Set vault_approle_enable to false if you prefer to manually enable the AppRole authentication method
vault_approle_enable: true
# Set vault_approle_retrieve to false if you prefer to manually configure the AppRole ID and SecretsID
vault_approle_retrieve: true

# It is strongly recommended to limit the CIDR's allowed to use the AppRole and Token created in Vault
# Update the guardian_secret_id_bound_cidrs and guardian_token_bound_cidrs to correspond with the internal IP used by the Guardian to talk to the Vault cluster
# NOTE: Should match open_iptables_source_network_api_port from inventory/group_vars/example-guard-1/cubexch.guardian.hashicorp_vault_cluster.yml
guardian_secret_id_bound_cidrs: '127.0.0.0/8'
guardian_token_bound_cidrs: '127.0.0.0/8'

### Option to create /etc/hosts entries ###
# Option to create /etc/hosts entries for each cluster member
create_etc_hosts_entries: true
### Required Inventory Variables when creating /etc/hosts entries ###
# Select an interface to get an IP address from when creating /etc/hosts entries
#
## Select the default interface detected by ansible
hashicorp_vault_interface_api_interface: '{{ ansible_default_ipv4.interface }}'
## Or specify an interface name
# hashicorp_vault_interface_api_interface: "bond0"
# hashicorp_vault_interface_api_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ hashicorp_vault_interface_api_interface]['ipv4']['address'] }}"
###########################################

# No changes needed unless you are using your owned certificates for vault
# Local directory where Vault Cluster Certificates are stored
self_signed_certs_local_dir: '{{ inventory_dir }}/hashicorp-vault-certs'
# Cert file names to copy to Guardian node
self_signed_cert_files:
  ca_cert: '{{ vault_cluster_fqdn }}.ca.cert.pem'
# Remote path of CA Cert
vault_ca_cert_path: '{{ cube_vault_configs_dir }}/{{ self_signed_cert_files.ca_cert }}'
```

### 6.5. SENSITIVE: Create `host_vars` for sensitive Guardian Node Configuration

> Update the path to use your new guardian hostname

`inventory/host_vars/example-guard-1/guardian.ansible_vault.yml`

```yml
# Use a secure password to control access to the Guardian Admin Interface
# i.e. openssl rand -hex 32
guardian_access_token_vault: 'my_guardian_access_token'
```

### 6.6. SENSITIVE: Encrypt `host_vars` for sensitive Guardian Node Configuration with Ansible Vault

```bash
for f in $(find . -type f -name "*.ansible_vault.yml") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

### 6.7. Create `host_vars` for your non-sensitive Guardian Node Configuration

> Update the path to use your new guardian hostname

`inventory/host_vars/example-guard-1/guardian.yml`

```yml
# Update the guardian_id to match the Guardian ID number assigned to you by Cube.Exchange
# Update the public_fqdn to match the publicly available DNS name where your Guardian can be reached.
# See `public_guardian_list` at [roles/guardian/vars/main.yml](roles/guardian/vars/main.yml)
guardian_instance:
  guardian_id: 000
  public_fqdn: example-guard-1.testing.cube.exchange

# Update the Vault URL to match your Vault cluster
# Should match vault_url in inventory/host_vars/example-guard-1/guardian_vault_config.yml
guardian_key_storage:
  hashicorp_vault:
    vault_url: 'https://example-vault-1.example.hashicorp.vault.cluster.com:8200'
    vault_tls_client_ca_filename: '{{ self_signed_cert_files.ca_cert }}'
    vault_tls_client_ca_local_source_dir: '{{ inventory_dir }}/hashicorp-vault-certs'
    secret_mount_path: 'cube-guardian/guardian-{{ guardian_instance.guardian_id }}'
    approle_path_reader: '{{ guardian_dirs.config }}/vault.guardian.{{ inventory_hostname }}.reader.json'
    approle_path_writer: '{{ guardian_dirs.config }}/vault.guardian.{{ inventory_hostname }}.writer.json'
    approle_token_renew_seconds: 3600
    access_log_filename: 'access.json'

# The Guardian will be configured to listen on the default port of 9420 for node-to-node communication.
# Ensure the port specified here matches your guardian entry in the `public_guardian_list` at [roles/guardian/vars/main.yml](roles/guardian/vars/main.yml)
guardian_listen_node_port: 00000

# If you would like Ansible to automatically create an iptables rule to allow the node-to-node traffic, set to guardian_listen_node_port_open_iptables: true
guardian_listen_node_port_open_iptables: true

# The Guardian will be configured to listen on the default port of 443 for end user web communication (i.e. emergency withdrawals).
# It is strongly recommended that you do not change the default port of 443 in order to ensure that end users don't have any challenges accessing the Guardian instance if needed.
# Ensure the port specified here matches your guardian entry in the `public_guardian_list` at [roles/guardian/vars/main.yml](roles/guardian/vars/main.yml)
guardian_listen_web_port: 443

# If you would like Ansible to automatically create an iptables rule to allow the web traffic, set to guardian_listen_node_port_open_iptables: true
guardian_listen_web_port_open_iptables: true

# The Guardian will be configured to listen on the default interface detected by ansible as the default listening IP.
# You can use the settings below to use a different interface for node-to-node or web communication if needed:
# # guardian_listen_node_interface: "{{ ansible_default_ipv4.interface }}"
# guardian_listen_node_interface: enp1s0
# guardian_listen_node_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ guardian_listen_node_interface]['ipv4']['address'] }}"
# # guardian_listen_web_interface: "{{ ansible_default_ipv4.interface }}"
# guardian_listen_web_interface: enp1s0
# guardian_listen_web_ip: "{{ hostvars[inventory_hostname]['ansible_' ~ guardian_listen_web_interface]['ipv4']['address'] }}"

guardian_access_token: '{{ guardian_access_token_vault }}' # References value defined in guardian.ansible_vault.yml for clarity
```

### 6.8. Create an Ansible playbook to deploy

The list of roles can be adjusted if not all are desired.

- `geerlingguy.swap` disables swap
- `geerlingguy.certbot` installs certbot and creates the Guardian's TLS certificates
- `cubexch.guardian.guardian` installs and configures the Guardian service

`playbooks/deploy_guardian.yml`

```yml
- name: Deploy Guardian
  # Update hosts selector with new guardian hostname
  # Ensure host_vars folder matches when changed
  hosts: example-guard-1
  gather_facts: false
  become: true
  become_user: root
  pre_tasks:
    - name: Gather OS Family
      ansible.builtin.setup:
        gather_subset:
          - os_family
  roles:
    - geerlingguy.swap
    - geerlingguy.certbot
    - cubexch.guardian.guardian_vault_config
    - cubexch.guardian.guardian
```

### 6.9. Run the playbook to configure the Guardian Node

```bash
ansible-playbook -i ./inventory/hosts-example.ini playbooks/deploy_guardian.yml --diff -v
```

> The last step of starting the service should succeed, however, you will see messages similar to this if your Guardian has not been added to the public list of approved Guardians. You will also see similar errors if other Guardians have not updated their configuration with the latest list approved Guardians.

```bash
# SSH to your Guardian instance
# Tail the aurum log for your Guardian instance
sudo tail -n 500 -f /var/log/cube-guardian-000/aurum.log.$(date +'%F')

...

# You may see messages like this if your Guardian instance has not been added to the public_guardian_list
2023-08-05T22:06:01.509715Z  INFO cube_aurum::modules::guardian_nodes: attempting connection to (id:201 address:guardian-201.testing.cube.exchange:20101)...
2023-08-05T22:06:01.520091Z  INFO cube_aurum::modules::guardian_nodes: initiated connection to (token:641 id:201 address:guardian-201.testing.cube.exchange:20101)
2023-08-05T22:06:01.520097Z  INFO cube_aurum::modules::guardian_nodes: connected to (token:641 id:201 address:guardian-201.testing.cube.exchange:20101)
2023-08-05T22:06:01.520129Z  WARN cube_aurum::modules::guardian_nodes: connection closed on handshake for (token:641 id:201 address:guardian-201.testing.cube.exchange:20101)
2023-08-05T22:06:01.520152Z  WARN cube_aurum::modules::guardian_nodes: received event for unknown source Token(641)

# You may see messages like this if your Guardian SSL Certificate CN does not match the public_fqdn in the public_guardian_list
2023-08-05T22:11:01.509719Z  INFO cube_aurum::modules::guardian_nodes: attempting connection to (id:201 address:guardian-201.testing.cube.exchange:20101)...
2023-08-05T22:11:01.512543Z  INFO cube_aurum::modules::guardian_nodes: initiated connection to (token:741 id:201 address:guardian-201.testing.cube.exchange:20101)
2023-08-05T22:11:01.512546Z  INFO cube_aurum::modules::guardian_nodes: connected to (token:741 id:201 address:guardian-201.testing.cube.exchange:20101)
2023-08-05T22:11:01.512600Z  INFO cube_aurum::modules::manager: guardian=201: connected
2023-08-05T22:11:01.514424Z  WARN cube_aurum::modules::guardian_nodes: connection to (token:741 id:201 address:guardian-201.testing.cube.exchange:20101) errored: read_tls

Caused by:
    Connection reset by peer (os error 104)
...

# You may see messages like this if other Guardians have not updated with the latest list of approved Guardians
2023-08-05T22:21:11.511981Z  INFO cube_aurum::modules::guardian_nodes: initiated connection to (token:883 id:202 address:guardian-202.testing.cube.exchange:20102)
2023-08-05T22:21:11.511983Z  INFO cube_aurum::modules::guardian_nodes: connected to (token:883 id:202 address:guardian-202.testing.cube.exchange:20102)
2023-08-05T22:21:11.512000Z  WARN cube_aurum::modules::guardian_nodes: connection closed on handshake for (token:883 id:202 address:guardian-202.testing.cube.exchange:20102)
2023-08-05T22:21:11.512011Z  WARN cube_aurum::modules::guardian_nodes: received event for unknown source Token(883)

# You may see messages like this if the DNS resolution for other Guardian instances fails
2023-08-05T21:43:21.526200Z  INFO cube_aurum::modules::guardian_nodes: could not resolve some-other-guardian.example.com:20101000: failed ToSocketAddrs: failed to lookup address information: Name or service not known

# Once your Guardian instance successfully connects with the Cube Guardian Monitor instance, you should see a message like this
2023-08-05T22:11:32.633661Z  INFO cube_aurum::modules::manager: guardian=201: initialized keys
```

If the Guardian service fails to start, please refer to [9. FAQ](#9-faq)

### 6.10. Verify inbound connectivity to your Guardian Node

```bash
nc -vz -w 10 example-guardian-1.testing.cube.exchange 20104
# Example Output
# Connection to example-guardian-1.testing.cube.exchange port 20104 [tcp/*] succeeded!

nc -vz -w 10 example-guardian-1.testing.cube.exchange 443
# Example Output
# Connection to example-guardian-1.testing.cube.exchange port 443 [tcp/https] succeeded!
```

### 6.11. Verify your Guardian Certificate has the expected CN

```bash
openssl s_client -showcerts -connect example-guardian-1.testing.cube.exchange:443 </dev/null 2>/dev/null | grep s:CN
# Example Output
#  0 s:CN = example-guardian-1.testing.cube.exchange
```

- The `CN` of the certificate should match your entry in `public_guardian_list` at [roles/guardian/vars/main.yml](roles/guardian/vars/main.yml).
- The `public_guardian_list` entries correspond to the Guardian configuration toml entries

```bash
grep tls_name /opt/cube-guardian-204/config/production-204.toml -C 3

[[nodes.guardians]]
id = 201
addr = "guardian-201.testing.cube.exchange:20101"
tls_name = "guardian-201.testing.cube.exchange"

[[nodes.guardians]]
id = 202
addr = "guardian-202.testing.cube.exchange:20102"
tls_name = "guardian-202.testing.cube.exchange"

[[nodes.guardians]]
id = 203
addr = "guardian-203.testing.cube.exchange:20103"
tls_name = "guardian-203.testing.cube.exchange"

[[nodes.guardians]]
id = 204
addr = "example-guardian-1.testing.cube.exchange:20104"
tls_name = "example-guardian-1.testing.cube.exchange"

[[nodes.guardians]]
id = 205
addr = "example-guardian-2.testing.cube.exchange:20105"
tls_name = "example-guardian-2.testing.cube.exchange"
```

## 7. SENSITIVE: Ensure All Sensitive Information Encrypted with Ansible Vault

```bash
for f in $(find . -type f -name "*.ansible_vault.yml") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
for f in $(find . -type f -name "*.private.key") ;do echo Encrypting $f ;ansible-vault encrypt $f ;done
```

## 8. FAQ

### 8.1. How can I check the status of the Guardian service?

The Ansible role deploys the Guardian service as a systemd service named `guardian-{{ your_guardian_id }}`.

```bash
root@example-guardian-1:~# systemctl status guardian-204.service
● guardian-204.service - "Cube Guardian - 204"
     Loaded: loaded (/etc/systemd/system/guardian-204.service; enabled; vendor preset: enabled)
     Active: active (running) since Tue 2023-08-01 14:46:19 UTC; 4h 59min ago
       Docs: https://docs.cube.exchange
   Main PID: 22284 (cube-aurum)
      Tasks: 18 (limit: 308638)
     Memory: 29.4M
     CGroup: /system.slice/guardian-204.service
             └─22284 /opt/cube-guardian-204/bin/current/cube-aurum

Aug 01 14:46:06 example-guardian-1 systemd[1]: Starting "Cube Guardian - 204"...
Aug 01 14:46:19 example-guardian-1 systemd[1]: Started "Cube Guardian - 204".



root@example-guardian-1:~# journalctl -n 100 -f -u guardian-204.service
-- Logs begin at Tue 2023-08-01 14:27:38 UTC. --
Aug 01 14:46:06 example-guardian-1 systemd[1]: Starting "Cube Guardian - 204"...
Aug 01 14:46:19 example-guardian-1 systemd[1]: Started "Cube Guardian - 204".
```

### 8.2. How can I check the deployed configuration?

- Guardian configuration files are stored in `/opt/cube-guardian-{{ your_guardian_id }}/config` by default
- Environment variables required by the Guardian service are in `guardian-{{ your_guardian_id }}.service.env`
- Guardian Application configurations are stored in `production-{{ your_guardian_id }}.toml`

```bash
root@example-guardian-1:~# ll /opt/cube-guardian-204/config/
total 48
drwxr-x--- 2 cube-guardian-204 cube-guardian-204 4096 Aug  1 14:46 ./
drwxr-x--- 4 cube-guardian-204 cube-guardian-204 4096 Aug  1 14:45 ../
-rw------- 1 cube-guardian-204 cube-guardian-204 1834 Aug  1 14:45 cert.pem
-rw------- 1 cube-guardian-204 cube-guardian-204 5584 Aug  1 14:45 fullchain.pem
-rw-r----- 1 cube-guardian-204 cube-guardian-204  200 Aug  1 14:45 guardian-204.service.env
-rw------- 1 cube-guardian-204 cube-guardian-204 1704 Aug  1 14:45 privkey.pem
-rw-r----- 1 cube-guardian-204 cube-guardian-204 1635 Aug  1 14:45 production-204.toml
-rw-r--r-- 1 cube-guardian-204 cube-guardian-204  810 Aug  1 15:52 public_shares.json
-rw-r----- 1 cube-guardian-204 cube-guardian-204  652 Aug  1 14:40 vault-ca.pem
-rw------- 1 cube-guardian-204 cube-guardian-204  114 Aug  1 14:44 vault.guardian.example-guardian-1.reader.json
-rw------- 1 cube-guardian-204 cube-guardian-204  114 Aug  1 14:45 vault.guardian.example-guardian-1.writer.json
```

### 8.3. How can I view the Guardian logs?

- Logs are written to `/var/log/cube-guardian-{{ your_guardian_id }}` by default.
- The `aurum.log.*` file is the primary application log.

```bash
root@example-guardian-1:~# ll /var/log/cube-guardian-204/
total 56
drwxr-x---  2 cube-guardian-204 cube-guardian-204  4096 Aug  1 14:46 ./
drwxrwxr-x 10 root              syslog             4096 Aug  1 14:45 ../
-rw-r--r--  1 cube-guardian-204 cube-guardian-204   683 Aug  1 15:52 access.json.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204 37436 Aug  1 19:37 aurum.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 btc.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 cubenet.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 eth.log.2023-08-01
-rw-r--r--  1 cube-guardian-204 cube-guardian-204     0 Aug  1 14:46 metrics.log.2023-08-01
```

- You can tail the logs with the following command

```bash
tail -f /var/log/cube-guardian-204/aurum.log.$(date +'%F')
```

### 8.4. Example Log Messages

#### 8.4.1. Successful Guardian Connection to Hashicorp Vault

```bash
2023-08-01T14:46:07.023501Z  INFO cube_key_store::hashicorp_vault: login auth {"request_id":"20cd2583-7b8c-2ba2-53ef-1c12b6597344","auth":{"policies":["default","vault.guardian.204.writer.policy"],"token_policies":["default","vault.guardian.204.writer.policy"],"metadata":{"role_name":"cube-guardian-204.writer"}}}
2023-08-01T14:46:07.023757Z  INFO cube_key_store::hashicorp_vault: login auth {"request_id":"c758de74-d71d-05e0-1d87-20a67931711b","auth":{"policies":["default","vault.guardian.204.reader.policy"],"token_policies":["default","vault.guardian.204.reader.policy"],"metadata":{"role_name":"cube-guardian-204.reader"}}}
```

#### 8.4.2. Successful Guardian Key Initialization

> The initial key generation process could take some time to complete.

```bash
2023-08-01T14:41:56.121721Z  INFO cube_aurum::modules::manager: no paillier keys found at paillier_keys. generating...
2023-08-01T14:42:18.109109Z  INFO cube_aurum::modules::manager: precomputing local key tables...
```

#### 8.4.3. Successful Guardian Peer Connection

```bash
2023-08-01T14:46:20.511870Z  INFO cube_aurum::modules::guardian_nodes: accepting connection from (token:5 id:203 address:guardian-203.testing.cube.exchange:20103)
2023-08-01T14:46:20.511878Z  INFO cube_aurum::modules::guardian_nodes: connected to (token:5 id:203 address:guardian-203.testing.cube.exchange:20103)

2023-08-01T15:52:36.804541Z  INFO cube_aurum::modules::manager: guardian=201: connected
2023-08-01T15:52:38.255799Z  INFO cube_aurum::modules::manager: guardian=201: initialized keys
```

#### 8.4.4. Successful User Key Generation

```bash
2023-08-01T15:52:50.079367Z  INFO cube_aurum::modules::manager: job_id=56576470318841861 user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e starting keygen
2023-08-01T15:52:50.079642Z  INFO cube_aurum::modules::manager: user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e: calculated cipher key 9d9a5f9dae92c4742610b4e75a5d1f4c35d5ef6046534bf87e7e3e68e59d4b14
2023-08-01T15:52:50.706929Z  INFO cube_aurum::modules::manager: generated user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e key_id=1690905169961379032 public_key=020950f146649432c0b91e71ba2b16d28ee4d28951ab899ab9b32b01f7d40e5e51
2023-08-01T15:52:51.822734Z  INFO cube_aurum::modules::manager: generated user_id=e480b799-0613-4fae-9ae1-3a49902d7d0e subaccount_id=1 key_id=1690905169961379000 public_key=028c8b2bb57aadf893dc3f5e96e3fbd40e7f42572762bc720408c8f1a3813c7ddc
```

#### 8.4.5. Failed Peer Connection - Received Invalid TLS Certificate Name

```bash
2023-08-01T17:42:08.668311Z  WARN rustls::msgs::handshake: Illegal SNI hostname received "147.75.84.211"
```

#### 8.4.6. Other Errors

- Generally logs tagged as `ERROR` represent a failure that should be investigated.
- Log messages for errors will typically include a descriptive message (and parameters if applicable) to indicate the source of the issue.
- Please reach out to Cube in our shared Slack channel if you run into any issues we haven't documented yet
